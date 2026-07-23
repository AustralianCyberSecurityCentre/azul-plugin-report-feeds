"""Classes for reimporting feeds that have been exported to disk."""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Iterator

from azul_plugin_report_feeds.reportcollector.base_feed import (
    BaseFeed,
    ReportFeedOptions,
)
from azul_plugin_report_feeds.reportcollector.models import ReportResult

logger = logging.getLogger("reportcollector")


class ExportedFeed(BaseFeed):
    """Reporting Feed to read back in serialised reports from filesystem.

    The format expected is that produced by the main `reportcollector` tool's
    output directory.  It allows the transfer of feeds out-of-band to a
    non-Internet connected network for re-reading via the feed interface.
    """

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new ExportedFeed for reading back in from filesystem."""
        super().__init__(feed_options, global_options)
        self.max_file_size = feed_options.max_file_size

    def fetch(self, last_fetch: datetime | None = None) -> Iterator[ReportResult]:
        """Yield the latest serialised reports from directory source, in asc time order.

        Generator yields dictionaries of report meta, pdf and previously downloaded samples.
        Entries are filtered to ensure they are after the last_fetch time, or all
        if None.
        """
        reports: list[ReportResult] = []
        for dirpath, _, filenames in os.walk(self.feed_url):
            for fname in filenames:
                if not fname.endswith(".meta"):
                    continue
                m = re.match(r".*/(\d{4})\-(\d{2})\-(\d{2})$", dirpath)
                if not m:
                    continue
                date = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                if not date.tzinfo:
                    date = date.replace(tzinfo=timezone.utc)

                if last_fetch and date < last_fetch.replace(hour=0, minute=0, second=0, microsecond=0):
                    continue

                path = os.path.join(dirpath, fname)
                with open(path, "rb") as tmp:
                    j = json.loads(tmp.read())
                    report = ReportResult.model_validate(j)
                if last_fetch and report.timestamp and report.timestamp <= last_fetch:
                    continue

                report._report_path = os.path.dirname(path)

                # override with configuration for current feed
                report.publisher = self.publisher
                report.topic = self.source
                report.distribution = self.distribution
                report.site = self.site

                reports.append(report)

        for cur_report in sorted(reports, key=lambda r: r.timestamp):
            path = cur_report._report_path
            if path is None or cur_report.slug is None:
                raise TypeError("Expected path and cur_report.slug to be str, got None")
            pdf_path = os.path.join(path, cur_report.slug + ".pdf")
            if os.path.exists(pdf_path):
                with open(pdf_path, "rb") as tmp:
                    cur_report.report = tmp.read()

            # multiple reports can be in same dir, need to associate files based on hash
            all_current_hashes = list(cur_report.indicators_hashes_iter())
            for f in os.listdir(path):
                if f.endswith((".pdf", ".meta")):
                    continue
                filepath = os.path.join(path, f)
                filesize = os.path.getsize(filepath)
                if filesize > self.max_file_size:
                    logger.warning(
                        "Skipping %s %s (%i bytes) as exceeds max size limit.",
                        cur_report.title,
                        os.path.basename(filepath),
                        filesize,
                    )
                    continue
                with open(filepath, "rb") as tmp:
                    content = tmp.read()
                hashes = []
                hashes.append(hashlib.md5(content).hexdigest())  # noqa: S324
                hashes.append(hashlib.sha1(content).hexdigest())  # noqa: S324
                hashes.append(hashlib.sha256(content).hexdigest())
                if any(h in all_current_hashes for h in hashes):
                    cur_report.files.append(content)
            yield cur_report

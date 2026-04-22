"""Classes for integrating iSight threat intel reporting."""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Iterator

from slugify import slugify

from azul_plugin_report_feeds.reportcollector.base_feed import (
    BaseFeed,
    ReportFeedOptions,
)
from azul_plugin_report_feeds.reportcollector.models import Indicator, ReportResult

logger = logging.getLogger("reportcollector")


class ISightReports(BaseFeed):
    """Reporting Feed for iSight threatintel reports.

    These are assumed to be pre-serialised to the filesystem and won't download
    via their WebAPI directly.
    """

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new ISightReportFeed where feed_url is the local filesystem to fetch."""
        super().__init__(feed_options, global_options)
        self.max_reports = feed_options.max_reports

    def fetch(self, last_fetch: datetime | None = None) -> Iterator[ReportResult]:
        """Yield the latest parsed reports from directory source, in asc time order.

        Generator yields dictionaries of report meta and pdf.
        Entries are filtered to ensure they are after the last_fetch time, or all
        if None.
        """
        useful = 0
        # assumes directory order will match time order
        for dirpath, _, filenames in os.walk(self.feed_url):
            for fname in filenames:
                if useful >= self.max_reports:
                    logger.info("Exiting early as reached limit of %i reports", self.max_reports)
                    return

                if not fname.startswith("isight_report") or not fname.endswith(".json"):
                    continue

                path = os.path.join(self.feed_url, dirpath, fname)
                with open(path, "rb") as tmp:
                    j = json.loads(tmp.read())

                report: dict = j["message"]["report"]
                published = datetime.strptime(report["publishDate"], "%B %d, %Y %I:%M:%S %p")
                if not published.tzinfo:
                    published = published.replace(tzinfo=timezone.utc)
                if last_fetch and published <= last_fetch:
                    continue

                indicators = self.get_indicators(report)
                if any(len(list(i.hashes_iter())) > 0 for i in indicators):
                    logger.info("No hashes found in report %s, skipping.", report["title"])
                    continue
                logger.info("Yay %i indicators found in report %s", len(indicators), report["title"])

                reportpdf = path[:-5] + ".pdf"
                if not os.path.exists(reportpdf):
                    pdf = None
                else:
                    with open(reportpdf, "rb") as tmp:
                        pdf = tmp.read()

                useful += 1
                yield ReportResult(
                    publisher=self.publisher,
                    distribution=self.distribution,
                    topic=self.source,
                    site=self.site,
                    url=self.site,
                    title=report["title"],
                    slug=slugify(report["title"]),
                    timestamp=published,
                    report_id=report["reportId"],
                    report_type=report.get("reportType", ""),
                    report=pdf,
                    indicators=indicators,
                    description=report.get("execSummary", ""),
                )

    def get_indicators(self, report) -> list[Indicator]:
        """Extract the indicators out of the report json into a list of our internal format."""
        mapping = {
            "md5": ("md5", str),
            "sha1": ("sha1", str),
            "sha256": ("sha256", str),
            "file_size": ("filesize", int),
            "filename": ("filename", str),
            "malware_family": ("tag", str),
            "ssdeep": ("ssdeep", str),
        }
        indicators: list[Indicator] = []
        # only mapping files for now...
        for f in report.get("tagSection", {}).get("files", {}).get("file", []):
            indicator = Indicator()
            indicator.model_dump()
            indicator_has_value = False
            for m in mapping:
                if m not in f:
                    continue

                indicator_has_value = True
                itype = mapping[m][0]
                ival = mapping[m][1](f[m])
                setattr(indicator, itype, ival)
            if indicator_has_value:
                indicators.append(indicator)
        return indicators

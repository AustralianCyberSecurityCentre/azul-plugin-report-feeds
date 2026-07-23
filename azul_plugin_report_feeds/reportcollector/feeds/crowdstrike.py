"""Classes for integrating Crowdstrike threat intel reporting."""

import json
import logging
import os
import re
import shutil
import subprocess  # noqa: S404 # nosec B404
import tempfile
from datetime import UTC, datetime
from typing import Iterator

from azul_plugin_report_feeds.reportcollector.base_feed import (
    BaseFeed,
    ReportFeedOptions,
)
from azul_plugin_report_feeds.reportcollector.models import Indicator, ReportResult

logger = logging.getLogger("reportcollector")

MD5_PAT = r"([a-f0-9]{32})[^a-f0-9]"
SHA256_PAT = r"([a-f0-9]{64})"
# text output where pdf table column was wrapped
SPLIT_PAT = r"^([a-f0-9]{32,63}\n[a-f0-9]{1,32}[^a-f0-9])"
SPLIT_PAT2 = r"^([a-f0-9]{22,31}\n[a-f0-9]{22,31}\n[a-f0-9]{1,21}[^a-f0-9])"
# html output where pdf table column was wrapped
SPLIT_HTML_PAT = r"([a-f0-9]{32,63}<br/>[a-f0-9]{1,32})[^a-f0-9]"
SPLIT_HTML_PAT2 = r"([a-f0-9]{22,31}<br/>[a-f0-9]{22,31}<br/>[a-f0-9]{1,21})[^a-f0-9]"


class CrowdstrikeReports(BaseFeed):
    """Reporting Feed for Crowdstrike threatintel reports.

    These are assumed to be pre-serialised to the filesystem and won't contact
    Falcon API directly.
    """

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new CrowdstrikeReportFeed where feed_url is the local filesystem to fetch."""
        super().__init__(feed_options, global_options)
        self.max_reports = feed_options.max_reports

    def fetch(self, last_fetch: datetime | None = None) -> Iterator[ReportResult]:
        """Yield the latest parsed reports from directory source, in asc time order.

        Generator yields dictionaries of report meta and pdf.
        Entries are filtered to ensure they are after the last_fetch time, or all
        if None.
        """
        reports: list[ReportResult] = []
        for dirpath, _, filenames in os.walk(self.feed_url):
            for fname in filenames:
                if not fname.startswith("crowdstrike_report") or not fname.endswith(".json"):
                    continue

                path = os.path.join(self.feed_url, dirpath, fname)
                with open(path, "rb") as tmp:
                    j = json.loads(tmp.read())

                for rep in j.get("resources", []):
                    if not isinstance(rep, dict):
                        continue
                    name = rep.get("name")
                    created = rep.get("created_date")
                    slug = rep.get("slug")
                    desc = rep.get("short_description")
                    rtype = rep.get("type", {}).get("name")
                    url = rep.get("url")
                    if not name or not created or not slug:
                        continue

                    m = re.search(r"([A-Z]{3,5}\-\d+)", name)
                    if not m:
                        logger.warning('Unable to match report id from "%s" (%s)', name, path)
                        continue

                    report_id = m.group(1)
                    name = name[len(report_id) :].strip()
                    created = datetime.fromtimestamp(created, tz=UTC)
                    reportpdf = path[:-5] + ".pdf"
                    if not os.path.exists(reportpdf):
                        reportpdf = None
                    reports.append(
                        ReportResult(
                            publisher=self.publisher,
                            distribution=self.distribution,
                            topic=self.source,
                            site=self.site,
                            url=url,
                            title=name,
                            slug=slug,
                            timestamp=created,
                            report_id=report_id,
                            report_type=rtype,
                            description=desc,
                            _report_path=reportpdf,
                        )
                    )
        useful = 0
        for cur_report in sorted(reports, key=lambda r: r.timestamp):
            if last_fetch and cur_report.timestamp and cur_report.timestamp <= last_fetch:
                continue
            if useful >= self.max_reports:
                logger.info("Exiting early as reached limit of %i reports", self.max_reports)
                return

            if not cur_report._report_path:
                logger.warning(
                    "No matching pdf report found for %s..may have hashes in description", cur_report._report_path
                )
            else:
                with open(cur_report._report_path, "rb") as tmp:
                    cur_report.report = tmp.read()

            hashes = hash_scrape(cur_report)
            if not hashes:
                cur_report.report = None
                logger.info(f"No hashes found in report {cur_report.slug} with url {cur_report.url}")
                continue
            indicator = Indicator()
            indicator.assign_hashes(hashes)
            cur_report.indicators.append(indicator)
            useful += 1

            yield cur_report


def hash_scrape(report: ReportResult) -> list[str]:
    """Scrape any file hashes from the given report object.

    :param report: Dict of report metadata
    :return: List of hashes
    """
    # This can be quite complex because the pdf reports often contain hashes in tables that are line wrapped.
    # This makes regex difficult after text conversion.
    # Html conversion can be better at keeping content in the same table cell, so try both.
    hashes: set[str] = set()
    description = ""
    if report.description:
        description = report.description
    for h in re.findall(MD5_PAT, description):
        hashes.add(h)

    for h in re.findall(SHA256_PAT, description):
        hashes.add(h)

    if report._report_path:
        pdf = report._report_path
        tmpdir = tempfile.mkdtemp()
        try:
            p = subprocess.Popen(  # noqa: S603
                ["pdftotext", pdf, "-"],  # noqa: S607
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                content, stderr = p.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
                content, stderr = p.communicate()
            p = subprocess.Popen(  # noqa: S603
                ["pdftohtml", "-s", pdf, os.path.join(tmpdir, "output.html")],  # noqa: S607
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                content, stderr = p.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
                content, stderr = p.communicate()
            with open(os.path.join(tmpdir, "output-html.html"), "rb") as tmp:
                content += tmp.read()

            for pat in [MD5_PAT, SHA256_PAT, SPLIT_PAT, SPLIT_PAT2, SPLIT_HTML_PAT, SPLIT_HTML_PAT2]:
                for h in re.findall(pat, content.decode("utf-8")):
                    h = h.replace("\n", "").replace("<br/>", "")
                    if len(h) not in (32, 64):
                        continue
                    hashes.add(h.lower())

        except Exception as ex:
            logger.warning("Error converting PDF to txt/html %s: %s", pdf, str(ex))
        finally:
            shutil.rmtree(tmpdir)

    return list(hashes)

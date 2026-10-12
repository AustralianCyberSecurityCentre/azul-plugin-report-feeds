#!/usr/bin/env python
"""Collect configured public blog and RSS feeds for malware related reports.

Ensure you have the following programs installed / on $PATH :
* pdftotext (poppler-utils package)

"""

import hashlib
import http.client as http_client
import json
import logging
import os
import os.path
import pathlib

import click
import yaml

from azul_plugin_report_feeds.reportcollector.base_feed import BaseFeed, ReportFeedOptions
from azul_plugin_report_feeds.reportcollector.downloads import FileDownloader
from azul_plugin_report_feeds.reportcollector.util import ReportState

logger = logging.getLogger("reportcollector")
DEFAULT_STATEDIR = os.path.expanduser("~/.reportcollector")
DEFAULT_CONFIG_PATH = "./reportfeeds.yaml"


@click.command()
@click.option(
    "--apikey",
    default="",
    help="Api key to download files from virustotal with. If not set, will not attempt download",
)
@click.option("--feedlist", help="Yaml file containing a  list of feeds to scrape", default=DEFAULT_CONFIG_PATH)
@click.option("--statedir", default=DEFAULT_STATEDIR, help="Path to the directory where state is stored.")
@click.option("--outdir", default="reports", help="Directory where downloaded files and content are stored.")
@click.option("--debug", help="", default=False)
def main(apikey="", statedir=DEFAULT_STATEDIR, outdir="reports", debug=False, feedlist=DEFAULT_CONFIG_PATH):
    """Run the cmdline for the reportcollector, scraping all configured endpoints.

    Hash indicators found can be attempted to be downloaded via VirusTotal, but doing so requires a private API Key.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s: %(name)s - %(levelname)s - %(message)s")
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        http_client.HTTPConnection.debuglevel = 1

    # Make or get state directory
    state: ReportState = ReportState(statedir)

    feeds_path = pathlib.Path(feedlist)
    if not feeds_path.exists():
        raise Exception(f"feed list '{feeds_path}' does not exists")
    if not feeds_path.is_file():
        raise Exception(f"feed list '{feeds_path}' is not a file")

    raw_feeds: dict[str, list[dict]] = yaml.load(feeds_path.open(), yaml.SafeLoader)
    feed_config: list[ReportFeedOptions.Feed] = list()
    for feed in raw_feeds["feeds"]:
        feed_config.append(
            ReportFeedOptions.Feed(
                publisher=feed["publisher"],
                source=feed["source"],
                module=feed["module"],
                distribution="public" if "distribution" not in feed else feed["distribution"],
                site=feed["site"],
                feed_url=feed["feed_url"],
            )
        )

    if len(feed_config) < 1:
        raise Exception("feed list yaml contained no feeds")

    dump_feed_config(feed_config)

    downer = FileDownloader(apikey)
    feeds: list[BaseFeed] = ReportFeedOptions().feeds

    for feed in feeds:
        last_timestamp = state.checkForFeedLastTimestamp(feed.publisher)
        try:
            for report in feed.fetch(last_fetch=last_timestamp):
                if not report.timestamp or not report.publisher:
                    continue

                reportdir = os.path.join(outdir, report.publisher, str(report.timestamp))
                try:
                    os.makedirs(reportdir)
                except Exception:
                    if not os.path.exists(reportdir):
                        logger.error("Unable to create output dir %s", reportdir)
                        continue

                if report.slug:
                    title = report.slug
                else:
                    title = report.publisher + str(report.timestamp)
                # pdf reports are now optional
                if report.report:
                    with open(os.path.join(reportdir, title + ".pdf"), "wb") as tmp:
                        tmp.write(report.report)

                # may include the actual files
                have = []
                for f in report.files:
                    sha256 = hashlib.sha256(f).hexdigest()
                    sha1 = hashlib.sha1(f).hexdigest()  # noqa: S324
                    md5 = hashlib.md5(f).hexdigest()  # noqa: S324
                    with open(os.path.join(reportdir, sha256), "wb") as tmp:
                        tmp.write(f)
                    have.extend([md5, sha1, sha256])

                if apikey:
                    for indicator in report.indicators:
                        if indicator.has_at_least_one_hash():
                            for h in indicator.hashes_iter():
                                if h in have:
                                    continue  # Skip any files already obtained
                                try:
                                    downer.download(h, reportdir)
                                except Exception as ex:
                                    logger.warning("Unable to download Sample %s from VT: %s", h, str(ex))

                logger.info("Updating state for %s to %s" % (feed.publisher, report.timestamp))
                state.setFeedLastTimestamp(feed.publisher, report.timestamp)
        except Exception as ex:
            logger.error(str(ex))
            logger.error("Error fetching source %s skipping.", feed.publisher)


def dump_feed_config(feed_config: list[ReportFeedOptions.Feed]):
    """Dumps feeds into the env to mimic how feeds are passed when running as a plugin."""
    FEED_CONFIG_KEY: str = "REPORT_FEED_FEEDS_CONFIG"
    json_dumped_config = []
    for elem in feed_config:
        json_dumped_config.append(elem.model_dump())
    os.environ[FEED_CONFIG_KEY] = json.dumps(json_dumped_config)

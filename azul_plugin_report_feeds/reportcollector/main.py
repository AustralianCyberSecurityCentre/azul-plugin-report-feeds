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
from datetime import datetime, timezone

import click

from azul_plugin_report_feeds.reportcollector.base_feed import ReportFeedOptions
from azul_plugin_report_feeds.reportcollector.downloads import FileDownloader

logger = logging.getLogger("reportcollector")
DEFAULT_STATEDIR = os.path.expanduser("~/.reportcollector")


@click.command()
@click.option("--apikey", help="Api key to download files from virustotal with.")
@click.option("--statedir", default=DEFAULT_STATEDIR, help="Path to the directory where state is stored.")
@click.option("--outdir", default="reports", help="Directory where downloaded files and content are stored.")
@click.option("--debug", help="", default=False)
def main(apikey, statedir=DEFAULT_STATEDIR, outdir="reports", debug=False):
    """Run the cmdline for the reportcollector, scraping all configured endpoints.

    Hash indicators found are attempted to be downloaded via VirusTotal and as such,
    a private API Key is required.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s: %(name)s - %(levelname)s - %(message)s")
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        http_client.HTTPConnection.debuglevel = 1

    if not os.path.exists(statedir):
        try:
            os.makedirs(statedir)
        except Exception as e:
            raise Exception("Unable to create statedir: %s" % statedir) from e

    downer = FileDownloader(apikey)
    sources = ReportFeedOptions().feeds

    for source in sources:
        statefile = os.path.join(statedir, source.publisher)
        last_timestamp = None
        if os.path.exists(statefile):
            with open(statefile, "rb") as tmp:
                s = tmp.read().strip()
                last_timestamp = datetime.strptime(s.decode("utf-8"), "%Y-%m-%dT%H:%M:%S")
                last_timestamp = last_timestamp.replace(tzinfo=timezone.utc)
        try:
            for x in source.fetch(last_fetch=last_timestamp):
                datestamp = x["timestamp"][:10]
                reportdir = os.path.join(outdir, x["source"], datestamp)
                try:
                    os.makedirs(reportdir)
                except Exception:
                    if not os.path.exists(reportdir):
                        logger.error("Unable to create output dir %s", reportdir)
                        continue
                # pdf reports are now optional
                if x.get("report"):
                    with open(os.path.join(reportdir, x["slug"] + ".pdf"), "wb") as tmp:
                        tmp.write(x.pop("report"))

                # may include the actual files
                have = []
                for f in x.get("files", []):
                    sha256 = hashlib.sha256(f).hexdigest()
                    sha1 = hashlib.sha1(f).hexdigest()  # noqa: S324
                    md5 = hashlib.md5(f).hexdigest()  # noqa: S324
                    with open(os.path.join(reportdir, sha256), "wb") as tmp:
                        tmp.write(f)
                    have.extend([md5, sha1, sha256])
                x.pop("files", None)

                with open(os.path.join(reportdir, x["slug"] + ".meta"), "wb") as tmp:
                    tmp.write(json.dumps(x).encode("utf-8"))
                for h in x["hashes"]:
                    if h in have:
                        continue
                    try:
                        downer.download(h, reportdir)
                    except Exception as ex:
                        logger.warning("Unable to download Sample %s from VT: %s", h, str(ex))
                logger.info("Updating state for %s to %s" % (source.publisher, x["timestamp"]))
                with open(statefile, "wb") as tmp:
                    tmp.write(x["timestamp"].encode("utf-8"))
        except Exception as ex:
            logger.error(str(ex))
            logger.error("Error fetching source %s skipping.", source.publisher)

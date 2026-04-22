"""Classes for integrating Lookout blog reports."""

import logging
from datetime import datetime
from urllib.parse import urljoin

from azul_plugin_report_feeds.reportcollector.base_feed import ReportFeedOptions
from azul_plugin_report_feeds.reportcollector.feeds.rss import Entry, RSSFeed
from azul_plugin_report_feeds.reportcollector.util import request_url

logger = logging.getLogger("reportcollector")


class LookoutBlog(RSSFeed):
    """Source feed for Lookout Blogs."""

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new Lookout blog scraping feed."""
        super().__init__(feed_options, global_options)
        self.referer = "https://blog.lookout.com/topics#/"
        self.max_results = feed_options.max_results

    def listing(self) -> list[Entry]:
        """Return the latest list of available reports/blogs entries."""
        logger.info("Get entry listing from url: %s", self.feed_url)
        j = request_url(self.feed_url, self.referer).json()
        entries = [self.convert(x) for x in j["Results"]][: self.max_results]

        logger.info("%i entries found", len(entries))
        return sorted(entries, key=lambda x: x.published_parsed, reverse=True)

    def convert(self, entry: dict) -> Entry:
        """Map from the json blog structure to our standard entry tuple."""
        return Entry(
            entry["AdditionalFields"]["Title"],
            urljoin(self.feed_url, entry["AdditionalFields"]["path"]),
            entry["AdditionalFields"]["Date"],
            datetime.strptime(entry["AdditionalFields"]["Date"], "%Y%m%dT%H:%M:%S").timetuple(),
        )

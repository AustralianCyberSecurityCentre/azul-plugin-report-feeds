"""Classes for integrating with Symantec's blog via web api."""

import logging
from datetime import datetime, timezone
from typing import Iterator
from urllib.parse import urljoin

from azul_plugin_report_feeds.reportcollector.base_feed import ReportFeedOptions
from azul_plugin_report_feeds.reportcollector.feeds.rss import Entry, RSSFeed
from azul_plugin_report_feeds.reportcollector.util import request_url

logger = logging.getLogger("reportcollector")


class SymantecBlog(RSSFeed):
    """Source feed for Symantec's threat-intelligence blog."""

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new SymantecBlog."""
        super().__init__(feed_options, global_options)
        self.rows = feed_options.rows
        self.max_pages = feed_options.max_pages
        # entry urls don't appear to be from root
        self.blog_prefix = "https://symantec-enterprise-blogs.security.com/blogs/"
        # turns out 'page' is really row offset
        self.max_pages = self.max_pages * self.rows

    def listing(self) -> list[Entry]:
        """Return the latest list of available reports/blogs entries."""
        logger.info("Get entry listing from: %s", self.feed_url)
        entries = []
        for i in range(0, self.max_pages, self.rows):
            u = self.feed_url + "&rows=" + str(self.rows) + "&page=" + str(i)
            entries += list(self.get_entries(request_url(u).json()))

        logger.info("%i entries found", len(entries))
        return sorted(entries, key=lambda x: x.published_parsed, reverse=True)

    def get_entries(self, json: dict) -> Iterator[Entry]:
        """Yield the contained Entries from the given json page/response."""
        for r in json.get("results", []):
            link = urljoin(self.blog_prefix, r["urlAlias"].lstrip("/"))
            title = r["title"].strip()
            date = r["created"]  # unix ts
            date_parsed = datetime.fromtimestamp(float(date), tz=timezone.utc).timetuple()
            yield Entry(title, link, date, date_parsed)  # ty: ignore[missing-argument] content isn't specified

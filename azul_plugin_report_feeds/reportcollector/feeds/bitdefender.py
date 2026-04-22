"""Classes for interacting with BitDefender Labs public AntiMalware Research blog site."""

import logging
from datetime import datetime
from typing import Iterator
from urllib.parse import urljoin

import bs4

from azul_plugin_report_feeds.reportcollector.base_feed import ReportFeedOptions
from azul_plugin_report_feeds.reportcollector.feeds.rss import Entry, RSSFeed
from azul_plugin_report_feeds.reportcollector.util import request_url

logger = logging.getLogger("reportcollector")


class BitDefenderFeed(RSSFeed):
    """Source feed for BitDefender Labs web blogs/reports."""

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new BitDefenderFeed."""
        super().__init__(feed_options, global_options)
        self.max_pages = feed_options.max_pages

    def listing(self) -> list[Entry]:
        """Return the latest list of available reports/blogs entries."""
        logger.info("Get entry listing from: %s", self.feed_url)
        entries: list[Entry] = []
        for i in range(1, self.max_pages + 1):
            url = self.feed_url
            if i > 1:
                url = urljoin(self.feed_url, "page/%i/" % i)
                logger.info("Including additional page from: %s", url)
            entries += list(self.get_entries(request_url(url).text))

        logger.info("%i entries found", len(entries))
        return sorted(entries, key=lambda x: x.published_parsed, reverse=True)

    def get_entries(self, response: str) -> Iterator[Entry]:
        """Yield the contained Entries from the given html page/response."""
        bs = bs4.BeautifulSoup(response, "lxml")
        for v in bs.find_all("div", {"class": "article-thumb"}):
            anchor = v.find("a", {"class": "article-thumb__link"})
            if not anchor:
                continue
            link = urljoin(self.feed_url, anchor["href"])
            title = anchor.get_text().strip()
            date = v.find("p", {"class": "article-details__info"}).get_text().strip()
            date_parsed = datetime.strptime(date, "%B %d, %Y").timetuple()
            yield Entry(title, link, date, date_parsed)

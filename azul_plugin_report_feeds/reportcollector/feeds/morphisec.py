"""Classes for interacting with Morphisec's public blog site."""

import logging
from datetime import datetime
from typing import Iterator

import bs4

from azul_plugin_report_feeds.reportcollector.base_feed import ReportFeedOptions
from azul_plugin_report_feeds.reportcollector.feeds.rss import Entry, RSSFeed
from azul_plugin_report_feeds.reportcollector.util import request_url

logger = logging.getLogger("reportcollector")


class MorphisecFeed(RSSFeed):
    """Source feed for Morphisec blog."""

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new MorphisecFeed."""
        super().__init__(feed_options, global_options)
        self.max_pages = feed_options.max_pages

    def listing(self) -> list[Entry]:
        """Return the latest list of available reports/blogs entries."""
        logger.info("Get entry listing from: %s", self.feed_url)
        entries = list(self.get_entries(request_url(self.feed_url).text))
        for i in range(2, self.max_pages + 1):
            url = "%s/page/%i" % (self.feed_url, i)
            logger.info("Including additional page from: %s", url)
            entries += list(self.get_entries(request_url(url).text))

        logger.info("%i entries found", len(entries))
        return sorted(entries, key=lambda x: x.published_parsed, reverse=True)

    def get_entries(self, html: str) -> Iterator[Entry]:
        """Yield the contained Entries from the given html page/response."""
        bs = bs4.BeautifulSoup(html, "lxml")
        for v in bs.find_all("div", {"class": "post-header"}):
            date_div = v.find("div", {"id": "hubspot-author_data"})
            if date_div is None:
                raise ValueError("Expected date_div to be Tag, got None")
            date = date_div.get_text()
            date = date[date.index(" on ") :].strip()
            header = v.find("h2")
            if header is None:
                raise ValueError("Expected header to be Tag, got None")
            link_and_title = header.find("a")
            if link_and_title is None:
                raise ValueError("Expected link_and_title to be Tag, got None")
            link = link_and_title["href"]
            title = link_and_title.get_text()
            try:
                date_parsed = datetime.strptime(date, "on %b %d, %Y %I:%M:%S %p").timetuple()
            except ValueError:
                # more recent articles with the following date stamp
                date_parsed = datetime.strptime(date, "on %B %d, %Y").timetuple()

            yield Entry(title, link, date, date_parsed)  # ty: ignore[missing-argument] content is not specified

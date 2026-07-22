"""Classes for interacting with PaloAlto's Unit42 public blog site."""

import logging
from datetime import datetime
from typing import Iterator

import bs4

from azul_plugin_report_feeds.reportcollector.base_feed import ReportFeedOptions
from azul_plugin_report_feeds.reportcollector.feeds.rss import Entry, RSSFeed
from azul_plugin_report_feeds.reportcollector.util import request_url

logger = logging.getLogger("reportcollector")


class Unit42Feed(RSSFeed):
    """Source feed for PaloAlto's Unit42 web blogs/reports."""

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new Unit42Feed."""
        super().__init__(feed_options, global_options)
        self.max_offset = feed_options.max_offset
        self.offsets_per_page = 15

    def listing(self) -> list[Entry]:
        """Return the latest list of available reports/blogs entries."""
        logger.info("Get entry listing from: %s", self.feed_url)
        # count down through offsets by lots of 15 to 0
        entries: list[Entry] = []
        for i in range(self.max_offset, -1, self.offsets_per_page * -1):
            url = "%s&data%%5Boffset%%5D=%i" % (self.feed_url, i)
            logger.info("Including additional page from: %s", url)
            entries += list(self.get_entries(request_url(url).json()))

        logger.info("%i entries found", len(entries))
        return sorted(entries, key=lambda x: x.published_parsed, reverse=True)

    def get_entries(self, response: dict) -> Iterator[Entry]:
        """Yield the contained Entries from the given html page/response."""
        html = response["html"]
        bs = bs4.BeautifulSoup(html, "lxml")
        for v in bs.find_all("article"):
            anchor = v.find("a")
            if anchor is None:
                raise ValueError("Expected anchor to be Tag, got None")
            link = anchor["href"]
            title = anchor.get("data-page-track-value", anchor.get_text())
            date = v.find("time")
            if date is None:
                raise ValueError("Expected date to be Tag, got None")
            date_string = date["datetime"]
            if not isinstance(date_string, str):
                raise TypeError("Expected date_string to be str, got None")
            date_parsed = datetime.strptime(date_string[:19], "%Y-%m-%dT%H:%M:%S").timetuple()
            yield Entry(title, link, date_string, date_parsed)  # ty: ignore[missing-argument] content is not specified

"""Classes for integrating blog feeds via RSS or Atom."""

import logging
import traceback
from collections import namedtuple
from datetime import datetime, timezone
from typing import Iterator
from urllib.parse import urljoin

import feedparser
import httpx
from slugify import slugify

from azul_plugin_report_feeds.reportcollector.base_feed import (
    BaseFeed,
    ReportFeedOptions,
)
from azul_plugin_report_feeds.reportcollector.models import Indicator, ReportResult
from azul_plugin_report_feeds.reportcollector.parser import (
    PDF2TXT,
    HashFinder,
    HTML2PDFPlaywright,
    HTMLParser,
)
from azul_plugin_report_feeds.reportcollector.util import request_url

logger = logging.getLogger("reportcollector")

Entry = namedtuple("Entry", "title,link,published,published_parsed,content")
Entry.__new__.__defaults__ = (None,)


class RSSFeed(BaseFeed):
    """Sourcing reports from RSS blog feeds."""

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Create a new RSS feed scraper."""
        super().__init__(feed_options, global_options)
        self.converter = HTML2PDFPlaywright(global_options)
        self.extractor = PDF2TXT()
        self.finder = HashFinder()

    def retrieve_report(self, url: str, referer=None, content=None, depth=1) -> tuple[bytes, list[Indicator]] | None:
        """Fetch a potential report from the given url."""
        if depth > 3:
            return None

        if not content:
            r = request_url(url, referer)
            if r.url != url:
                logger.info("URL redirected to: %s", r.url)
                url = str(r.url)
            txt = r.content
        else:
            txt = content

        if txt.startswith(b"%PDF"):
            pdf = txt
            txt = self.extractor.convert(pdf)
            # FUTURE: rationalise this with the indicator parsing done in the parser
            h = set(self.finder.find(txt))
            indicators = [{"type": x[0], "value": x[1]} for x in h]
            logger.info(
                "%i indicators found",
                len(indicators),
            )
        else:
            parser = HTMLParser(url, txt)
            indicators = parser.get_indicators()
            # FUTURE: we can have situations where a blog will have one or two indicators
            # within the blog text but still link to a full report or ioc list
            if indicators:
                logger.info(
                    "%i indicators found",
                    len(indicators),
                )
                pdf = self.converter.convert(url)
                # regardless of whether converted successfully
                return pdf, indicators
            else:
                logger.info("No indicators found, searching for linked PDF instead")
                # try and find a linked pdf report
                links = list(set(parser.get_pdf_links(badwords=["quarterly", "annual"])))
                if not links:
                    logger.info("No linked PDF, looking for possible page links")
                    # NOTE - some keywords are specifically to try to stop following links in fireeye public blogs
                    links = list(
                        set(
                            parser.get_page_links(
                                [
                                    "report",
                                    "download",
                                    "iocs",
                                    "github.com",
                                    "indicators",
                                ],
                                badwords=[
                                    "openioc",
                                    "annual",
                                    "quarterly",
                                    "intelligence",
                                ],
                            )
                        )
                    )
                    if not links:
                        logger.info("Giving up on links")
                        return None

                # try all links:
                for ln in links:
                    link = urljoin(url, ln)
                    logger.info("Trying %s...", link)
                    try:
                        resp = self.retrieve_report(link, url, depth=depth + 1)
                        if resp:
                            logger.info("Indicators found from embedded link")
                            return resp
                    except Exception as ex:
                        # FUTURE distinguish between temp and perm fails
                        logger.warning("Broken Link? %s", str(ex))

        if indicators and pdf:
            return pdf, indicators  # ty: ignore[invalid-return-type] ty is confused by the `content`'s type, and frankly I am too.

    def listing(self):
        """Retrieve the full available RSS listing.

        Return as a list of Entry named tuples in newest to oldest order.
        """
        logger.info("Get entry listing from: %s", self.feed_url)
        feed = feedparser.parse(request_url(self.feed_url).text)
        logger.info("%i entries found", len(feed.entries))
        return feed.entries

    def fetch(self, last_fetch: datetime | None = None) -> Iterator[ReportResult]:
        """Yield the latest parsed reports from the RSS Feed, in asc time order.

        Generator yields dictionaries of report meta (and pdf when available).
        Entries are filtered to ensure they are after the last_fetch time, or all
        if None.
        """
        # Tolerance for bad links within an RSS feed.
        fails = 0
        successes = 0
        # Initial check for update time.
        for x in reversed(self.listing()):
            # alternate date format seen that breaks the rss parsing
            if hasattr(x, "published_parsed") and not x.published_parsed:
                published = datetime.strptime(
                    x.published.replace("th", "").replace("nd", "").replace("st", "").replace(" +0000", ""),
                    "%a, %d %b %Y %H:%M:%S",
                )
            elif hasattr(x, "published_parsed"):
                published = datetime(*x.published_parsed[:6])
            elif hasattr(x, "updated_parsed"):
                published = datetime(*x.updated_parsed[:6])
            else:
                x.pop("report", None)
                logger.warning("Skipping entry due to bad date. %s", str(x))
                continue

            if not published.tzinfo:
                published = published.replace(tzinfo=timezone.utc)
            if last_fetch and published <= last_fetch:
                continue

            logger.info(
                "Fetching report: %s (%s)",
                x.link,
                published.strftime("%Y-%m-%dT%H:%M:%S"),
            )
            report = None
            try:
                if hasattr(x, "content") and not isinstance(x.content, list):
                    report = self.retrieve_report(x.link, self.feed_url, x.content)
                else:
                    report = self.retrieve_report(x.link, self.feed_url)
                successes += 1
            except httpx._exceptions.HTTPStatusError as ex:
                exception_message = traceback.format_exception_only(ex)
                logger.warning(
                    "Exception when retrieving a top level RSS report URL '%s' error was %s",
                    x.link,
                    exception_message,
                )
                fails += 1
                # If enough of the top level links are bad the Feed is bad so raise an exception.
                # (Note success will be at least 1 if the feed itself succeeds.)
                if fails > successes:
                    raise
            if not report:
                continue

            pdf, indicators = report
            yield ReportResult(
                publisher=self.publisher,
                distribution=self.distribution,
                topic=self.source,
                site=self.site,
                url=x.link,
                title=x.title,
                slug=slugify(x.title),
                timestamp=published,
                report=pdf,
                indicators=indicators,
            )


class RSSContentFeed(RSSFeed):
    """RSS Feeds which include the report content in the xml."""

    def listing(self) -> list[feedparser.FeedParserDict]:
        """Retrieve the full available RSS listing.

        Return as a list of Entry named tuples in newest to oldest order.
        """
        logger.info("Get entry listing from: %s", self.feed_url)
        feed = feedparser.parse(request_url(self.feed_url).text)
        for e in feed.entries:
            if hasattr(e, "content") and isinstance(e.content, list):
                logger.info("Using embedded content as report for entry %s", e.title)
                e.content = b"\n".join([c.get("value", "").encode("utf-8") for c in e.content])
        logger.info("%i entries found", len(feed.entries))
        return feed.entries

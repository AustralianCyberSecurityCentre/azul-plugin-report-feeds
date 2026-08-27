"""Feed reader for feedly."""

from datetime import datetime, timedelta
from typing import Any, Iterator

import httpx
import pendulum
from pydantic import BaseModel, ConfigDict
from slugify import slugify

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.base_feed import (
    BaseFeed,
    ReportFeedOptions,
)
from azul_plugin_report_feeds.reportcollector.models import (
    GeneralIndicator,
    Indicator,
    ReportResult,
)
from azul_plugin_report_feeds.reportcollector.parser import (
    HTML2PDFPlaywright,
)


class CustomBaseModel(BaseModel):
    """Base model for all Feedly data."""

    model_config = ConfigDict(json_schema_extra={"exclude_none": True})


class FeedlyIOCMentions(CustomBaseModel):
    """Mentions within the IOCs of a feedly feed response."""

    type: str = ""
    text: str = ""  # Possible sha256
    canonical: str = ""  # Possible sha256
    subtype: str = ""


class FeedlyIOCExports(CustomBaseModel):
    """Exports within the IOCs of a feedly feed response."""

    type: str = ""
    url: str = ""


class FeedlyIOCs(CustomBaseModel):
    """IOCs within a feedly response the inner mentions often have notable sha256's."""

    mentions: list[FeedlyIOCMentions] = []
    exports: list[FeedlyIOCExports] = []


class FeedlyContentItem(CustomBaseModel):
    """Content of a feedly response."""

    content: str = ""


class FeedlyLinkedItems(CustomBaseModel):
    """Linked items including full HTML content linked by feedly."""

    id: str = ""
    language: str = ""
    parentEntryId: str = ""
    origin: dict[str, Any] = dict()
    content: FeedlyContentItem = FeedlyContentItem()
    title: str = ""
    crawled: int = -1
    canonicalUrl: str = ""
    expandedInline: bool = False
    originContentType: str = ""
    unread: bool = True
    categories: list[dict[str, Any]] = []
    commonTopics: list[dict[str, Any]] = []
    entities: list[dict[str, Any]] = []
    leoSummary: dict = dict()
    indicatorsOfCompromise: FeedlyIOCs = FeedlyIOCs()
    attackNavigator: dict[str, Any] = dict()
    webfeeds: dict[str, Any] = dict()


class FeedlyItems(CustomBaseModel):
    """Response items within a Feedly when getting a stream."""

    fingerprint: str = ""
    id: str = ""
    language: str = ""
    summary: dict[str, Any] = dict()
    crawled: int = -1
    published: int = -1
    commonTopics: list[dict[str, Any]] = []
    entities: list[dict[str, Any]] = []
    linked: list[FeedlyLinkedItems] = []


class FeedlyResponseStructure(CustomBaseModel):
    """Feedly response structure for getting from a stream."""

    continuation: str = ""
    id: str = ""
    title: str = ""
    items: list[FeedlyItems] = []


class JsonFeedly(BaseFeed):
    """Reads from Feedly's json stream id viewer and extracts the relevant content."""

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        """Init."""
        super().__init__(feed_options, global_options)
        self.converter = HTML2PDFPlaywright(global_options)
        # Not too old or fetch can take a long time
        self.max_days_to_go_back = feed_options.max_days
        # Not too new or you get incomplete reports.
        self.older_than_days = feed_options.older_than_days
        self.feedly_url_encoded_stream_id = global_options.feedly_url_encoded_stream_id
        self.feedly_bearer_token = global_options.feedly_bearer_token
        self.feedly_url = f"{feed_options.feed_url}?streamID="

    def fetch(self, last_fetch: datetime | None) -> Iterator[ReportResult]:
        """Yield the latest parsed reports from the Feedly json feed."""
        # Reports published at or before this were read on an earlier run.
        already_read = last_fetch
        if not last_fetch:
            last_fetch = datetime.now(tz=pendulum.UTC)
            last_fetch = last_fetch - timedelta(days=self.max_days_to_go_back)

        closest_fetch = datetime.now(tz=pendulum.UTC) - timedelta(days=-self.older_than_days)

        time_since_in_ms = int(last_fetch.timestamp() * 1000)
        closest_fetch_in_ms = int(closest_fetch.timestamp() * 1000)

        token = self.feedly_bearer_token
        if not self.feedly_bearer_token.startswith("Bearer "):
            token = f"Bearer {token}"
        headers = {"accept": "application/json", "Authorization": token}
        continuation = True
        while continuation:
            with httpx.Client(headers=headers) as web_client:
                fetch_url = (
                    self.feedly_url
                    + self.feedly_url_encoded_stream_id
                    + f"&count=20&newerThan={time_since_in_ms}&olderThan={closest_fetch_in_ms}"
                )
                if isinstance(continuation, str):
                    fetch_url = fetch_url + f"&continuation={continuation}"
                response = web_client.get(fetch_url, follow_redirects=True)
                response.raise_for_status()
                response_model = FeedlyResponseStructure(**response.json())

                continuation = response_model.continuation

            for item in response_model.items:
                best_content = ""
                extracted_title = ""
                published_time = pendulum.from_timestamp(item.published / 1000)
                # `newerThan` filters on when feedly crawled an entry rather than when it was published,
                # so reports read on an earlier run come back and would be submitted a second time.
                if already_read and published_time <= already_read:
                    continue
                source_url = ""
                iocs: list[Indicator] = []
                general_indicator_values: set[str] = set()
                general_indicators: list[GeneralIndicator] = []
                # Look over each link and identify indicators and the best raw content.
                for link in item.linked:
                    raw_content = link.content.content
                    if len(raw_content) > len(best_content):
                        best_content = raw_content
                        extracted_title = link.title
                        source_url = link.canonicalUrl

                    for ioc in link.indicatorsOfCompromise.mentions:
                        if ioc.type == "hash":
                            if ioc.subtype == "sha512":
                                continue
                            current_ioc = Indicator()
                            current_ioc.assign_hashes([ioc.text])
                            iocs.append(current_ioc)
                            continue

                        # Skipping adding general indicator if it's already present.
                        if ioc.text in general_indicator_values:
                            continue

                        general_indicator_values.add(ioc.text)

                        general_indicators.append(
                            GeneralIndicator(
                                type=ioc.type,  # Depending on type canonical can be more useful.
                                text=ioc.text,
                                additional_text=ioc.canonical,
                            )
                        )
                # no content to yield.
                if len(best_content) == 0:
                    continue
                pdf = self.converter.convert_raw_html(best_content)
                yield ReportResult(
                    publisher=self.publisher,
                    distribution=self.distribution,
                    topic=self.source,
                    url=source_url,
                    title=extracted_title,
                    slug=slugify(extracted_title),
                    timestamp=published_time,
                    report=pdf,
                    indicators=iocs,
                    general_indicators=general_indicators,
                )


# Basic check to see continuation works.

if __name__ == "__main__":
    base_feed_settings = base_feed.ReportFeedOptions.Feed(
        publisher="Test",
        distribution="public",
        source="reporting",
        site="test",
        feed_url="https://api.feedly.com/v3/streams/contents",
        module="",
        max_days=365,
    )
    jf = JsonFeedly(base_feed_settings, base_feed.ReportFeedOptions())

    iterations = 0
    for r in jf.fetch(None):
        iterations += 1
        print(iterations)
        print(f"{iterations}: {r.report_id}, {r.timestamp}, {r.slug}")

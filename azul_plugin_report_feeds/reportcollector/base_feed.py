"""BaseFeed holding a class with core functions required of a feed."""

import importlib
import os
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Iterator

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from azul_plugin_report_feeds.reportcollector.models import ReportResult

PARENT_MODULE = "azul_plugin_report_feeds"


def class_for_name(class_name: str):
    """Dynamically load the given class name.

    :param class_name: str with class name to import/load.
    :return: Loaded Class object.
    """
    module_name, class_name = class_name.rsplit(".", 1)
    module = importlib.import_module(f"{PARENT_MODULE}.{module_name}")
    return getattr(module, class_name)


class PlaywrightLoadingDoneState(StrEnum):
    """String enum for possible playwright loading states."""

    commit = "commit"
    domcontentloaded = "domcontentloaded"
    load = "load"
    networkidle = "networkidle"


class ReportFeedOptions(BaseSettings):
    """Centeralised report feed specific settings, to configure how websites are browsed and PDFs generated."""

    model_config = SettingsConfigDict(env_prefix="report_feed_")

    class Feed(BaseModel):
        """Nested configuration for each individual feed."""

        publisher: str
        source: str
        module: str
        distribution: str = "public"
        site: str
        feed_url: str
        # Feed specific config
        rows: int = 5
        max_pages: int = 10
        max_offset: int = 60
        max_reports: int = 30
        max_results: int = 200
        max_file_size: int = 100 * 1024 * 1024
        max_days: int = 180
        older_than_days: int = 1

    feeds_config: list[Feed] = []
    proxy_url: str = ""
    playwright_loading: PlaywrightLoadingDoneState = PlaywrightLoadingDoneState.networkidle

    feedly_url_encoded_stream_id: str = ""
    feedly_bearer_token: str = ""

    _feeds: list[type["BaseFeed"]] | None = None

    def perform_setup(self):
        """Perform the environment setup for the report feed options to be used."""
        if self.proxy_url:
            os.environ["HTTP_PROXY"] = self.proxy_url
            os.environ["HTTPS_PROXY"] = self.proxy_url

        self._feeds = []
        for cur_feed in self.feeds_config:
            cls = class_for_name(cur_feed.module)
            self._feeds.append(cls(feed_options=cur_feed, global_options=self))

    @property
    def feeds(self) -> list[type["BaseFeed"]]:
        """Get the feeds objects."""
        if not self._feeds:
            self._feeds = []
            self.perform_setup()
        return self._feeds


class BaseFeed(ABC):
    """Base class for all report feeds."""

    def __init__(self, feed_options: ReportFeedOptions.Feed, global_options: ReportFeedOptions):
        self.source = feed_options.source
        self.publisher = feed_options.publisher
        self.distribution = feed_options.distribution
        self.site = feed_options.site
        self.feed_url = feed_options.feed_url

    @abstractmethod
    def fetch(self, last_fetch: datetime | None) -> Iterator[ReportResult]:
        """Fetch all the reports from the feed."""
        ...

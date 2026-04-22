"""Tests for importing exported feeds."""

import os
from datetime import datetime, timezone

import deepdiff

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.feeds import filesystem
from azul_plugin_report_feeds.reportcollector.models import Indicator, ReportResult


def test_fetch():
    f = filesystem.ExportedFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Example",
            source="reporting",
            distribution="public",
            module="",
            site="http://test.com",
            feed_url=os.path.dirname(__file__) + "/Example",
        ),
        base_feed.ReportFeedOptions(),
    )
    ents = list(f.fetch())
    assert len(ents) == 3
    assert set(ents[0].files) == {b"BBB\n", b"AAA\n"}
    ents[0].files = []
    expected = ReportResult(
        publisher="Example",
        distribution="public",
        topic="reporting",
        site="http://test.com",
        url="https://test.foo.com/2020/i-am-running-out-of-report-names/",
        title="I am running out of report names",
        slug="i-am-running-out-of-report-names",
        timestamp=datetime.fromisoformat("2020-08-17T10:15:15"),
        report=b"%PDF-1.0NotReally\n",
        indicators=[
            Indicator(sha256="36a4aba0dcec23e926f0692065524808479c33f4501bae79348f8f005f10b21c"),
            Indicator(md5="8880cd8c1fb402585779766f681b868b"),
            Indicator(md5="cdac10d71fc7dc8b8064ac9dbbf3f743"),
        ],
    )
    deep_diff = deepdiff.DeepDiff(ents[0].model_dump(), expected.model_dump())
    print(deep_diff)
    assert ents[0].model_dump() == expected.model_dump()
    # test defaulting of fields for old style meta format
    ents[1].files = []

    deep_diff = deepdiff.DeepDiff(ents[0].model_dump(), expected.model_dump())
    print(deep_diff)
    expected_2 = ReportResult(
        publisher="Example",
        distribution="public",
        topic="reporting",
        site="http://test.com",
        url="https://test.foo.com/2020/report/",
        title="Another Test Report",
        slug="another-test-report",
        timestamp="2020-08-17T11:15:15",
        indicators=[
            Indicator(sha256="36a4aba0dcec23e926f0692065524808479c33f4501bae79348f8f005f10b21c"),
            Indicator(md5="cdac10d71fc7dc8b8064ac9dbbf3f743"),
        ],
    )
    deep_diff = deepdiff.DeepDiff(ents[1].model_dump(), expected_2.model_dump())
    print(deep_diff)
    assert ents[1].model_dump() == expected_2.model_dump()


def test_fetch_dir_filter():
    f = filesystem.ExportedFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Example",
            source="reporting",
            distribution="public",
            module="",
            site="http://test.com",
            feed_url=os.path.dirname(__file__) + "/Example",
        ),
        base_feed.ReportFeedOptions(),
    )
    ents = list(f.fetch(last_fetch=datetime(2020, 8, 17, 10, 15, 15, tzinfo=timezone.utc)))
    assert len(ents) == 2
    assert ents[0].timestamp == datetime.fromisoformat("2020-08-17T11:15:15+00:00")
    assert ents[1].timestamp == datetime.fromisoformat("2020-10-15T03:15:15+00:00")


def test_fetch_timestamp_filter():
    f = filesystem.ExportedFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Example",
            source="reporting",
            distribution="public",
            module="",
            site="http://test.com",
            feed_url=os.path.dirname(__file__) + "/Example",
        ),
        base_feed.ReportFeedOptions(),
    )
    ents = list(f.fetch(last_fetch=datetime(2020, 8, 17, 11, 15, 15, tzinfo=timezone.utc)))
    assert len(ents) == 1
    assert ents[0].timestamp.isoformat() == "2020-10-15T03:15:15+00:00"

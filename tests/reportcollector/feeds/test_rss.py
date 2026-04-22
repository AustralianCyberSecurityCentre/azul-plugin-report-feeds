"""Test suite for standard RSS feed."""

import os.path
from datetime import datetime

import deepdiff
import httpx
import pytest
from pytest_httpserver import HTTPServer

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.feeds import rss
from azul_plugin_report_feeds.reportcollector.models import Indicator, ReportResult


@pytest.fixture
def rss_response():
    with open(os.path.join(os.path.dirname(__file__), "test_rss.xml"), "rb") as f:
        return f.read()


@pytest.fixture
def rss_response_4_values():
    with open(os.path.join(os.path.dirname(__file__), "test_rss_4_values.xml"), "rb") as f:
        return f.read()


@pytest.fixture
def rss_content_response():
    with open(os.path.join(os.path.dirname(__file__), "test_content_rss.xml"), "rb") as f:
        return f.read()


@pytest.fixture
def report_response():
    with open(os.path.join(os.path.dirname(__file__), "test_rss.html"), "rb") as f:
        return f.read()


# Using different playwright loading, as it makes testing a little quicker
CUSTOM_TEST_SETTINGS = base_feed.ReportFeedOptions(playwright_loading=base_feed.PlaywrightLoadingDoneState.load)


def test_listing(httpserver: HTTPServer, rss_response: bytes, report_response: bytes):
    httpserver.expect_request("/security/blog").respond_with_data(response_data=rss_response)
    httpserver.expect_request("/security/blog/2021/06/14/test-title-1/").respond_with_data(
        response_data=report_response
    )
    httpserver.expect_request("/security/blog/2021/05/26/test-title-2/").respond_with_data(
        response_data=report_response
    )
    p = rss.RSSFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Test",
            distribution="public",
            source="reporting",
            site="test",
            feed_url=httpserver.url_for("/security/blog"),
            module="",
        ),
        CUSTOM_TEST_SETTINGS,
    )
    e = p.listing()
    assert len(e) == 2
    assert e[0].title == "Test title 1"
    assert e[0].link == "http://www.test.com/security/blog/2021/06/14/test-title-1/"
    assert e[0].published == "Mon, 14 Jun 2021 16:00:44 +0000"
    assert e[1].title == "Test title 2"
    assert e[1].link == "http://www.test.com/security/blog/2021/05/26/test-title-2/"
    assert e[1].published == "Wed, 26 May 2021 21:36:17 +0000"


def test_retrieve_report(httpserver: HTTPServer, report_response: bytes):
    httpserver.expect_request("/security/blog/2021/06/14/test-title-1/").respond_with_data(
        response_data=report_response
    )
    httpserver.expect_request("/security/blog").respond_with_json({})
    p = rss.RSSFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Test",
            distribution="public",
            source="reporting",
            site="test",
            feed_url=httpserver.url_for("/security/blog"),
            module="",
        ),
        CUSTOM_TEST_SETTINGS,
    )
    report = p.retrieve_report(url=httpserver.url_for("/security/blog/2021/06/14/test-title-1/"))
    assert report is not None
    pdf, indicators = report
    # uses built in pdf converter
    assert len(pdf) > 1
    # have only implemented hash extraction so far
    assert indicators
    assert len(indicators) == 3
    assert Indicator(md5="4a57a635ea1fb4db0a57480d811bf8d7") in indicators
    assert Indicator(sha256="c95ea4fc921c016fd056f96800d6c8e79167f5057b168c25a424a74ae2ca5170") in indicators
    assert Indicator(sha256="df6987c7a5e621b8ff7c8049f895a8e511b51fefba6f8943c920cbcbb77a8377") in indicators


def test_fetch(httpserver: HTTPServer, rss_response: bytes, report_response: bytes):
    # Replace URLS in the RSS response with URLs that point to the test server.
    rss_response_as_str = rss_response.decode().replace("http://www.test.com/", httpserver.url_for(""))
    httpserver.expect_request("/security/blog").respond_with_data(rss_response_as_str)
    httpserver.expect_request("/security/blog/2021/06/14/test-title-1/").respond_with_data(report_response)
    httpserver.expect_request("/security/blog/2021/05/26/test-title-2/").respond_with_data(report_response)
    p = rss.RSSFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Test",
            distribution="public",
            source="reporting",
            site="test",
            feed_url=httpserver.url_for("/security/blog"),
            module="",
        ),
        CUSTOM_TEST_SETTINGS,
    )
    actual_report = list(p.fetch())
    assert len(actual_report) == 2
    expected_report = ReportResult(
        publisher="Test",
        distribution="public",
        topic="reporting",
        site="test",
        url=httpserver.url_for("/security/blog/2021/05/26/test-title-2/"),
        title="Test title 2",
        slug="test-title-2",
        timestamp=datetime.fromisoformat("2021-05-26T21:36:17"),
        indicators=[
            Indicator(md5="4a57a635ea1fb4db0a57480d811bf8d7"),
            Indicator(sha256="c95ea4fc921c016fd056f96800d6c8e79167f5057b168c25a424a74ae2ca5170"),
            Indicator(sha256="df6987c7a5e621b8ff7c8049f895a8e511b51fefba6f8943c920cbcbb77a8377"),
        ],
    )
    assert set(expected_report.indicators_hashes_iter()) == set(actual_report[0].indicators_hashes_iter())
    # Don't need to compare all the indicators.
    actual_report[0].indicators = []
    # Don't want to compare the actual report (as it changes slightly.)
    actual_report[0].report = None
    expected_report.indicators = []
    diff = deepdiff.DeepDiff(actual_report[0].model_dump(), expected_report.model_dump())
    print(diff)
    assert actual_report[0].model_dump() == expected_report.model_dump()


def test_fetch_blog_404(httpserver: HTTPServer, report_response: bytes):
    httpserver.expect_request("/security/blog").respond_with_json({}, status=404)
    httpserver.expect_request("/security/blog/2021/06/14/test-title-1/").respond_with_data(report_response)
    httpserver.expect_request("/security/blog/2021/05/26/test-title-2/").respond_with_data(report_response)

    p = rss.RSSFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Test",
            distribution="public",
            source="reporting",
            site="test",
            feed_url=httpserver.url_for("/security/blog"),
            module="",
        ),
        CUSTOM_TEST_SETTINGS,
    )
    with pytest.raises(httpx._exceptions.HTTPStatusError):
        list(p.fetch())


def test_fetch_single_404(httpserver: HTTPServer, rss_response: bytes, report_response: bytes):
    # Replace URLS in the RSS response with URLs that point to the test server.
    rss_response_as_str = rss_response.decode().replace("http://www.test.com/", httpserver.url_for(""))
    httpserver.expect_request("/security/blog").respond_with_data(rss_response_as_str)
    httpserver.expect_request("/security/blog/2021/06/14/test-title-1/").respond_with_json({}, status=404)
    httpserver.expect_request("/security/blog/2021/05/26/test-title-2/").respond_with_data(report_response)

    p = rss.RSSFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Test",
            distribution="public",
            source="reporting",
            site="test",
            feed_url=httpserver.url_for("/security/blog"),
            module="",
        ),
        CUSTOM_TEST_SETTINGS,
    )
    actual_report = list(p.fetch())
    assert len(actual_report) == 1
    expected_report = ReportResult(
        publisher="Test",
        distribution="public",
        topic="reporting",
        site="test",
        url=httpserver.url_for("/security/blog/2021/05/26/test-title-2/"),
        title="Test title 2",
        slug="test-title-2",
        timestamp=datetime.fromisoformat("2021-05-26T21:36:17"),
        indicators=[
            Indicator(md5="4a57a635ea1fb4db0a57480d811bf8d7"),
            Indicator(sha256="c95ea4fc921c016fd056f96800d6c8e79167f5057b168c25a424a74ae2ca5170"),
            Indicator(sha256="df6987c7a5e621b8ff7c8049f895a8e511b51fefba6f8943c920cbcbb77a8377"),
        ],
    )
    assert set(expected_report.indicators_hashes_iter()) == set(actual_report[0].indicators_hashes_iter())
    actual_report[0].indicators = []
    # Don't want to compare the actual report (as it changes slightly.)
    actual_report[0].report = None
    expected_report.indicators = []
    diff = deepdiff.DeepDiff(actual_report[0].model_dump(), expected_report.model_dump())
    print(diff)
    assert actual_report[0].model_dump() == expected_report.model_dump()


def test_fetch_multiple_404(httpserver: HTTPServer, rss_response_4_values: bytes, report_response: bytes):
    # Replace URLS in the RSS response with URLs that point to the test server.
    rss_response_4_values_as_str = rss_response_4_values.decode().replace(
        "http://www.test.com/", httpserver.url_for("")
    )
    httpserver.expect_request("/security/blog").respond_with_data(rss_response_4_values_as_str)
    httpserver.expect_request("/security/blog/2021/06/14/test-title-1/").respond_with_json({}, status=404)
    httpserver.expect_request("/security/blog/2021/05/26/test-title-2/").respond_with_json({}, status=404)
    httpserver.expect_request("/security/blog/2021/05/26/test-title-3/").respond_with_json({}, status=404)
    httpserver.expect_request("/security/blog/2021/05/26/test-title-4/").respond_with_data(report_response)

    p = rss.RSSFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Test",
            distribution="public",
            source="reporting",
            site="test",
            feed_url=httpserver.url_for("/security/blog"),
            module="",
        ),
        CUSTOM_TEST_SETTINGS,
    )
    with pytest.raises(httpx.HTTPStatusError):
        list(p.fetch())


def test_content_listing(httpserver: HTTPServer, rss_content_response: bytes):
    """
    We will usually follow links for the content, even if included.

    In some cases, however, the linked pages are robots blocked, and we use rss content directly.
    """
    httpserver.expect_request("/security/blog").respond_with_data(rss_content_response)

    p = rss.RSSContentFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Test",
            distribution="public",
            source="reporting",
            site="test",
            feed_url=httpserver.url_for("/security/blog"),
            module="",
        ),
        CUSTOM_TEST_SETTINGS,
    )
    e = p.listing()
    assert len(e) == 2
    assert e[0].title == "Test title 1"
    assert e[0].link == "http://www.test.com/security/blog/2021/06/14/test-title-1/"
    assert e[0].published == "Mon, 14 Jun 2021 16:00:44 +0000"
    assert b"long descriptive" in e[0].content
    assert e[1].title == "Test title 2"
    assert e[1].link == "http://www.test.com/security/blog/2021/05/26/test-title-2/"
    assert e[1].published == "Wed, 26 May 2021 21:36:17 +0000"
    assert b"further descriptive" in e[1].content

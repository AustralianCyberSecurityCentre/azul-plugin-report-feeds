"""Test feedly."""

import os.path
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pendulum
import pytest
from pytest_httpserver import HTTPServer
from pytest_httpserver.httpserver import QueryMatcher

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.feeds import feedly
from azul_plugin_report_feeds.reportcollector.models import (
    GeneralIndicator,
    Indicator,
)


@pytest.fixture
def feedly_response() -> bytes:
    with open(os.path.join(os.path.dirname(__file__), "feedly_sample.json"), "rb") as f:
        return f.read()


@pytest.fixture
def feedly_empty_response() -> bytes:
    with open(os.path.join(os.path.dirname(__file__), "feedly_empty_sample.json"), "rb") as f:
        return f.read()


COMMON_GLOBAL_OPTIONS = base_feed.ReportFeedOptions(
    feedly_bearer_token="abc", feedly_url_encoded_stream_id="fakeStreamId"
)


class FeedlyQueryMatcher(QueryMatcher):
    def __init__(self, query_key: str, query_value: str, fuzzy_number: bool):
        self.expected_query_param_value = query_value
        self.expected_query_param_key = query_key
        self.fuzzy_number = fuzzy_number
        # How close the two numbers need to be to be considered equal (30 seconds)
        self.fuzzy_variance = 30

    def get_comparing_values(self, request_query_string: bytes) -> tuple[Any, Any]:
        query_param_dict = dict()
        for query_param in parse_qsl(request_query_string.decode()):
            query_param_dict[query_param[0]] = query_param[1]
        print(query_param_dict)

        try:
            if self.fuzzy_number:
                query_param_dict[self.expected_query_param_key]
                self.expected_query_param_value
                selected_val = int(query_param_dict[self.expected_query_param_key]) + self.fuzzy_variance
                if selected_val > int(
                    self.expected_query_param_value
                ) and selected_val - self.fuzzy_variance * 2 < int(self.expected_query_param_value):
                    return (0, 0)
                else:
                    print(
                        f"Query parameters with key '{self.expected_query_param_key}' are not equal with value "
                        + f"{query_param_dict[self.expected_query_param_key]} != {self.expected_query_param_value}"
                    )
                    return query_param_dict[self.expected_query_param_key], self.expected_query_param_value
            else:
                print("GHI")
                return (self.expected_query_param_value, query_param_dict[self.expected_query_param_key])
        except Exception as e:
            print(f"Failed to validate input parameters with error {e}")
            raise


def test_fetch_normal(httpserver: HTTPServer, feedly_response: bytes):
    """Test a fetch behaves correctly in the feedly feed."""
    max_days_feed_old = 90
    current_date = datetime.now(tz=pendulum.UTC) - timedelta(days=max_days_feed_old)
    current_timestamp_ms = int(1000 * current_date.timestamp())
    httpserver.expect_request(
        "/v3/streams/contents", query_string=FeedlyQueryMatcher("newerThan", str(current_timestamp_ms), True)
    ).respond_with_data(response_data=feedly_response)
    feed_settings = base_feed.ReportFeedOptions.Feed(
        publisher="Test",
        distribution="public",
        source="reporting",
        site="test",
        feed_url=httpserver.url_for("/v3/streams/contents"),
        module="",
        max_days=max_days_feed_old,
    )
    p = feedly.JsonFeedly(feed_settings, COMMON_GLOBAL_OPTIONS)

    resp = p.fetch(last_fetch=None)
    # First response
    r = next(resp)
    print(r.title)
    assert r.title == "f6dfc06fb7fa8e733ae7b2541d7b1771cd1b6d11984b97f636a9ac47e23ad811"
    print(r.timestamp)
    assert r.timestamp == pendulum.DateTime(2026, 1, 18, 8, 15, 26, tzinfo=pendulum.UTC)
    print(r.url)
    assert r.url == "https://tria.ge/260117-qf18ysat4c"
    print(r.indicators)
    assert r.indicators == [
        Indicator(sha256="f6dfc06fb7fa8e733ae7b2541d7b1771cd1b6d11984b97f636a9ac47e23ad811"),
        Indicator(md5="ed770654eb36947eec999ea1492452c9"),
        Indicator(sha1="8f4634f89b0aa1d417582a1cb8c2e882e02691e8"),
    ]
    print(r.general_indicators)
    assert r.general_indicators == []
    assert len(r.report) > 10

    # Second response
    r = next(resp)
    print(r.title)
    assert r.title == "New Remcos Campaign Distributed Through Fake Shipping Document"
    print(r.timestamp)
    assert r.timestamp == pendulum.DateTime(2026, 1, 18, 14, 1, 50, tzinfo=pendulum.UTC)
    print(r.url)
    assert (
        r.url
        == "https://www.fortinet.com/blog/threat-research/new-remcos-campaign-distributed-through-fake-shipping-document"
    )
    indicators = [cur_i.model_dump(exclude_none=True) for cur_i in r.indicators]
    print(indicators)
    assert r.indicators == [
        Indicator(sha256="E915CE8F7271902FA7D270717A5C08E57014528F19C92266F7B192793D40972F"),
        Indicator(sha256="A35DD25CD31E4A7CCA528DBFFF37B5CDBB4076AAC28B83FD4DA397027402BADD"),
        Indicator(sha256="7798059D678BCA13EEEEBB44A8DB3588E4AA287701AEDE94B094B18F33B58F84"),
        Indicator(sha256="94CA3BEEB0DFD3F02FE14DE2E6FB0D26E29BEB426AEE911422B08465AFBD2FAA"),
    ]
    print(r.general_indicators)
    assert r.general_indicators == [
        GeneralIndicator(
            type="url",
            text="hxxps://go-shorty[.]killcod3[.]com/OkkxCrq",
            additional_text="https://go-shorty[.]killcod3.com/okkxcrq",
        ),
        GeneralIndicator(
            type="url",
            text="hxxp://66[.]179[.]94[.]117/157/fsf090g90dfg090asdfxcv0sdf09sdf90200002f0sf0df09f0s9f0sdf0sf00ds.vbe",
            additional_text="http://66[.]179.94.117/157/fsf090g90dfg090asdfxcv0sdf09sdf90200002f0sf0df09f0s9f0sdf0sf00ds.vbe",
        ),
        GeneralIndicator(
            type="url",
            text="hxxp://66[.]179[.]94[.]117/157/w/w.doc",
            additional_text="http://66[.]179.94.117/157/w/w.doc",
        ),
        GeneralIndicator(type="url", text="hxxps://tnvs[.]de/e4gUVc", additional_text="https://tnvs[.]de/e4guvc"),
        GeneralIndicator(
            type="url",
            text="hxxp://66[.]179.94.117/157/fsf090g90dfg090asdfxcv0sdf09sdf90200002f0sf0df09f0s9f0sdf0sf00ds.vbe",
            additional_text="http://66[.]179.94.117/157/fsf090g90dfg090asdfxcv0sdf09sdf90200002f0sf0df09f0s9f0sdf0sf00ds.vbe",
        ),
        GeneralIndicator(
            type="url",
            text="hxxps://idliya[.]com/assets/optimized_MSI.png",
            additional_text="https://idliya[.]com/assets/optimized_msi.png",
        ),
        GeneralIndicator(
            type="url",
            text="hxxps://idliya[.]com/arquivo_20251130221101.txt",
            additional_text="https://idliya[.]com/arquivo_20251130221101.txt",
        ),
    ]
    assert len(r.report) > 10


def test_fetch_continuation(httpserver: HTTPServer, feedly_response: bytes):
    """Test a fetch behaves correctly in the feedly feed."""
    max_days_feed_old = 90
    current_date = datetime.now(tz=pendulum.UTC) - timedelta(days=max_days_feed_old)
    current_timestamp_ms = int(1000 * current_date.timestamp())
    httpserver.expect_request(
        "/v3/streams/contents", query_string=FeedlyQueryMatcher("newerThan", str(current_timestamp_ms), True)
    ).respond_with_data(response_data=feedly_response)
    feed_settings = base_feed.ReportFeedOptions.Feed(
        publisher="Test",
        distribution="public",
        source="reporting",
        site="test",
        feed_url=httpserver.url_for("/v3/streams/contents"),
        module="",
        max_days=max_days_feed_old,
    )
    p = feedly.JsonFeedly(feed_settings, COMMON_GLOBAL_OPTIONS)

    found_reports = 0
    # There is only 3 reports so if 10 are found it means they were found via continuations.
    for r in p.fetch(last_fetch=None):
        found_reports += 1
        if found_reports >= 10:
            break

    assert 10 == found_reports


def _base_status_code_error(httpserver: HTTPServer, status_code: int):
    """Base case for testing status code failures"""
    max_days_feed_old = 90
    current_date = datetime.now(tz=pendulum.UTC) - timedelta(days=max_days_feed_old)
    current_timestamp_ms = int(1000 * current_date.timestamp())
    httpserver.expect_request("/v3/streams/contents", str(current_timestamp_ms)).respond_with_json({}, status=500)
    feed_settings = base_feed.ReportFeedOptions.Feed(
        publisher="Test",
        distribution="public",
        source="reporting",
        site="test",
        feed_url=httpserver.url_for("/v3/streams/contents"),
        module="",
        max_days=max_days_feed_old,
    )
    p = feedly.JsonFeedly(feed_settings, COMMON_GLOBAL_OPTIONS)

    resp = p.fetch(last_fetch=None)
    # First response
    with pytest.raises(httpx.HTTPStatusError):
        next(resp)


def test_fetch_failure_404(httpserver: HTTPServer):
    """Test fetch fails on a 404 error."""
    _base_status_code_error(httpserver, 404)


def test_fetch_failure_400(httpserver: HTTPServer):
    """Test fetch fails on a 400 error."""
    _base_status_code_error(httpserver, 400)


def test_fetch_failure_500(httpserver: HTTPServer):
    """Test fetch fails on a 500 error."""
    _base_status_code_error(httpserver, 500)


def test_empty_response(httpserver: HTTPServer, feedly_empty_response: bytes):
    """Test a nearly empty response from feedly, doesn't provide any data."""
    max_days_feed_old = 90
    current_date = datetime.now(tz=pendulum.UTC) - timedelta(days=max_days_feed_old)
    current_timestamp_ms = int(1000 * current_date.timestamp())
    httpserver.expect_request(
        "/v3/streams/contents", query_string=FeedlyQueryMatcher("newerThan", str(current_timestamp_ms), True)
    ).respond_with_data(response_data=feedly_empty_response)
    feed_settings = base_feed.ReportFeedOptions.Feed(
        publisher="Test",
        distribution="public",
        source="reporting",
        site="test",
        feed_url=httpserver.url_for("/v3/streams/contents"),
        module="",
        max_days=max_days_feed_old,
    )
    p = feedly.JsonFeedly(feed_settings, COMMON_GLOBAL_OPTIONS)

    resp = p.fetch(last_fetch=None)

    assert len(list(r for r in resp)) == 0

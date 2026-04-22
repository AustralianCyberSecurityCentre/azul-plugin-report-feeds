"""Test suite for BitDefender blog feed."""

import datetime
import os.path

import respx

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.feeds import bitdefender

HTML_RESPONSE = open(os.path.join(os.path.dirname(__file__), "test_bitdefender_2021.html"), "rb").read()


def test_get_entries():
    p = bitdefender.BitDefenderFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="BitDefender",
            source="reporting",
            distribution="public",
            module="",
            site="test",
            feed_url="http://test.com/",
            max_offset=45,
        ),
        base_feed.ReportFeedOptions(),
    )
    e = list(p.get_entries(HTML_RESPONSE))
    assert len(e) == 1
    assert e[0].title == "New WastedLoader Campaign Delivered Through RIG Exploit Kit"
    assert e[0].link == "http://test.com/blog/labs/new-wastedloader-campaign-delivered-through-rig-exploit-kit/"
    assert e[0].published_parsed == datetime.datetime(2021, 5, 18, 0, 0, 0, tzinfo=datetime.timezone.utc).timetuple()


def test_listing(respx_mock: respx.MockRouter):
    respx_mock.get("http://test.com/").respond(200, content=HTML_RESPONSE)
    respx_mock.get("http://test.com/page/2/").respond(200, content=HTML_RESPONSE)

    p = bitdefender.BitDefenderFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="BitDefender",
            source="reporting",
            distribution="public",
            module="",
            site="test",
            feed_url="http://test.com/",
            max_pages=2,
        ),
        base_feed.ReportFeedOptions(),
    )
    e = p.listing()
    assert len(e) == 2

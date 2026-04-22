"""Test suite for Morphisec blog feed."""

import datetime
import os.path

import respx

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.feeds import morphisec

HTML_RESPONSE = open(os.path.join(os.path.dirname(__file__), "test_morphisec.html"), "rb").read()


def test_get_entries():
    p = morphisec.MorphisecFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Morphisec",
            source="reporting",
            distribution="public",
            module="",
            site="test",
            feed_url="test",
            max_offset=45,
        ),
        base_feed.ReportFeedOptions(),
    )
    e = list(p.get_entries(HTML_RESPONSE))
    assert len(e) == 5
    assert e[0].title == "Security News in Review: Avaddon Ransomware Closes Down; CLOP Gang Members Arrested"
    assert (
        e[0].link
        == "https://blog.morphisec.com/security-news-in-review-avaddon-ransomware-closes-down-clop-gang-members-arrested"
    )
    assert e[0].published_parsed == datetime.datetime(2021, 6, 19, 0, 0, 0, tzinfo=datetime.timezone.utc).timetuple()


def test_listing(respx_mock: respx.MockRouter):
    respx_mock.get("http://test.com/").respond(200, content=HTML_RESPONSE)
    respx_mock.get("http://test.com/page/2").respond(200, content=HTML_RESPONSE)
    p = morphisec.MorphisecFeed(
        base_feed.ReportFeedOptions.Feed(
            publisher="Morphisec",
            source="reporting",
            distribution="public",
            module="",
            site="test",
            feed_url="http://test.com",
            max_pages=2,
        ),
        base_feed.ReportFeedOptions(),
    )
    e = p.listing()
    assert len(e) == 10

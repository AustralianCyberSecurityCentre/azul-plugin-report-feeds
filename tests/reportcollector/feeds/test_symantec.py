"""Test suite for Symantec blog feed."""

import datetime
import json
import os.path

import respx

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.feeds import symantec

JSON_RESPONSE = json.loads(open(os.path.join(os.path.dirname(__file__), "test_symantec_search.json"), "rb").read())


def test_get_entries():
    p = symantec.SymantecBlog(
        base_feed.ReportFeedOptions.Feed(
            publisher="Symantec",
            source="reporting",
            distribution="public",
            module="",
            site="",
            feed_url="https://test.com/",
        ),
        base_feed.ReportFeedOptions(),
    )
    e = list(p.get_entries(JSON_RESPONSE))
    assert len(e) == 1
    assert e[0].title == "Ransomware: Growing Number of Attackers Using Virtual Machines"
    assert e[0].link == "https://symantec-enterprise-blogs.security.com/blogs/blog-post/ransomware-virtual-machines"
    assert e[0].published_parsed == datetime.datetime(2021, 6, 23, 13, 0, 2, tzinfo=datetime.timezone.utc).timetuple()


def test_listing(respx_mock: respx.MockRouter):
    respx_mock.get("https://test.com/?foo=bar&rows=5&page=0").respond(200, json=JSON_RESPONSE)
    respx_mock.get("https://test.com/?foo=bar&rows=5&page=5").respond(200, json=JSON_RESPONSE)

    p = symantec.SymantecBlog(
        base_feed.ReportFeedOptions.Feed(
            publisher="Symantec",
            source="reporting",
            distribution="public",
            module="",
            site="test",
            feed_url="https://test.com/?foo=bar",
            max_pages=2,
        ),
        base_feed.ReportFeedOptions(),
    )
    e = p.listing()
    assert len(e) == 2

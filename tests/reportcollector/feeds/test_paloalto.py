"""Test suite for PaloAlto blog feed."""

import json
import os.path

import respx

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.feeds import paloalto

JSON_RESPONSE = open(os.path.join(os.path.dirname(__file__), "test_paloalto.json"), "rb").read()


def test_get_entries():
    p = paloalto.Unit42Feed(
        base_feed.ReportFeedOptions.Feed(
            publisher="PaloAlto",
            source="reporting",
            distribution="public",
            module="",
            site="test",
            feed_url="test",
            max_offset=45,
        ),
        base_feed.ReportFeedOptions(),
    )
    e = list(p.get_entries(json.loads(JSON_RESPONSE)))
    assert len(e) == 15
    assert (
        e[0].title
        == "Unit 42 Vulnerability Research Team Discovers 23 New Vulnerabilities February 2019 Disclosures - Adobe and Microsoft"
    )
    assert (
        e[0].link
        == "https://unit42.paloaltonetworks.com/unit-42-vulnerability-research-team-discovers-23-new-vulnerabilities-february-2019-disclosures-adobe-and-microsoft/"
    )
    assert e[0].published == "2019-02-22T20:00:52+00:00"


def test_listing(respx_mock: respx.MockRouter):
    respx_mock.get("http://test.com/admin-ajax.php?actions=news_infinite&data%5Boffset%5D=15").respond(
        200, content=JSON_RESPONSE
    )
    respx_mock.get("http://test.com/admin-ajax.php?actions=news_infinite&data%5Boffset%5D=0").respond(
        200, content=JSON_RESPONSE
    )

    p = paloalto.Unit42Feed(
        base_feed.ReportFeedOptions.Feed(
            publisher="PaloAlto",
            source="reporting",
            distribution="public",
            module="",
            site="test",
            feed_url="http://test.com/admin-ajax.php?actions=news_infinite",
            max_offset=15,
        ),
        base_feed.ReportFeedOptions(),
    )
    e = p.listing()
    assert len(e) == 30

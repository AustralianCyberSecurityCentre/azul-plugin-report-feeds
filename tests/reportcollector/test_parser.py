"""Test suite for parsers/converters."""

import os.path

from azul_plugin_report_feeds.reportcollector import parser

DATADIR = os.path.dirname(__file__)


def test_link_parser():
    """Tests the HTML Parser's ability to extract relevant linked pages."""
    testfile = os.path.join(DATADIR, "test_lookout_summary.html")
    p = parser.HTMLParser("https://blog.lookout.com/dark-caracal-mobile-apt", open(testfile, "rb").read())
    assert len(p.get_page_links(["download", "report"])) == 2


def test_html_parser_hashes():
    """Tests the HTML Parser's ability to parse hashes from different html reports."""
    testfile = os.path.join(DATADIR, "test_fireeye_nil.html")
    p = parser.HTMLParser("http://www.blah.com", open(testfile, "rb").read())
    h = p.get_indicators()
    assert not h

    testfile = os.path.join(DATADIR, "test_fireeye_nil2.html")
    p = parser.HTMLParser("http://www.blah.com", open(testfile, "rb").read())
    h = p.get_indicators()
    assert not h

    testfile = os.path.join(DATADIR, "test_fireeye_hashes.html")
    p = parser.HTMLParser("http://www.blah.com", open(testfile, "rb").read())
    h = p.get_indicators()
    assert len(h) == 2

    testfile = os.path.join(DATADIR, "test_malwarebytes_nil.html")
    p = parser.HTMLParser("http://www.blah.com", open(testfile, "rb").read())
    h = p.get_indicators()
    assert not h

    testfile = os.path.join(DATADIR, "test_malwarebytes_hashes.html")
    p = parser.HTMLParser("http://www.blah.com", open(testfile, "rb").read())
    h = p.get_indicators()
    assert len(h) == 5

    testfile = os.path.join(DATADIR, "test_microsoft_nil.html")
    p = parser.HTMLParser("http://www.blah.com", open(testfile, "rb").read())
    h = p.get_indicators()
    assert not h

    testfile = os.path.join(DATADIR, "test_microsoft_hashes.html")
    p = parser.HTMLParser("http://www.blah.com", open(testfile, "rb").read())
    h = p.get_indicators()
    assert len(h) == 4


def test_link_domain():
    assert parser.LinkSimilarity.domain("bitdefender.com") == "bitdefender.com"
    assert parser.LinkSimilarity.domain("labs.bitdefender.com") == "bitdefender.com"
    assert parser.LinkSimilarity.domain("pwc.co.uk") == "pwc.co.uk"
    assert parser.LinkSimilarity.domain("blogs.pwc.co.uk") == "pwc.co.uk"
    assert parser.LinkSimilarity.domain("avast.io") == "avast.io"
    assert parser.LinkSimilarity.domain("decoded.avast.io") == "avast.io"
    assert parser.LinkSimilarity.domain("us-cert.cisa.gov") == "cisa.gov"
    assert parser.LinkSimilarity.domain("www.BitDefender.com") == "bitdefender.com"


def test_link_words():
    assert parser.LinkSimilarity.words("/2021/06/catching-apt-lollipop.pdf") == {"catching", "lollipop", "2021", "06"}

    assert parser.LinkSimilarity.words("/blog/necurs%20disrupts%20banking/iocs.csv") == {
        "necurs",
        "disrupts",
        "banking",
        "iocs",
        "csv",
    }


def test_link_similarity():
    link = parser.LinkSimilarity("https://blog.foobar.com/2021/06/foobar-finds-lollipop-group-in-multiple-countries")
    assert not link.compare("http://www.nato.org/something/else.html")
    assert not link.compare("http://www.nato.org/something/lollipop.pdf")
    assert link.compare("http://www.foobar.com/something/lollipop-en.pdf")
    assert link.compare("http://www.foobar.com/apt/reports/lol-iocs.pdf", goodwords=["iocs"])
    assert not link.compare(
        "http://www.foobar.com/2021/06/reports/foobar-annual-report.pdf", badwords=["annual", "quarterly"]
    )

    # no word list to compare
    link = parser.LinkSimilarity("https://blog.foobar.com/")
    assert not link.compare("https://blog.foobar.com/something/something")
    link = parser.LinkSimilarity("https://blog.foobar.com/something/something")
    assert not link.compare("https://blog.foobar.com/")

    # problematic real example
    link = parser.LinkSimilarity(
        "https://labs.bitdefender.com/2021/04/new-nebulae-backdoor-linked-with-the-naikon-group/"
    )
    assert link.compare(
        "https://www.bitdefender.com/files/News/CaseStudies/study/396/Bitdefender-PR-Whitepaper-NAIKON-creat5397-en-EN.pdf"
    )


def test_parser_links():
    testfile = os.path.join(DATADIR, "test_lookout_download_report.html")
    p = parser.HTMLParser("http://blog.lookout.com/2018/dark-caracal", open(testfile, "rb").read())
    assert p.get_pdf_links() == [
        "https://info.lookout.com/rs/051-ESQ-475/images/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf"
    ]

    testfile = os.path.join(DATADIR, "test_missed_pdf_link.html")
    p = parser.HTMLParser(
        "https://labs.bitdefender.com/2021/04/new-nebulae-backdoor-linked-with-the-naikon-group/",
        open(testfile, "rb").read(),
    )
    assert p.get_pdf_links(badwords=["quarterly", "annual"]) == [
        "https://www.bitdefender.com/files/News/CaseStudies/study/396/Bitdefender-PR-Whitepaper-NAIKON-creat5397-en-EN.pdf"
    ]

    testfile = os.path.join(DATADIR, "test_clearsky_missing_links.html")
    p = parser.HTMLParser(
        "https://www.clearskysec.com/cryptocore-lazarus-attribution/",
        open(testfile, "rb").read(),
    )
    assert p.get_pdf_links(badwords=["quarterly", "annual"]) == [
        "https://www.clearskysec.com/wp-content/uploads/2021/05/CryptoCore-Lazarus-Clearsky.pdf"
    ]

    testfile = os.path.join(DATADIR, "test_github_links.html")
    p = parser.HTMLParser(
        "https://decoded.avast.io/luigicamastra/apt-group-targeting-governmental-agencies-in-east-asia/",
        open(testfile, "rb").read(),
    )
    assert p.get_page_links(["ioc", "report", "download", "github.com"]) == [
        "https://github.com/avast/ioc/tree/master/LuckyMouse",
        "https://github.com/avast/ioc/blob/master/LuckyMouse/samples.sha256",
    ]

    testfile = os.path.join(DATADIR, "test_fireeye_product_links.html")
    p = parser.HTMLParser(
        "https://www.fireeye.com/blog/threat-research/2020/11/critical-buffer-overflow-vulnerability-in-solaris-can-allow-remote-takeover.html",
        open(testfile, "rb").read(),
    )
    assert p.get_page_links(["ioc", "report", "download", "github.com"]) == []

"""Contains classes for parsing and converting different file formats."""

import hashlib
import logging
import re
import subprocess  # noqa: S404 # nosec B404
import tempfile
from abc import ABC, abstractmethod
from typing import Iterator
from urllib.parse import urlparse

import bs4
from playwright.sync_api import sync_playwright

from azul_plugin_report_feeds.reportcollector.base_feed import ReportFeedOptions
from azul_plugin_report_feeds.reportcollector.models import Indicator

logger = logging.getLogger("reportcollector")

EMPTY_HASHES = [
    hashlib.md5(b"").hexdigest(),  # noqa: S324
    hashlib.sha1(b"").hexdigest(),  # noqa: S324
    hashlib.sha256(b"").hexdigest(),
]

MAX_LOG_LEN = 500


class BaseHTML2PDFFeed(ABC):
    """Base class for all HTML to PDF converters."""

    def __init__(self, options: ReportFeedOptions):
        self.options = options

    @abstractmethod
    def convert(self, url: str) -> bytes:
        """Download from provided URL and convert the site to a PDF returning the raw bytes."""
        ...


class HTML2PDFPlaywright(BaseHTML2PDFFeed):
    """Playwright based HTML to PDF converter."""

    def __init__(self, options: ReportFeedOptions):
        """Create a new Playwright pdf converter."""
        super().__init__(options)

    def convert(self, url: str) -> bytes:
        """Convert the provided URL to a PDF."""
        logger.info("Converting Online HTML to PDF for URL: %s", url)
        return self._inner_convert(url=url)

    def convert_raw_html(self, raw_html: str) -> bytes:
        """Convert the provided raw HTML to a PDF."""
        logger.info("Converting Raw HTML to PDF")
        if not raw_html:
            raise ValueError("No raw html provided for version into a pdf.")
        return self._inner_convert(raw_html=raw_html)

    def _inner_convert(self, url: str = "", raw_html: str = "") -> bytes:
        """Convert the provided URL to a PDF."""
        return_val = b""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            # Directly convert html or use a browser to achieve the same thing.
            if raw_html:
                page.set_content(raw_html)
            else:
                page.goto(url, wait_until=self.options.playwright_loading.value)
            return_val = page.pdf(
                format="A4",
                print_background=True,
            )
            browser.close()
        if not return_val:
            return b""
        return return_val


class PDF2TXT:
    """Text extractor for PDF Documents."""

    def convert(self, pdf):
        """Convert the supplied pdf content to text str."""
        logger.info("Extracting text from PDF...")
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(pdf)
            tmp.flush()
            p = subprocess.Popen(  # noqa: S603
                ["pdftotext", tmp.name, "-"],  # noqa: S607
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = p.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                logger.warning(stderr.decode("utf-8")[:MAX_LOG_LEN])
                return stdout.decode("utf-8")


class LinkSimilarity:
    """Compare URLs to determine if related topic."""

    CommonWords = [
        "the",
        "a",
        "is",
        "with",
        "to",
        "apt",
        "cybercrime",
        "threat",
        "new",
        "news",
        "group",
        "pdf",
        "html",
        "blog",
        "report",
        "www",
        "en",
        "us",
    ]

    def __init__(self, url: str):
        """Create a new comparison against the supplied url."""
        u = urlparse(url)
        self.url = url
        self.host = u.hostname
        self.path = u.path
        self.current_domain = LinkSimilarity.domain(self.host)
        self.current_words = LinkSimilarity.words(self.path)

    def compare(self, url, goodwords: list[str] | None = None, badwords: list[str] | None = None) -> float:
        """Return a percentage of how similar the url is.

        0.0 is nothing in common 1.0 being semantically the same.
        Optional goodwords list, when encountered will mark as 1.0.
        Optional badwords list, when encounter will mark as 0.0.
        """
        if not goodwords:
            goodwords = []
        if not badwords:
            badwords = []
        u = urlparse(url)
        if u.hostname:
            domain = LinkSimilarity.domain(u.hostname)
        else:
            # relative link?
            domain = self.current_domain
        words = LinkSimilarity.words(u.path)
        if words.intersection(set(goodwords)):
            return 1.0
        if words.intersection(set(badwords)):
            return 0.0
        # need to be from same site
        if domain not in self.current_domain and self.current_domain not in domain:
            return 0.0
        # origin url has no interesting words in path
        if not self.current_words:
            return 0.0
        matched = words.intersection(self.current_words)
        if not matched:
            return 0.0
        return float(len(matched)) / min(len(words), len(self.current_words))

    @staticmethod
    def domain(domain: str) -> str:
        """Return the domain name of a host or subdomain.

        i.e. The portion that would be registered to an entity.
        """
        # not strictly accurate but should be good enough for purpose
        parts = domain.lower().split(".")
        if len(parts) <= 2:
            return domain.lower()

        if len(parts[-1]) == 2 and parts[-1] not in ("io", "tv"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def words(path: str) -> set[str]:
        """Return set of words extracted from url path str."""
        w = {x for x in re.split(r"-|_|\.|,|\%\d{2}| |/|\(|\)|=|\+", path.lower()) if x}
        w.difference_update(LinkSimilarity.CommonWords)
        return w


class HTMLParser:
    """HTML document parser/extractor."""

    def __init__(self, url, html):
        """Create a HTML Parser for the supplied URL and content."""
        self.bs = bs4.BeautifulSoup(html, "lxml")
        self.url = url
        self.html = html
        self.link = LinkSimilarity(url)
        # strip script and meta tags (can contain hashes/etc.)
        if self.bs.meta:
            self.bs.meta.decompose()
        if self.bs.script:
            self.bs.script.decompose()

    def get_text(self) -> str:
        """Return the textual content as a str, for the current html document."""
        logger.info("Extracting text from HTML...")
        # scan html content for hashes
        try:
            # if using get_text it will strip all formatting including <br/>
            # which can run hashes into each other on same sites/pages, so
            # ensure we give a whitespace separator to join with...
            return self.bs.body.get_text("\n")
        except AttributeError:
            return ""

    def get_pdf_links(self, badwords: list[str] | None = None) -> list[str]:
        """Return a list of 'related' pdf urls embedded in the document."""
        logger.info("Scanning for PDF Links...")
        # try and find a linked pdf report
        links: list[str] = [
            str(x["href"])
            for x in self.bs.find_all("a")
            if x.get("href")
            and x["href"].lower().endswith(".pdf")
            and self.link.compare(x["href"], badwords=badwords or [])
        ]
        return links

    def get_page_links(self, keywords: list[str], badwords: list[str] | None = None) -> list[str]:
        """Return a list of 'related' urls, containing keywords, in the document."""
        logger.info("Scanning for page links with keywords: %s", str(keywords))
        links = [
            str(x["href"])
            for x in self.bs.find_all("a")
            if x.get("href")
            and any([k in x.get_text().lower() for k in keywords])
            and self.link.compare(x["href"], keywords, badwords or [])
        ]
        return links

    def get_indicators(self) -> list[Indicator]:
        """Return a list of indicator dicts extracted from html text."""
        h = HashFinder()
        hashes = set(h.find(self.get_text()))
        # FUTURE: we can potentially use heuristics based on html table info in page
        # to match hashes/filenames/network indicators sanely

        # Map from output of the hash finder to an Indicator field name.
        mappings = {
            "sha256": "sha256",
            "sha1": "sha1",
            "md5": "md5",
        }
        result = []
        for x in hashes:
            i = Indicator()
            setattr(i, mappings[x[0]], x[1])
            result.append(i)
        return result


class HashFinder:
    """Pattern matching for file hashes."""

    # let other chars run into the hash as some pdf table extraction
    # can result in badly formatted output
    template_lower = "(?:^|[^a-f0-9])([a-f0-9]{{{0}}})[^a-f0-9]"
    template_upper = template_lower.upper()
    hash_lengths = dict(md5=32, sha1=40, sha256=64)

    def find(self, text: str) -> Iterator[tuple[str, str]]:
        """Return tuples of (type, hash) for any found file hashes in text."""
        logger.info("Searching for file hashes in text content...")
        # hash len
        for h, i in HashFinder.hash_lengths.items():
            for template in [HashFinder.template_lower, HashFinder.template_upper]:
                off = 0
                while off < len(text):
                    m = re.search(template.format(i), text[off:])
                    if not m:
                        break
                    off = off + m.end() - 1
                    val = m.group(1).lower()
                    # skip bad hashes
                    if val in EMPTY_HASHES:
                        continue
                    if len(val) == 64 and val.startswith("0000000"):
                        # statistically unlikely and more likely a blockchain hash
                        continue
                    if len(set(val)) < 5:
                        # statistically unlikely, some repeated char string
                        continue
                    yield h, val

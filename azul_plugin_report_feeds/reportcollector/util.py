"""Shared utility functions for reportcollector modules."""

import os
import os.path
import subprocess
from datetime import datetime
from pathlib import Path
from typing import AsyncIterable, Iterable  # noqa: S404 # nosec B404

import httpx
import pendulum
from pendulum import Date, DateTime, Duration, Time, parse

USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
ACCEPT_HEADER = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
ACCEPT_LANG_HEADER = "en-US,en;q=0.5"

# Enable cookies across requests, etc.
client = httpx.Client(timeout=30)


def request_url(url: str, referer: str | None = None) -> httpx.Response:
    """Request GET with overridden common header to look more like a browser."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": ACCEPT_HEADER,
        "Accept-Language": ACCEPT_LANG_HEADER,
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        headers["Referer"] = referer

    # guess at protocol
    if url.startswith("//"):
        url = "http:" + url
    r = client.get(url, headers=headers, follow_redirects=True)
    r.raise_for_status()
    return r


def post_url(
    url: str,
    data: str | bytes | Iterable[bytes] | AsyncIterable[bytes] | None,
    referer: str | None = None,
    override_headers: dict[str, str] | None = None,
):
    """Perform POST with overriden common header to look more like a browser."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": ACCEPT_HEADER,
        "Accept-Language": ACCEPT_LANG_HEADER,
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        headers["Referer"] = referer
    if override_headers:
        headers.update(override_headers)

    r = client.post(url, content=data, headers=headers)
    r.raise_for_status()
    return r


def mirror(url, outdir, recursive=True, referer=None):
    """Mirror the site/page at url to the output dir."""
    try:
        os.mkdir(outdir)
    except OSError:
        if not os.path.exists(outdir):
            raise

    command = [
        "wget",
        "-E",
        "-nH",
        "-k",
        "-K",
        "-N",
        "-p",
        "-P",
        outdir,
        "-e",
        "robots=off",
        "--user-agent",
        USER_AGENT,
        "--header",
        "Accept-Language: %s" % ACCEPT_LANG_HEADER,
        "--header",
        "Accept: %s" % ACCEPT_HEADER,
        "--timeout",
        "10",
    ]
    if referer:
        command += ["--referer", referer]
    if recursive:
        command += ["--recursive", "--level", "5"]
    command.append(url)
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # noqa: S603 # noqa: S603
    _, stderr = p.communicate()
    if p.returncode:
        raise Exception("Failed to mirror using wget.\n%s", stderr)


class ReportState:
    """ReportState.

    An abstraction around getting and setting state for feeds.
    """

    def __init__(self, state_directory: str) -> None:
        """Class used to check, get and update report state.

        @param state_directory: path/to/state_dir. Will be made if not found.
        Will not make parent directories.
        """
        self.state_dir = Path(state_directory)
        try:
            if not self.state_dir.exists():
                self.state_dir.mkdir()
        except OSError as e:
            if not self.state_dir.exists():
                raise Exception(f"Unable to create {state_directory=}") from e

    def checkForFeedLastTimestamp(self, feed_publisher: str) -> None | DateTime:
        """Given a feed publisher, check for last timestamp.

        @param feed_publisher: The publishers to check for a timestamp for.
        """
        state_file = self.state_dir.joinpath(feed_publisher)
        last_timestamp = None
        if state_file.exists():
            if state_file.is_file() and not state_file.is_symlink():
                with state_file.open() as state:
                    raw_timestamp = state.read().strip()
                    last_timestamp = parse(raw_timestamp, tz=pendulum.UTC)

                    # Validate found data
                    match last_timestamp:
                        case DateTime():
                            pass  # No conversions needed, just hand it back
                        case Date():
                            last_timestamp = DateTime(last_timestamp.year, last_timestamp.month, last_timestamp.day)
                        case Time():
                            last_timestamp = None
                        case Duration():
                            last_timestamp = None

        return last_timestamp

    def setFeedLastTimestamp(self, feed_publisher: str, timestamp: DateTime | datetime):
        """Save latest timestamp for a feed.

        @param feed_publisher: The publisher to set timestamp of.
        @param timestamp: The time stamp that it will be set to.

        throws OSError or child of on failure to write state file.
        """
        state_file = self.state_dir.joinpath(feed_publisher)
        newest_timestamp = pendulum.instance(timestamp, tz=pendulum.UTC)

        with state_file.open("w") as state:
            state.write(newest_timestamp.to_iso8601_string())

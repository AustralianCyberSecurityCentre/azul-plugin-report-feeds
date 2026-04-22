"""Models defining the return value of reportfeeds."""

import re
from datetime import datetime, timezone
from typing import Annotated, Iterator

from pydantic import AfterValidator, BaseModel


class Indicator(BaseModel):
    """Indicators from the given report feed."""

    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    file_size: int | None = None
    filename: str | None = None
    malware_family: str | None = None
    ssdeep: str | None = None

    def assign_hashes(self, values: list[str]):
        """Assign a hash of type md5, sha1 or sha256 to the appropriate internal value."""
        for hash in values:
            if re.match(r"^[a-fA-F0-9]{64}$", hash):  # Sha256
                self.sha256 = hash
            if re.match(r"^[a-fA-F0-9]{40}$", hash):  # Sha1
                self.sha1 = hash
            if re.match(r"^[a-fA-F0-9]{32}$", hash):  # Md5
                self.md5 = hash

    def has_at_least_one_hash(self) -> bool:
        """Return true if the indicator contains at least one hash."""
        if self.md5 or self.sha1 or self.sha256:
            return True
        return False

    def hashes_iter(self) -> Iterator[str]:
        """Return all the hashes in this indicator as a generator."""
        if self.md5:
            yield self.md5
        if self.sha1:
            yield self.sha1
        if self.sha256:
            yield self.sha256


class GeneralIndicator(BaseModel):
    """General indicator associated with a report that applies to all associated files."""

    type: str
    text: str
    additional_text: str


class ReportResult(BaseModel):
    """Model to hold the potential results from any report feed."""

    # Report publisher - e.g Avast, Dell, FireEye Fortinet...
    publisher: str | None = None
    # Distribution allowed by source
    distribution: str = "public"
    topic: str | None = None  # Currently redundant as topic == source == "reporting"
    site: str | None = None  # Url to the website the data came from
    url: str | None = None  # Path to the downloaded content.
    title: str | None = None  # Name of the report or content
    slug: str | None = None  # A slugified version of the title.
    timestamp: Annotated[datetime | None, AfterValidator(lambda d: d.astimezone(timezone.utc) if d else None)] = (
        None  # An isoformat of the timestamp when the report was created.
    )
    report_id: str | None = None  # Unique identifier for the report if the publisher has one.
    report_type: str | None = None  # Type of report
    report: bytes | None = None  # Raw report as bytes.
    indicators: list[Indicator] = []
    general_indicators: list[GeneralIndicator] = []
    description: str | None = None  # Executive summary of the report.
    # Raw malware content from the feed.
    files: list[bytes] = []
    _report_path: str | None = None  # Intermediate value used to get other information.

    def deduplicate_indicators(self):
        """Merge all the common indicators into singular objects.

        Useful when you have lots of different information under the same sha256 in different indicators.
        """
        new_indicators = []
        while len(self.indicators) > 0:
            indicator = self.indicators.pop()
            common_indexes = []
            for idx, old_indicator in enumerate(self.indicators):
                if (
                    # Check if any hashes are set to a value and are equal
                    old_indicator.md5 == indicator.md5
                    and indicator.md5
                    or old_indicator.sha1 == indicator.sha1
                    and indicator.sha1
                    or old_indicator.sha256 == indicator.sha256
                    and indicator.sha256
                ):
                    common_indexes.append(idx)

            common_indicators: list[Indicator] = []
            # Pop all the common indicators
            for idx in reversed(common_indexes):
                common_indicators.append(self.indicators.pop(idx))

            # if there are common indicators merge them all

            if common_indicators:
                new_indicator_dict = indicator.model_dump()
                for com_cur_i in common_indicators:
                    new_indicator_dict.update(com_cur_i.model_dump(exclude_none=True, exclude_defaults=True))

                indicator = Indicator.model_validate(new_indicator_dict)

            new_indicators.append(indicator)
        self.indicators = new_indicators

    def get_indicator_by_sha256(self, sha256: str) -> Indicator | None:
        """Get an indicator by it's sha256 if it exists."""
        for ind in self.indicators:
            if ind.sha256 == sha256:
                return ind
        return None

    def indicators_hashes_iter(self) -> Iterator[str]:
        """Get all hashes that are in all the indicators in the ReportResult."""
        for i in self.indicators:
            for hash in i.hashes_iter():
                yield hash

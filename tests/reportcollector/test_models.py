"""Tests for reportcollector models."""

from azul_plugin_report_feeds.reportcollector.models import Indicator, ReportResult


def test_indicator():
    """Tests that the indicator Model's functions all work as expected."""
    garbage = "sdfjsd"
    garbage2 = "123a"
    sha256 = "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b"
    sha1 = "b87a9c07252fc25ed710a50adcce35697058fda5"
    md5 = "64524d6c56a8c910f19c11f73e8251b6"
    generic_indicator = Indicator()
    generic_indicator.assign_hashes([sha256])
    assert generic_indicator.sha256 == sha256
    assert list(generic_indicator.hashes_iter()) == [sha256]
    assert generic_indicator.md5 is None
    assert generic_indicator.sha1 is None
    generic_indicator.assign_hashes([sha1])
    assert generic_indicator.sha1 == sha1
    generic_indicator.assign_hashes([md5])
    assert generic_indicator.md5 == md5
    assert generic_indicator.has_at_least_one_hash() == True
    generic_indicator = Indicator()
    generic_indicator.assign_hashes([garbage])
    assert generic_indicator.has_at_least_one_hash() == False
    assert generic_indicator.md5 is None
    assert generic_indicator.sha1 is None
    assert generic_indicator.sha256 is None
    generic_indicator = Indicator()
    generic_indicator.assign_hashes([garbage, sha256, sha1, md5, garbage2])
    assert generic_indicator.has_at_least_one_hash() == True
    assert generic_indicator.sha256 == sha256
    assert generic_indicator.sha1 == sha1
    assert generic_indicator.md5 == md5
    assert sorted(list(generic_indicator.hashes_iter())) == sorted([sha256, sha1, md5])


def test_deduplicate_report():
    """Test indicators can be de-duplicated."""
    garbage = "sdfjsd"
    garbage2 = "123a"

    sha256 = "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b"
    sha1 = "187a9c07252fc25ed710a50adcce35697058fda5"
    md5 = "14524d6c56a8c910f19c11f73e8251b6"
    fname1 = "name1"

    sha256_2 = "2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b"
    sha1_2 = "287a9c07252fc25ed710a50adcce35697058fda5"
    md5_2 = "24524d6c56a8c910f19c11f73e8251b6"
    fname2 = "name2"
    malware_family_2 = "Lonely"

    md5_3 = "34524d6c56a8c910f19c11f73e8251b6"
    ref_3 = Indicator(md5=md5_3)
    report = ReportResult(
        indicators=[
            Indicator(sha256=sha256, md5=md5),
            Indicator(sha256=sha256, sha1=sha1, filename=fname1),
            Indicator(sha256=sha256_2, filename=fname2, sha1=sha1_2, md5=md5_2),
            Indicator(sha256=sha256_2, malware_family=malware_family_2),
            ref_3,
        ]
    )
    # Pre-merge assertion
    assert (
        report.get_indicator_by_sha256(sha256_2).model_dump()
        == Indicator(sha256=sha256_2, filename=fname2, sha1=sha1_2, md5=md5_2).model_dump()
    )
    assert report.get_indicator_by_sha256(sha256).model_dump() == Indicator(sha256=sha256, md5=md5).model_dump()
    assert len(report.indicators) == 5

    # MERGING
    report.deduplicate_indicators()

    # after indicators are merged
    assert len(report.indicators) == 3
    assert (
        report.get_indicator_by_sha256(sha256_2).model_dump()
        == Indicator(
            sha256=sha256_2, filename=fname2, sha1=sha1_2, md5=md5_2, malware_family=malware_family_2
        ).model_dump()
    )
    assert (
        report.get_indicator_by_sha256(sha256).model_dump()
        == Indicator(sha256=sha256, sha1=sha1, md5=md5, filename=fname1).model_dump()
    )

    assert ref_3 in report.indicators

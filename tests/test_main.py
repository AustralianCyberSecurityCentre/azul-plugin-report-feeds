import copy
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import deepdiff
import pendulum
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from azul_runner import DataLabel
from azul_runner import settings as azr_settings
from pydantic import BaseModel

from azul_plugin_report_feeds.main import AzulPluginReportFeeds
from azul_plugin_report_feeds.main import main as azul_plugin_report_feeds_main_method
from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.base_feed import (
    ReportFeedOptions,
)
from azul_plugin_report_feeds.reportcollector.feeds import rss
from azul_plugin_report_feeds.reportcollector.models import Indicator, ReportResult

TIME_NOW = pendulum.datetime(2024, 4, 1, 1, 1, 1, 1, pendulum.UTC)
REPORT_TIMESTAMP = pendulum.datetime(2023, 2, 1, 1, 1, 1, 1, pendulum.UTC)


def get_indicators_full_1() -> Indicator:
    sha256 = "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b"
    sha1 = "187a9c07252fc25ed710a50adcce35697058fda5"
    md5 = "14524d6c56a8c910f19c11f73e8251b6"
    filename = "fname1"
    file_size = 200
    malware_family = "my-family-1"
    ssdeep = "168:5YGbu72mrwBZBs6tqQc5Xi/6DlemQKuIIx6siUI7EQE3PH+yT:5YGbsdwvBTaXi/q0vKuIIUSIaNT"
    return Indicator(
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        filename=filename,
        file_size=file_size,
        malware_family=malware_family,
        ssdeep=ssdeep,
    )


def get_indicators_full_2() -> Indicator:
    sha256 = "2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b"
    sha1 = "287a9c07252fc25ed710a50adcce35697058fda5"
    md5 = "24524d6c56a8c910f19c11f73e8251b6"
    filename = "fname2"
    file_size = 300
    malware_family = "my-family-2"
    ssdeep = "268:5YGbu72mrwBZBs6tqQc5Xi/6DlemQKuIIx6siUI7EQE3PH+yT:5YGbsdwvBTaXi/q0vKuIIUSIaNT"
    return Indicator(
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        filename=filename,
        file_size=file_size,
        malware_family=malware_family,
        ssdeep=ssdeep,
    )


def get_report_1() -> ReportResult:
    return ReportResult(
        publisher="publisher1",
        distribution="public",
        topic="reporting",
        site="https://www.not.real.com/security",
        url="https://www.not.real.com/security/blog/1",
        title="awesome title",
        slug="awesome-title",
        timestamp=copy.deepcopy(REPORT_TIMESTAMP),
        report_id="report_id_abc",
        report_type="good-type-of-report",
        report=b"%PDFlets-pretend-to-be-a-pdf",
        indicators=[],
        description="Report 1's high level summary.",
        files=[b"pretend-malware-to-upload-yay", b"second-piece-of-pretend-malware-to-upload-spicy"],
        _report_path="Should/have/no/effect/on/tests",
    )


def get_report_1_with_indicators() -> ReportResult:
    report = get_report_1()
    report.indicators = [get_indicators_full_1(), get_indicators_full_2()]
    return report


def get_fake_file_info() -> azm.Datastream:
    return azm.Datastream(
        identify_version=1,
        label=DataLabel.REPORT,
        size=216000,
        sha512="b1e954ddb850127128c04a39e9b21783732a2741c47392e550615ec0d1f72a944b5fbbfad2981838ee37ab25f4fa0feef75d9825c5a737647960ddf2f2b5151b",
        sha256="dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
        sha1="8d332d49e436df0a69f0453596b11007b781307b",
        md5="f54038c08570488430deb8594535ed60",
        mime="pdf",
        magic="PDF but not real magic",
        file_format="document/pdf",
    )


def mock_pendulum_now(*args, **kwargs):
    """A fake version of now to ensure datetime is consistent for tests."""
    return TIME_NOW


class BaseTest(unittest.TestCase):
    def create_plugin_from_config(self, in_cfg: dict = None):
        if not in_cfg:
            in_cfg = {}
        config = azr_settings.parse_config(AzulPluginReportFeeds, in_cfg)
        self.plugin = AzulPluginReportFeeds(config)

    def compare_pydantic_model_to_dict(self, model: BaseModel, expected: dict):
        """Compare pydantic models and if there is a difference print it."""
        model_as_dict = json.loads(model.model_dump_json(exclude_defaults=True))
        diff = deepdiff.DeepDiff(model_as_dict, expected)
        if diff:
            print("Difference between the two models is: \n")
            print(diff)
            print("---------------------------------------------------------------\n\n")
        print("Actual model value is: ")
        print(model_as_dict)
        print("---------------------------------------------------------------\n")
        self.assertEqual(model_as_dict, expected)


@mock.patch("pendulum.now", mock_pendulum_now)
@mock.patch.object(dispatcher.DispatcherAPI, "submit_events")
class BasicTests(BaseTest):
    FEED_CONFIG_KEY: str = "REPORT_FEED_FEEDS_CONFIG"

    def setUp(self):
        self.known_publisher = "Microsoft"
        self._original_feed_config = os.environ.get(self.FEED_CONFIG_KEY, None)
        self.indicator_1_full = get_indicators_full_1()
        self.indicator_2_full = get_indicators_full_2()
        self.report_1_full = get_report_1()
        self.report_1_full_with_indicators = get_report_1_with_indicators()
        self.create_plugin_from_config()

    def dump_feed_config(self, feed_config: list[ReportFeedOptions.Feed]):
        json_dumped_config = []
        for elem in feed_config:
            json_dumped_config.append(elem.model_dump())
        os.environ[self.FEED_CONFIG_KEY] = json.dumps(json_dumped_config)

    def change_feed_to_config_1(self):
        feed_config = [
            ReportFeedOptions.Feed(
                publisher="Microsoft",
                source="reporting",
                module="reportcollector.feeds.rss.RSSFeed",
                distribution="public",
                site="https=//www.microsoft.com/security/",
                feed_url="https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
            )
        ]
        self.dump_feed_config(feed_config)

    def change_feed_to_config_2(self):
        feed_config = [
            ReportFeedOptions.Feed(
                publisher="Microsoft",
                source="reporting",
                module="reportcollector.feeds.rss.RSSFeed",
                distribution="public",
                site="https://www.microsoft.com/security/",
                feed_url="https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
            ),
            ReportFeedOptions.Feed(
                publisher="NotMicrosoft",
                source="reporting",
                module="reportcollector.feeds.rss.RSSFeed",
                distribution="public",
                site="https://www.microsoft.com/security/",
                feed_url="https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
            ),
            ReportFeedOptions.Feed(
                publisher="AlsoNotMicrosoft",
                source="reporting",
                module="reportcollector.feeds.rss.RSSFeed",
                distribution="public",
                site="https://www.microsoft.com/security/",
                feed_url="https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
            ),
        ]
        self.dump_feed_config(feed_config)

    def tearDown(self):
        if self._original_feed_config:
            os.environ[self.FEED_CONFIG_KEY] = self._original_feed_config

    def test_main_loads_config(self, mock_submit_events: mock.MagicMock):
        """when main is called plugin is correctly configured and run_once is called ( don't let it run)"""
        plugin_report_feed_instance: AzulPluginReportFeeds = None

        def mock_run_once(self, *args, **kwargs):
            nonlocal plugin_report_feed_instance
            plugin_report_feed_instance = self

        with mock.patch.object(AzulPluginReportFeeds, "run_once", side_effect=mock_run_once, autospec=True) as m:
            # Drop any input arguments that the test agent adds (tox/vscode testing)
            sys.argv = [sys.argv[0]]
            azul_plugin_report_feeds_main_method()
            m.assert_called()

        self.assertIsNotNone(plugin_report_feed_instance)
        dumped = plugin_report_feed_instance.cfg.model_dump()
        print(dumped)
        expected = {
            "max_downloads_per_report": 100,
            # "feed_config_path": "<PATH>/reportfeeds.yaml", # Ignore because it's environment dependent
            # "state_directory": ".reportfeeds", # Ignore because it's environment dependent
            "prometheus_push_gateway": "",
            "feed_source_name": "reporting",
            "feed_security": "OFFICIAL",
            "namespace_suffix": "",
        }
        for key, value in expected.items():
            self.assertEqual(dumped.get(key), value)

        """use run_once to iterate over a feed list and verify each feed has fetched called with the appropriate args."""
        self.change_feed_to_config_1()
        with tempfile.TemporaryDirectory() as temp_dir:
            self.create_plugin_from_config({"state_directory": temp_dir})
            with mock.patch.object(rss.RSSFeed, "fetch", return_value=[self.report_1_full_with_indicators]) as m:

                def fake_process_report(*args, **kwargs):
                    """Method to prevent calling process report"""
                    return ([], [], [])

                self.plugin.process_report = fake_process_report
                self.plugin.run_once()
                m.assert_called_once()
                # State directory is empty so shouldn't have a value for last_fetch
                self.assertEqual(m.call_args[1]["last_fetch"], None)
                self.plugin.run_once()
                # Should load state this time.
                self.assertEqual(m.call_args[1]["last_fetch"], REPORT_TIMESTAMP)

            # Re test to ensure fetch is called 3 times for a feed config with 3 feeds.
            self.change_feed_to_config_2()
            self.create_plugin_from_config({"state_directory": temp_dir})
            with mock.patch.object(rss.RSSFeed, "fetch", return_value=[self.report_1_full_with_indicators]) as m:

                def fake_process_report(*args, **kwargs):
                    """Method to prevent calling process report"""
                    return ([], [], [])

                self.plugin.process_report = fake_process_report
                self.plugin.run_once()
                self.assertEqual(m.call_count, 3)
                # State directory populated from last run.
                self.assertEqual(m.call_args_list[0][1]["last_fetch"], REPORT_TIMESTAMP)
                # Both New feed won't have state so won't load it
                self.assertEqual(m.call_args_list[1][1]["last_fetch"], None)
                self.assertEqual(m.call_args_list[2][1]["last_fetch"], None)
                m.reset_mock()
                self.plugin.run_once()
                # All publishers have been queried so state should be loaded for each one.
                self.assertEqual(m.call_args_list[0][1]["last_fetch"], REPORT_TIMESTAMP)
                self.assertEqual(m.call_args_list[1][1]["last_fetch"], REPORT_TIMESTAMP)
                self.assertEqual(m.call_args_list[2][1]["last_fetch"], REPORT_TIMESTAMP)

    def test_fetch_fails(self, mock_submit_events: mock.MagicMock):
        """Ensure no error is raised when fetch errors."""
        # use run_once to iterate over a feed list and verify each feed has fetch called with the appropriate args.
        self.change_feed_to_config_1()

        class TestException(Exception):
            pass

        def raise_except(*args, **kwargs):
            raise TestException()

        with tempfile.TemporaryDirectory() as temp_dir:
            self.create_plugin_from_config({"state_directory": temp_dir})
            with mock.patch.object(rss.RSSFeed, "fetch") as m:
                m.side_effect = raise_except

                def fake_process_report(*args, **kwargs):
                    """Method to prevent calling process report"""
                    return ([], [], [])

                self.plugin.process_report = fake_process_report
                self.plugin.run_once()

    def test_gen_download_event(self, mock_submit_events: mock.MagicMock):
        """Event generation is working as expected."""
        report = self.plugin._gen_download_event(
            self.report_1_full_with_indicators,
            self.indicator_1_full,
            {"publisher": self.report_1_full_with_indicators.publisher},
        )
        self.compare_pydantic_model_to_dict(
            report,
            {
                "kafka_key": "download-1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                "action": "requested",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {"publisher": "publisher1"},
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "hash": "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                    "pcap": True,
                    "category": "awesome-title",
                    "category_quota": 100,
                },
            },
        )

    def test_gen_input_event(self, mock_submit_events: mock.MagicMock):
        """Event generation is working as expected."""
        entity = azm.BinaryEvent.Entity(sha256="custom-entity-id")
        refs = {"ref1": "val1", "ref2": "ref2_val"}
        input_event_1 = self.plugin._gen_input_event(
            self.known_publisher, entity, refs, azm.BinaryAction.Mapped, "file1"
        )
        self.compare_pydantic_model_to_dict(
            input_event_1,
            {
                "model_version": azm.CURRENT_MODEL_VERSION,
                "kafka_key": "reportfeed-placeholder",
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "author": {"category": "plugin", "name": "ReportFeeds-Microsoft", "version": "2025.11.18"},
                "entity": {"sha256": "custom-entity-id"},
                "action": "mapped",
                "source": {
                    "security": "OFFICIAL",
                    "name": "reporting",
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "references": {"ref1": "val1", "ref2": "ref2_val"},
                    "path": [
                        {
                            "sha256": "custom-entity-id",
                            "action": "mapped",
                            "timestamp": "2024-04-01T01:01:01.000001+00:00",
                            "author": {"category": "plugin", "name": "ReportFeeds-Microsoft", "version": "2025.11.18"},
                            "filename": "file1",
                        }
                    ],
                },
                "dequeued": "report-feeds.custom-entity-id.ReportFeeds-Microsoft.2025.11.18.2024-04-01T01:01:01.000001Z",
            },
        )

        input_event_2 = self.plugin._gen_input_event(
            self.known_publisher, entity, refs, azm.BinaryAction.Augmented, "file2"
        )
        self.compare_pydantic_model_to_dict(
            input_event_2,
            {
                "model_version": azm.CURRENT_MODEL_VERSION,
                "kafka_key": "reportfeed-placeholder",
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "author": {"category": "plugin", "name": "ReportFeeds-Microsoft", "version": "2025.11.18"},
                "entity": {"sha256": "custom-entity-id"},
                "action": "augmented",
                "source": {
                    "security": "OFFICIAL",
                    "name": "reporting",
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "references": {"ref1": "val1", "ref2": "ref2_val"},
                    "path": [
                        {
                            "sha256": "custom-entity-id",
                            "action": "augmented",
                            "timestamp": "2024-04-01T01:01:01.000001+00:00",
                            "author": {"category": "plugin", "name": "ReportFeeds-Microsoft", "version": "2025.11.18"},
                            "filename": "file2",
                        }
                    ],
                },
                "dequeued": "report-feeds.custom-entity-id.ReportFeeds-Microsoft.2025.11.18.2024-04-01T01:01:01.000001Z",
            },
        )

    def test_gen_indicator_event(self, mock_submit_events: mock.MagicMock):
        """Event generation is working as expected."""
        common_refs: dict[str, str] = {"publisher": "dummy1"}
        common_features: dict[str, str] = {"report_found": self.report_1_full.site if self.report_1_full.site else ""}

        indicator_event_1 = self.plugin._gen_indicator_event(
            common_refs["publisher"], self.indicator_1_full, common_features, [get_fake_file_info()], common_refs
        )
        self.compare_pydantic_model_to_dict(
            indicator_event_1,
            {
                "dequeued": "report-feeds.1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b.ReportFeeds.2025.11.18.2024-04-01T01:01:01.000001Z",
                "kafka_key": "reportfeed-placeholder",
                "action": "mapped",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [
                        {
                            "sha256": "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                            "action": "mapped",
                            "timestamp": "2024-04-01T01:01:01.000001+00:00",
                            "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                            "filename": "fname1",
                        }
                    ],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {"publisher": "dummy1"},
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "size": 200,
                    "sha256": "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                    "sha1": "187a9c07252fc25ed710a50adcce35697058fda5",
                    "md5": "14524d6c56a8c910f19c11f73e8251b6",
                    "ssdeep": "168:5YGbu72mrwBZBs6tqQc5Xi/6DlemQKuIIx6siUI7EQE3PH+yT:5YGbsdwvBTaXi/q0vKuIIUSIaNT",
                    "features": [
                        {"name": "filename", "type": "filepath", "value": "fname1"},
                        {"name": "malware_family", "type": "string", "value": "my-family-1"},
                        {"name": "report_found", "type": "string", "value": "https://www.not.real.com/security"},
                    ],
                    "datastreams": [
                        {
                            "identify_version": 1,
                            "label": "report",
                            "size": 216000,
                            "sha512": "b1e954ddb850127128c04a39e9b21783732a2741c47392e550615ec0d1f72a944b5fbbfad2981838ee37ab25f4fa0feef75d9825c5a737647960ddf2f2b5151b",
                            "sha256": "dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
                            "sha1": "8d332d49e436df0a69f0453596b11007b781307b",
                            "md5": "f54038c08570488430deb8594535ed60",
                            "mime": "pdf",
                            "magic": "PDF but not real magic",
                            "file_format": "document/pdf",
                        }
                    ],
                },
            },
        )

        indicator_event_2 = self.plugin._gen_indicator_event(
            common_refs["publisher"], self.indicator_2_full, common_features, [get_fake_file_info()], common_refs
        )
        self.compare_pydantic_model_to_dict(
            indicator_event_2,
            {
                "dequeued": "report-feeds.2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b.ReportFeeds.2025.11.18.2024-04-01T01:01:01.000001Z",
                "kafka_key": "reportfeed-placeholder",
                "action": "mapped",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [
                        {
                            "sha256": "2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                            "action": "mapped",
                            "timestamp": "2024-04-01T01:01:01.000001+00:00",
                            "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                            "filename": "fname2",
                        }
                    ],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {"publisher": "dummy1"},
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "size": 300,
                    "sha256": "2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                    "sha1": "287a9c07252fc25ed710a50adcce35697058fda5",
                    "md5": "24524d6c56a8c910f19c11f73e8251b6",
                    "ssdeep": "268:5YGbu72mrwBZBs6tqQc5Xi/6DlemQKuIIx6siUI7EQE3PH+yT:5YGbsdwvBTaXi/q0vKuIIUSIaNT",
                    "features": [
                        {"name": "filename", "type": "filepath", "value": "fname2"},
                        {"name": "malware_family", "type": "string", "value": "my-family-2"},
                        {"name": "report_found", "type": "string", "value": "https://www.not.real.com/security"},
                    ],
                    "datastreams": [
                        {
                            "identify_version": 1,
                            "label": "report",
                            "size": 216000,
                            "sha512": "b1e954ddb850127128c04a39e9b21783732a2741c47392e550615ec0d1f72a944b5fbbfad2981838ee37ab25f4fa0feef75d9825c5a737647960ddf2f2b5151b",
                            "sha256": "dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
                            "sha1": "8d332d49e436df0a69f0453596b11007b781307b",
                            "md5": "f54038c08570488430deb8594535ed60",
                            "mime": "pdf",
                            "magic": "PDF but not real magic",
                            "file_format": "document/pdf",
                        }
                    ],
                },
            },
        )

    def test_metric_collection_doesnt_fail(self, mock_submit_events: mock.MagicMock):
        """Verifying that the metric handlers dont' break on the bedrock models."""
        self.plugin._load_metric_handlers()
        dummyFeed = rss.RSSFeed(
            base_feed.ReportFeedOptions.Feed(
                publisher="test1",
                source="y",
                module="",
                distribution="x",
                site="https://super-test.com",
                feed_url="https://super-test.com/feed",
            ),
            base_feed.ReportFeedOptions(),
        )

        entity = azm.BinaryEvent.Entity(sha256="custom-entity-id")
        refs = {"ref1": "val1", "ref2": "ref2_val"}
        mapped_event = self.plugin._gen_input_event(
            self.report_1_full_with_indicators.publisher, entity, refs, azm.BinaryAction.Mapped, "file1"
        )

        download_event = self.plugin._gen_download_event(
            self.report_1_full_with_indicators,
            self.indicator_1_full,
            {"publisher": self.report_1_full_with_indicators.publisher},
        )
        # Just verifying stats collection doesn't raise an exception
        self.plugin._capture_feed_metrics(dummyFeed, ([mapped_event], [mapped_event], [download_event]))


@mock.patch("pendulum.now", mock_pendulum_now)
@mock.patch.object(dispatcher.DispatcherAPI, "submit_binary")
@mock.patch.object(dispatcher.DispatcherAPI, "submit_events")
class ProcessReportTests(BaseTest):
    def setUp(self):
        self.indicator_1_full = get_indicators_full_1()
        self.indicator_2_full = get_indicators_full_2()
        self.report_1_full = get_report_1()
        self.report_1_full_with_indicators = get_report_1_with_indicators()
        self.create_plugin_from_config()

    def _verify_event_args(self, call_args, length: int, length_download: int):
        print(call_args)
        # Verify for each event to be downloaded a call to submit events is called.
        download_index = 0
        for i in range(length):
            self.assertIsInstance(call_args[0][0][0], list)
            self.assertEqual(len(call_args[0][0][0]), 1)
            download_index = i
        download_index += 1
        # Download is called once after all the other submissions with all the download events to be raised.
        if length_download > 0:
            self.assertEqual(len(call_args[download_index][0][0]), length_download)

    def test_normal(self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock):
        """Test a normal run of report process works when nothing goes wrong."""
        mock_submit_binary.return_value = get_fake_file_info()

        tuple_of_events = self.plugin.process_report(self.report_1_full_with_indicators)
        # Check Mapped events were created (report attached to various sha256's)
        self.assertEqual(len(tuple_of_events[0]), 2)
        self.compare_pydantic_model_to_dict(
            tuple_of_events[0][0],
            {
                "dequeued": "report-feeds.2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b.ReportFeeds.2025.11.18.2024-04-01T01:01:01.000001Z",
                "kafka_key": "reportfeed-placeholder",
                "action": "mapped",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [
                        {
                            "sha256": "2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                            "action": "mapped",
                            "timestamp": "2024-04-01T01:01:01.000001+00:00",
                            "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                            "filename": "fname2",
                        }
                    ],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {
                        "publisher": "publisher1",
                        "distribution": "public",
                        "site": "https://www.not.real.com/security",
                        "url": "https://www.not.real.com/security/blog/1",
                        "slug": "awesome-title",
                        "title": "awesome-title",
                        "report_id": "report_id_abc",
                    },
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "md5": "24524d6c56a8c910f19c11f73e8251b6",
                    "sha1": "287a9c07252fc25ed710a50adcce35697058fda5",
                    "sha256": "2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                    "ssdeep": "268:5YGbu72mrwBZBs6tqQc5Xi/6DlemQKuIIx6siUI7EQE3PH+yT:5YGbsdwvBTaXi/q0vKuIIUSIaNT",
                    "size": 300,
                    "features": [
                        {"name": "filename", "type": "filepath", "value": "fname2"},
                        {"name": "malware_family", "type": "string", "value": "my-family-2"},
                        {"name": "report_description", "type": "string", "value": "Report 1's high level summary."},
                        {"name": "report_found", "type": "string", "value": "https://www.not.real.com/security"},
                        {"name": "report_id", "type": "string", "value": "report_id_abc"},
                        {"name": "report_type", "type": "string", "value": "good-type-of-report"},
                    ],
                    "datastreams": [
                        {
                            "md5": "f54038c08570488430deb8594535ed60",
                            "sha1": "8d332d49e436df0a69f0453596b11007b781307b",
                            "sha256": "dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
                            "sha512": "b1e954ddb850127128c04a39e9b21783732a2741c47392e550615ec0d1f72a944b5fbbfad2981838ee37ab25f4fa0feef75d9825c5a737647960ddf2f2b5151b",
                            "size": 216000,
                            "file_format": "document/pdf",
                            "mime": "pdf",
                            "magic": "PDF but not real magic",
                            "identify_version": 1,
                            "label": "content",
                        }
                    ],
                },
            },
        )
        # Check Sourced events were created (adding files from report)
        self.assertEqual(len(tuple_of_events[1]), 2)
        self.compare_pydantic_model_to_dict(
            tuple_of_events[1][0],
            {
                "dequeued": "report-feeds.dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5.ReportFeeds.2025.11.18.2024-04-01T01:01:01.000001Z",
                "kafka_key": "reportfeed-placeholder",
                "action": "sourced",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [
                        {
                            "sha256": "dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
                            "action": "sourced",
                            "timestamp": "2024-04-01T01:01:01.000001+00:00",
                            "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                        }
                    ],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {
                        "publisher": "publisher1",
                        "distribution": "public",
                        "site": "https://www.not.real.com/security",
                        "url": "https://www.not.real.com/security/blog/1",
                        "slug": "awesome-title",
                        "title": "awesome-title",
                        "report_id": "report_id_abc",
                    },
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "md5": "f54038c08570488430deb8594535ed60",
                    "sha1": "8d332d49e436df0a69f0453596b11007b781307b",
                    "sha256": "dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
                    "sha512": "b1e954ddb850127128c04a39e9b21783732a2741c47392e550615ec0d1f72a944b5fbbfad2981838ee37ab25f4fa0feef75d9825c5a737647960ddf2f2b5151b",
                    "size": 216000,
                    "file_format": "document/pdf",
                    "mime": "pdf",
                    "magic": "PDF but not real magic",
                    "features": [
                        {"name": "report_description", "type": "string", "value": "Report 1's high level summary."},
                        {"name": "report_found", "type": "string", "value": "https://www.not.real.com/security"},
                        {"name": "report_id", "type": "string", "value": "report_id_abc"},
                        {"name": "report_type", "type": "string", "value": "good-type-of-report"},
                    ],
                    "datastreams": [
                        {
                            "md5": "f54038c08570488430deb8594535ed60",
                            "sha1": "8d332d49e436df0a69f0453596b11007b781307b",
                            "sha256": "dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
                            "sha512": "b1e954ddb850127128c04a39e9b21783732a2741c47392e550615ec0d1f72a944b5fbbfad2981838ee37ab25f4fa0feef75d9825c5a737647960ddf2f2b5151b",
                            "size": 216000,
                            "file_format": "document/pdf",
                            "mime": "pdf",
                            "magic": "PDF but not real magic",
                            "identify_version": 1,
                            "label": "content",
                        }
                    ],
                },
            },
        )
        # Check Download events are generated (Download any and all sha256's in the report)
        self.assertEqual(len(tuple_of_events[2]), 2)
        self.compare_pydantic_model_to_dict(
            tuple_of_events[2][0],
            {
                "kafka_key": "download-2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                "action": "requested",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {
                        "publisher": "publisher1",
                        "distribution": "public",
                        "site": "https://www.not.real.com/security",
                        "url": "https://www.not.real.com/security/blog/1",
                        "slug": "awesome-title",
                        "title": "awesome-title",
                        "report_id": "report_id_abc",
                    },
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "hash": "2ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                    "pcap": True,
                    "category": "awesome-title",
                    "category_quota": 100,
                },
            },
        )

        # Submit once for the PDF report and twice for the two file uploads
        self.assertEqual(mock_submit_binary.call_count, 3)
        # All events should be submitted for submission to dispatcher.
        self._verify_event_args(mock_submit_events.call_args_list, 4, 0)

    def test_bad_reference_mapping_config(
        self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock
    ):
        """Test a normal run of report process works when nothing goes wrong."""
        mock_submit_binary.return_value = get_fake_file_info()
        self.plugin.cfg.ref_key_to_report_result_key = {"title", "non_existant_report_result_model_key"}
        self.assertRaises(Exception, self.plugin.process_report, self.report_1_full_with_indicators)

    def test_duplicate_indicators(self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock):
        """Same as normal but there are duplicate indicators in the input (no change expected)."""
        mock_submit_binary.return_value = get_fake_file_info()
        indicator2_again = get_indicators_full_2()
        indicator2_again.md5 = ""
        indicator2_again.sha1 = ""
        indicator2_again.ssdeep = ""
        self.report_1_full_with_indicators.indicators.append(indicator2_again)
        self.report_1_full_with_indicators.indicators.append(get_indicators_full_2())
        tuple_of_events = self.plugin.process_report(self.report_1_full_with_indicators)
        # Check Mapped events were created (report attached to various sha256's)
        self.assertEqual(len(tuple_of_events[0]), 2)
        # Check Sourced events were created (adding files from report)
        self.assertEqual(len(tuple_of_events[1]), 2)
        # Check Download events are generated (Download any and all sha256's in the report)
        self.assertEqual(len(tuple_of_events[2]), 2)

        # All events should be submitted for submission to dispatcher.
        self._verify_event_args(mock_submit_events.call_args_list, 4, 2)

    def test_without_malware_files(self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock):
        """Ensure there are no binary sourced events when the report has no files."""
        mock_submit_binary.return_value = get_fake_file_info()
        self.report_1_full_with_indicators.files = []

        tuple_of_events = self.plugin.process_report(self.report_1_full_with_indicators)
        # Check Mapped events were created (report attached to various sha256's)
        self.assertEqual(len(tuple_of_events[0]), 2)
        # Check Sourced events were created (adding files from report)
        self.assertEqual(len(tuple_of_events[1]), 0)
        # Check Download events are generated (Download any and all sha256's in the report)
        self.assertEqual(len(tuple_of_events[2]), 2)

        # Only called to submit the PDF report once.
        mock_submit_binary.assert_called_once()
        self._verify_event_args(mock_submit_events.call_args_list, 2, 0)

    def test_without_malware_files_or_report(
        self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock
    ):
        """Ensure there are no binary sourced events when the report has no files."""
        mock_submit_binary.return_value = get_fake_file_info()
        self.report_1_full_with_indicators.files = []
        self.report_1_full_with_indicators.report = None

        tuple_of_events = self.plugin.process_report(self.report_1_full_with_indicators)
        # Check Mapped events were created (report attached to various sha256's)
        self.assertEqual(len(tuple_of_events[0]), 2)
        # Check Sourced events were created (adding files from report)
        self.assertEqual(len(tuple_of_events[1]), 0)
        # Check Download events are generated (Download any and all sha256's in the report)
        self.assertEqual(len(tuple_of_events[2]), 2)

        self._verify_event_args(mock_submit_events.call_args_list, 2, 0)

        mock_submit_binary.assert_not_called()

    def test_without_indicators(self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock):
        """Ensure process_report still works when there are no, indicators"""
        mock_submit_binary.return_value = get_fake_file_info()
        tuple_of_events = self.plugin.process_report(self.report_1_full)
        # Check Mapped events were created (report attached to various sha256's)
        self.assertEqual(len(tuple_of_events[0]), 0)
        # Check Sourced events were created (adding files from report)
        self.assertEqual(len(tuple_of_events[1]), 2)
        # Check Download events are generated (Download any and all sha256's in the report)
        self.assertEqual(len(tuple_of_events[2]), 0)

        # Submit once for the PDF report and twice for the two file uploads
        self.assertEqual(mock_submit_binary.call_count, 3)
        self._verify_event_args(mock_submit_events.call_args_list, 2, 0)

    def test_without_indicators_or_files(self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock):
        """Ensure process_report still works when there are no, indicators"""
        mock_submit_binary.return_value = get_fake_file_info()
        self.report_1_full.files = []
        tuple_of_events = self.plugin.process_report(self.report_1_full)
        # Check Mapped events were created (report attached to various sha256's)
        self.assertEqual(len(tuple_of_events[0]), 0)
        # Check Sourced events were created (adding files from report)
        self.assertEqual(len(tuple_of_events[1]), 0)
        # Check Download events are generated (Download any and all sha256's in the report)
        self.assertEqual(len(tuple_of_events[2]), 0)

        # If called with an empty list dispatcher will fail to process the events.
        mock_submit_events.assert_not_called()

    def test_indicators_have_no_sha256(self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock):
        """Ensure process_report still works when there are no indicators with sha256's"""
        mock_submit_binary.return_value = get_fake_file_info()
        for i in self.report_1_full_with_indicators.indicators:
            i.sha256 = ""
        tuple_of_events = self.plugin.process_report(self.report_1_full_with_indicators)
        # Check Mapped events were created (report attached to various sha256's)
        self.assertEqual(len(tuple_of_events[0]), 0)
        # Check Sourced events were created (adding files from report)
        self.assertEqual(len(tuple_of_events[1]), 2)
        # Check Download events are generated (Download any and all sha256's in the report)
        self.assertEqual(len(tuple_of_events[2]), 0)

        self._verify_event_args(mock_submit_events.call_args_list, 2, 0)

    def test_invalid_report(self, mock_submit_events: mock.MagicMock, mock_submit_binary: mock.MagicMock):
        """Ensure if there is an invalid report (not a PDF) it's dropped and doesn't feature in the results."""
        mock_submit_binary.return_value = get_fake_file_info()
        self.report_1_full_with_indicators.report = b"AHHHH not a PDF file anymore."
        tuple_of_events = self.plugin.process_report(self.report_1_full_with_indicators)
        # Check Mapped events were created (report attached to various sha256's)
        self.assertEqual(len(tuple_of_events[0]), 2)
        self.compare_pydantic_model_to_dict(
            tuple_of_events[0][1],
            {
                "dequeued": "report-feeds.1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b.ReportFeeds.2025.11.18.2024-04-01T01:01:01.000001Z",
                "kafka_key": "reportfeed-placeholder",
                "action": "mapped",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [
                        {
                            "sha256": "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                            "action": "mapped",
                            "timestamp": "2024-04-01T01:01:01.000001+00:00",
                            "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                            "filename": "fname1",
                        }
                    ],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {
                        "publisher": "publisher1",
                        "distribution": "public",
                        "site": "https://www.not.real.com/security",
                        "url": "https://www.not.real.com/security/blog/1",
                        "slug": "awesome-title",
                        "title": "awesome-title",
                        "report_id": "report_id_abc",
                    },
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "md5": "14524d6c56a8c910f19c11f73e8251b6",
                    "sha1": "187a9c07252fc25ed710a50adcce35697058fda5",
                    "sha256": "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                    "ssdeep": "168:5YGbu72mrwBZBs6tqQc5Xi/6DlemQKuIIx6siUI7EQE3PH+yT:5YGbsdwvBTaXi/q0vKuIIUSIaNT",
                    "size": 200,
                    "features": [
                        {"name": "filename", "type": "filepath", "value": "fname1"},
                        {"name": "malware_family", "type": "string", "value": "my-family-1"},
                        {"name": "report_description", "type": "string", "value": "Report 1's high level summary."},
                        {"name": "report_found", "type": "string", "value": "https://www.not.real.com/security"},
                        {"name": "report_id", "type": "string", "value": "report_id_abc"},
                        {"name": "report_type", "type": "string", "value": "good-type-of-report"},
                    ],
                },
            },
        )
        # Check Sourced events were created (adding files from report)
        self.assertEqual(len(tuple_of_events[1]), 2)
        self.compare_pydantic_model_to_dict(
            tuple_of_events[1][1],
            {
                "dequeued": "report-feeds.dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5.ReportFeeds.2025.11.18.2024-04-01T01:01:01.000001Z",
                "kafka_key": "reportfeed-placeholder",
                "action": "sourced",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [
                        {
                            "sha256": "dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
                            "action": "sourced",
                            "timestamp": "2024-04-01T01:01:01.000001+00:00",
                            "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                        }
                    ],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {
                        "publisher": "publisher1",
                        "distribution": "public",
                        "site": "https://www.not.real.com/security",
                        "url": "https://www.not.real.com/security/blog/1",
                        "slug": "awesome-title",
                        "title": "awesome-title",
                        "report_id": "report_id_abc",
                    },
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "md5": "f54038c08570488430deb8594535ed60",
                    "sha1": "8d332d49e436df0a69f0453596b11007b781307b",
                    "sha256": "dd4ce5982b48d49f4355212a75bac4fe8596301afca91b4e37141734dcb4d8a5",
                    "sha512": "b1e954ddb850127128c04a39e9b21783732a2741c47392e550615ec0d1f72a944b5fbbfad2981838ee37ab25f4fa0feef75d9825c5a737647960ddf2f2b5151b",
                    "size": 216000,
                    "file_format": "document/pdf",
                    "mime": "pdf",
                    "magic": "PDF but not real magic",
                    "features": [
                        {"name": "report_description", "type": "string", "value": "Report 1's high level summary."},
                        {"name": "report_found", "type": "string", "value": "https://www.not.real.com/security"},
                        {"name": "report_id", "type": "string", "value": "report_id_abc"},
                        {"name": "report_type", "type": "string", "value": "good-type-of-report"},
                    ],
                },
            },
        )
        # Check Download events are generated (Download any and all sha256's in the report)
        self.assertEqual(len(tuple_of_events[2]), 2)
        self.compare_pydantic_model_to_dict(
            tuple_of_events[2][1],
            {
                "kafka_key": "download-1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                "action": "requested",
                "model_version": azm.CURRENT_MODEL_VERSION,
                "timestamp": "2024-04-01T01:01:01.000001+00:00",
                "source": {
                    "name": "reporting",
                    "path": [],
                    "timestamp": "2024-04-01T01:01:01.000001+00:00",
                    "security": "OFFICIAL",
                    "references": {
                        "publisher": "publisher1",
                        "distribution": "public",
                        "site": "https://www.not.real.com/security",
                        "url": "https://www.not.real.com/security/blog/1",
                        "slug": "awesome-title",
                        "title": "awesome-title",
                        "report_id": "report_id_abc",
                    },
                },
                "author": {"category": "plugin", "name": "ReportFeeds", "version": "2025.11.18"},
                "entity": {
                    "hash": "1ce52aa8a62f1a184af133330ee565331070d5e937c31698f9c136a89514c80b",
                    "pcap": True,
                    "category": "awesome-title",
                    "category_quota": 100,
                },
            },
        )

        self._verify_event_args(mock_submit_events.call_args_list, 4, 0)

"""The map module maps report entities into binaries and download requests."""

import copy
import hashlib
import logging
import os.path
import time
import traceback

import pendulum
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from azul_runner import (
    DataLabel,
    Feature,
    FeatureType,
    FeatureValue,
    Plugin,
    add_settings,
)
from azul_runner import main as azr_main
from azul_runner import network_transform as azr_network_tranform
from azul_runner import settings as azr_settings
from prometheus_client import CollectorRegistry, Counter, Gauge, push_to_gateway

from azul_plugin_report_feeds.reportcollector import base_feed
from azul_plugin_report_feeds.reportcollector.models import Indicator, ReportResult

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "reportfeeds.yaml")
DEFAULT_STATE_DR = os.path.expanduser("~/.reportfeeds")


class AzulPluginReportFeeds(Plugin):
    """Plugin for download files from various feed sources and forwarding into Azul."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.11.18"
    SETTINGS = add_settings(
        # NOTE - report feeds are configured through environment variables as defined in the class `ReportFeedOptions`
        # Max downloads that the plugin will request from Virustotal per report.
        max_downloads_per_report=(int, 100),
        # Path to the directory holding the state of the loaded reports.
        state_directory=(str, DEFAULT_STATE_DR),
        # Gateway to push prometheus metrics to (optional).
        prometheus_push_gateway=(str, ""),
        # Name of the source report feeds will submit as.
        feed_source_name=(str, "reporting"),
        # Security applied to all documents sourced from this group of feeds.
        feed_security=(str, "OFFICIAL"),
        # Adds a suffix to the job name to indicate namespace.
        namespace_suffix=(str, ""),
        # Additional Reference mappings
        # (key is the name of the reference and value is the name of the field on the Report Result.)
        ref_key_to_report_result_key=(dict, {"title": "slug"}),
    )
    ENTITY_TYPE = ""  # Not applicable because this plugin doesn't pull entities from dispatcher.
    FEATURES = [
        Feature(
            name="malware_family",
            desc="Malware family associated with the identified binary.",
            type=FeatureType.String,
        ),
        Feature(
            name="report_found",
            desc="String indicating the URL to a report found for this binary,"
            + " sources may indicate more than one report.",
            type=FeatureType.String,
        ),
        Feature(name="report_description", desc="High level summary of the found report.", type=FeatureType.String),
        Feature(name="report_id", desc="Id number of the report that was found.", type=FeatureType.String),
        Feature(name="report_type", desc="Type of the report that was found.", type=FeatureType.String),
    ]

    TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"

    def __init__(self, config: azr_settings.Settings | dict | None = None) -> None:
        super().__init__(config)
        self.metrics_enabled = False
        self._load_metric_handlers()
        self.author = azm.Author(name=self.NAME, version=self.VERSION, category="plugin")
        self.dp = dispatcher.DispatcherAPI(
            events_url=self.cfg.events_url,
            data_url=self.cfg.data_url,
            retry_count=self.cfg.request_retry_count,
            timeout=self.cfg.request_timeout,
            author_name=self.NAME,
            author_version=self.VERSION,
            deployment_key=self.cfg.deployment_key,
        )
        # Register all the sources as plugins for registration functions with dummy processing functions.
        self.feed_config = base_feed.ReportFeedOptions()
        self.publisher_authors: dict[str, azm.Author] = dict()
        for feed in self.feed_config.feeds:
            self.register_multiplugin(feed.publisher, None, lambda j: None)
            # FUTURE security could be confgured on a publisher basis.
            self.publisher_authors[feed.publisher] = azr_network_tranform.gen_author(
                self, self.get_multiplugin(feed.publisher)
            )

    def _get_publisher_author(self, publisher_name: str | None) -> azm.Author:
        """Get the provided publisher and return the default publisher if the specific one couldn't be found."""
        return self.publisher_authors.get(publisher_name, self.author)

    def _get_report_info(self, content: bytes) -> azm.Datastream:
        """Convert the raw contents of a pdf report into a Datastream object ready to add as an augmented stream."""
        label = DataLabel.REPORT
        file_info = self.dp.submit_binary(self.cfg.feed_source_name, label, content)  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
        file_info.label = label  # Dispatcher doesn't set label
        return file_info

    def _convert_to_features_from_dict(self, features: dict[str, str]):
        features_as_fv = dict()
        for key, val in features.items():
            features_as_fv[key] = [FeatureValue(val)]
        return azr_network_tranform._to_api_features(self, features_as_fv)

    def process_report(
        self, report: ReportResult
    ) -> tuple[list[azm.BinaryEvent], list[azm.BinaryEvent], list[azm.DownloadEvent]]:
        """Process a report and extract the appropriate features, extract binaries and make download requests."""
        # If the timezone isn't set set it. (shouldn't happen but just in case.)
        if not report.timestamp:
            raise ValueError("Expected report.timestamp to be a datetime, got None")
        if not report.timestamp.tzname:
            report.timestamp = report.timestamp.replace(tzinfo=pendulum.UTC)
            logger.warning(f"Timezone isn't set for report published by '{report.publisher=}'")
        report_pdf = report.report

        if not report_pdf:
            report_pdf = None

        # Account for case where report isn't a PDF.
        if report_pdf and not report_pdf.startswith(b"%PDF"):
            logger.warning(f"The {report.publisher=} has provided a report that isn't in PDF format dropping it.")
            report_pdf = None

        report_pdf_info = None
        if report_pdf and report.report:
            report_pdf_info = self._get_report_info(report.report)

        logger.info(f"Posting {report.publisher=} report {report.slug} ({report.timestamp}) to Azul")

        # Smash all partial indicators together to make sure we don't have the same sha256 in multiple indicators.
        report.deduplicate_indicators()

        # If a report contains an indicator and the raw contents for the indicator remove the indicator and just add
        # the raw content because the features will be in the sourced event.
        for binary in report.files:
            if not binary:
                continue
            sha256 = hashlib.sha256(binary).hexdigest()
            cur_indicator = report.get_indicator_by_sha256(sha256)
            if cur_indicator:
                report.indicators.remove(cur_indicator)

        report_refs = report.model_dump(
            include=set(["publisher", "distribution", "slug", "site", "url", "report_id"]), exclude_none=True
        )

        if len(self.cfg.ref_key_to_report_result_key) > 0:  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
            dumped_model = report.model_dump()
            for ref_key, report_key in self.cfg.ref_key_to_report_result_key.items():  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
                try:
                    val = dumped_model[report_key]
                    report_refs[ref_key] = val
                except Exception as e:
                    raise Exception(
                        f"The report key '{report_key}' does not exist in report, "
                        + f"available fields are {report_refs.keys().join(',')}. Inner error {e}"
                    ) from e

        report_data: list[azm.Datastream] = []
        if report_pdf_info:
            report_data.append(report_pdf_info)

        mapped_events: list[azm.BinaryEvent] = []
        download_events: list[azm.DownloadEvent] = []

        # Find features that will be common to all indicators for this report.
        common_features: dict[str, str] = {
            "report_found": report.site if report.site else report.url if report.url else ""
        }
        if report.description:
            common_features["report_description"] = report.description
        if report.report_type:
            common_features["report_type"] = report.report_type
        if report.report_id:
            common_features["report_id"] = report.report_id

        for indicator in report.indicators:
            # Must have a sha256 to map the metadata in a sensible way.
            if not indicator.sha256:
                continue
            event = self._gen_indicator_event(report.publisher, indicator, common_features, report_data, report_refs)
            mapped_events.append(event)

            if len(download_events) < self.cfg.max_downloads_per_report:  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
                download_events.append(self._gen_download_event(report, indicator, report_refs))

        sourced_events: list[azm.BinaryEvent] = []
        # Child malware samples if there are any.
        for file_content in report.files:
            file_info = self.dp.submit_binary(self.cfg.feed_source_name, DataLabel.CONTENT, file_content)  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
            file_info.label = DataLabel.CONTENT  # Dispatcher doesn't set label
            as_entity = file_info.to_input_entity()
            as_entity.datastreams = report_data
            as_entity.features = self._convert_to_features_from_dict(common_features)
            sourced_events.append(
                self._gen_input_event(report.publisher, as_entity, report_refs, azm.BinaryAction.Sourced)
            )

        # FUTURE - validate feature values being too long etc... run the function _process_features on the features.
        # FUTURE - Use the azul-runner network module for registering the plugin and publishing completion/error
        # results.
        # Prevent submitting an empty list.
        binary_events_list = mapped_events + sourced_events
        if binary_events_list:
            for event in binary_events_list:
                eventDuplicate = copy.deepcopy(event)
                eventDuplicate.entity.features = []
                eventDuplicate.entity.datastreams = []
                eventDuplicate.entity.info = {}

                status_event = azm.StatusEvent(
                    model_version=azm.CURRENT_MODEL_VERSION,
                    kafka_key="azul-plugin-retrohunt-placeholder",
                    timestamp=pendulum.now(pendulum.UTC),
                    author=self._get_publisher_author(report.publisher),
                    entity=azm.StatusEvent.Entity(
                        input=eventDuplicate, status=azm.StatusEnum.COMPLETED, runtime=0, results=[event]
                    ),
                )
                self.dp.submit_events([status_event], model=azm.ModelType.Status)
        if download_events:
            self.dp.submit_events(download_events, model=azm.ModelType.Download)
        return (mapped_events, sourced_events, download_events)

    def _gen_indicator_event(
        self,
        publisher: str | None,
        indicator: Indicator,
        common_features: dict[str, str],
        report_data: list[azm.Datastream],
        report_refs: dict[str, str],
    ) -> azm.BinaryEvent:
        """Generate and submit events associated with an indicator.

        Returns False is nothing was mapped and True if the indicator generated anything useful.
        """
        if not indicator.sha256:
            raise ValueError("Attempting to create an enrichment event without a sha256.")

        # Add features as features where necessary.
        features = common_features.copy()
        if indicator.malware_family:
            features["malware_family"] = indicator.malware_family
        if indicator.filename:
            features["filename"] = indicator.filename

        entity = azm.BinaryEvent.Entity(
            # Basic metadata if it's present
            sha256=indicator.sha256,
            sha1=indicator.sha1,
            md5=indicator.md5,
            size=indicator.file_size if indicator.file_size else None,
            ssdeep=indicator.ssdeep,
            # Add feature values.
            features=self._convert_to_features_from_dict(features),
            datastreams=report_data,
        )

        return self._gen_input_event(publisher, entity, report_refs, azm.BinaryAction.Mapped, indicator.filename)

    def _gen_input_event(
        self,
        publisher: str | None,
        entity: azm.BinaryEvent.Entity,
        references: dict[str, str],
        event_type: azm.BinaryAction,
        filename: str | None = None,
    ) -> azm.BinaryEvent:
        """Create an Input event from the inputs setting the timestamps to now."""
        timestamp = pendulum.now(pendulum.UTC).to_iso8601_string()
        current_publisher = self._get_publisher_author(publisher)
        if entity.sha256 is None:
            raise ValueError("Expected entity.sha256 to str, got None")
        return azm.BinaryEvent(
            kafka_key="reportfeed-placeholder",  # temporary id so we can create the object
            dequeued=f"report-feeds.{entity.sha256}.{current_publisher.name}.{current_publisher.version}.{timestamp}",
            action=event_type,
            model_version=azm.CURRENT_MODEL_VERSION,
            timestamp=timestamp,
            author=current_publisher,
            entity=entity,
            source=azm.Source(
                name=self.cfg.feed_source_name,  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
                timestamp=timestamp,
                references=references,
                path=[
                    azm.PathNode(
                        author=current_publisher,
                        action=event_type,
                        timestamp=timestamp,
                        sha256=entity.sha256,
                        filename=filename,
                    )
                ],
                security=self.cfg.feed_security,  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
            ),
        )

    def _gen_download_event(
        self, report: ReportResult, indicator: Indicator, references: dict[str, str]
    ) -> azm.DownloadEvent:
        """Generate a download event that when published will trigger the virustotal plugin to download a file."""
        if not indicator.sha256:
            raise ValueError("Attempting to create download event without a sha256.")
        timestamp = pendulum.now(pendulum.UTC).to_iso8601_string()
        ent_id = f"download-{indicator.sha256}"

        entity = azm.DownloadEvent.Entity(
            hash=indicator.sha256,
            pcap=True,
            category=report.slug,
            category_quota=self.cfg.max_downloads_per_report,  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
        )

        return azm.DownloadEvent(
            model_version=azm.CURRENT_MODEL_VERSION,
            kafka_key=ent_id,
            action=azm.DownloadAction.Requested,
            timestamp=timestamp,
            # Author is just the root plugin author because it doesn't matter what publisher has requested the download
            author=self.author,
            entity=entity,
            source=azm.Source(
                name=self.cfg.feed_source_name,  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
                timestamp=timestamp,
                references=references,
                path=[],
                security=self.cfg.feed_security,  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
            ),
        )

    def _download_from_sources(self, feed_config: base_feed.ReportFeedOptions, state_dir: str):
        """Download from the feeds listed in the report-feeds configuration file."""
        for feed in feed_config.feeds:
            # Zero out all metrics for given feed labels so push gateway detects a new run.
            self._capture_feed_metrics(feed, ([], [], []), zeroing=True)
            self.publisher_failures_count.labels(publisher=feed.publisher, reason="process", message="").inc(0)
            self.publisher_failures_count.labels(publisher=feed.publisher, reason="fetch", message="").inc(0)
            self.publisher_fully_succeeded_count.labels(publisher=feed.publisher).inc(0)

            logger.info(f"Checking feed '{feed.publisher}'")
            state_file = os.path.join(state_dir, feed.publisher)
            last_timestamp = None

            if os.path.exists(state_file):
                with open(state_file, "r") as tmp:
                    s = tmp.read().strip()
                    last_timestamp = pendulum.parse(s, tz=pendulum.UTC)
                    logger.info(f"Resuming {feed.publisher=} from {last_timestamp}")

            start = time.time()

            fetched = False
            report_info = None
            try:
                for report_info in feed.fetch(last_fetch=last_timestamp):
                    # Save the latest successfully loaded report as the start point for the next load.
                    fetched = True
                    if report_info.timestamp:
                        with open(state_file, "w") as tmp:
                            newest_timestamp = pendulum.instance(report_info.timestamp, tz=pendulum.UTC)
                            tmp.write(newest_timestamp.to_iso8601_string())
                    metrics = self.process_report(report_info)
                    self._capture_feed_metrics(feed, metrics)
                    # Set fetched back to false after processing is done.
                    fetched = False
                self.publisher_fully_succeeded_count.labels(publisher=feed.publisher).inc()
            except Exception as ex:
                MAX_ERROR_MESSAGE_LEN = 300
                msg = "".join(traceback.format_exception_only(ex))[:MAX_ERROR_MESSAGE_LEN]
                if fetched and report_info:
                    logger.error(
                        "Failed to process a report from "
                        + f"{feed.publisher=} the report info (excluding files and report) was %s",
                        report_info.model_dump(exclude=set(["files", "report"])),
                    )
                    self.publisher_failures_count.labels(publisher=feed.publisher, reason="process", message=msg).inc()
                else:
                    logger.error(f"Failed to fetch data from {feed.publisher=}")
                    self.publisher_failures_count.labels(publisher=feed.publisher, reason="fetch", message=msg).inc()
                logger.error(f"Exception was \n{traceback.format_exc()}")

            duration = time.time() - start
            self.publisher_total_duration_gauge.labels(publisher=feed.publisher).set(duration)
            logger.info(f"Completed feed {feed.publisher=} after {duration:.2f}seconds")

    def _capture_feed_metrics(
        self,
        feed: base_feed.BaseFeed,
        metrics: tuple[list[azm.BinaryEvent], list[azm.BinaryEvent], list[azm.DownloadEvent]],
        zeroing=False,
    ):
        """Capture all of the metrics for a successful read of a feed."""
        for in_event in metrics[0]:
            self.publisher_events_generated.labels(
                publisher=feed.publisher, event_type="attach_report", sha256=in_event.entity.sha256
            ).inc()

        for in_event in metrics[1]:
            self.publisher_events_generated.labels(
                publisher=feed.publisher, event_type="source_malware", sha256=in_event.entity.sha256
            ).inc()

        for in_event in metrics[2]:
            self.publisher_events_generated.labels(
                publisher=feed.publisher, event_type="request_download", sha256=in_event.entity.hash
            ).inc()

        inc_amount = 1
        if zeroing:
            self.publisher_events_generated.labels(
                publisher=feed.publisher, event_type="attach_report", sha256=""
            ).inc(0)
            self.publisher_events_generated.labels(
                publisher=feed.publisher, event_type="source_malware", sha256=""
            ).inc(0)
            self.publisher_events_generated.labels(
                publisher=feed.publisher, event_type="request_download", sha256=""
            ).inc(0)
            inc_amount = 0
        self.publisher_reports_read_count.labels(publisher=feed.publisher).inc(inc_amount)

    def _push_all_metrics_to_gateway(self):
        """Push all of the modified values to the metric gateway."""
        if self.metrics_enabled:
            push_to_gateway(self.gateway, job=self.job_name, registry=self.registry)

    def _load_metric_handlers(self):
        """Create all of the metric handlers ready to capture metrics."""
        push_gateway = self.cfg.prometheus_push_gateway  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
        if not push_gateway:
            self.logger.info("Prometheus metrics are not being collected.")
        else:
            self.metrics_enabled = True
            self.gateway = push_gateway
            self.job_name = self.NAME + self.cfg.namespace_suffix  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings

        self.registry = CollectorRegistry()
        # Setup all metrics and point them to the appropriate registry.
        # Zeroed
        self.publisher_failures_count = Counter(
            "publisher_failures",
            "Total number of times a publisher has failed.",
            labelnames=(
                "publisher",
                "reason",
                "message",
            ),
            registry=self.registry,
        )
        # Zeroed
        self.publisher_reports_read_count = Counter(
            "publisher_reports_read",
            "Total number of reports read for a given publisher.",
            labelnames=("publisher",),
            registry=self.registry,
        )
        # zeroed
        self.publisher_events_generated = Counter(
            "publisher_events_generated",
            "Total number of events generated of a type by a publisher.",
            labelnames=("publisher", "event_type", "sha256"),
            registry=self.registry,
        )
        # zeroed
        self.publisher_fully_succeeded_count = Counter(
            "publisher_succeeded",
            "Publisher that read all it's feed data successfully.",
            labelnames=("publisher",),
            registry=self.registry,
        )
        self.publisher_total_duration_gauge = Gauge(
            "publisher_duration",
            "Total runtime for each individual publisher.",
            labelnames=("publisher",),
            registry=self.registry,
        )
        self.total_run_duration_gauge = Gauge(
            "total_runtime",
            "Total runtime for a full set of feeds being scraped.",
            registry=self.registry,
        )

    def run_once(self):
        """Run all of the configured feeds once."""
        state_dir = self.cfg.state_directory  # ty: ignore[unresolved-attribute] ty doesn't understand add_settings
        try:
            if not os.path.exists(state_dir):
                os.makedirs(state_dir)
        except OSError as e:
            if not os.path.exists(state_dir):
                raise Exception(f"Unable to create {state_dir=}") from e

        start_time = time.time()
        try:
            self._download_from_sources(self.feed_config, state_dir)
        finally:
            duration = time.time() - start_time
            self.total_run_duration_gauge.set(duration)
            self._push_all_metrics_to_gateway()
        logger.info(f"All feeds completed after {duration:.2f}seconds exiting...")


def main():
    """Perform a single batch of scrapes to collect latest reports from all the configured feeds.

    All metrics are forwarded to prometheus via a push gateway.
    """
    args = azr_main.parse_args()
    # Extracted from azul_plugin.main execute function.
    config = {}
    if args.server:
        config["events_url"] = args.server
        config["data_url"] = args.server
    if args.config:
        # Update with `-c NAME VALUE` args
        config.update({n: v for n, v in args.config})

    # Load config and create plugin.
    config = azr_settings.parse_config(AzulPluginReportFeeds, config)

    azprm = AzulPluginReportFeeds(config)
    # register plugin
    registration = azr_network_tranform.get_registrations(azprm)
    azprm.dp.submit_events(registration, model=azm.ModelType.Plugin)
    # process batch of scrapes
    azprm.run_once()


if __name__ == "__main__":
    main()

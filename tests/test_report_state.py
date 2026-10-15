import unittest
from random import choices
import datetime
from string import ascii_letters
from tempfile import TemporaryDirectory
from azul_plugin_report_feeds.reportcollector.util import ReportState


class ReportStateTests(unittest.TestCase):
    def test_new_state(self):
        """Test making a state object and using it."""
        with TemporaryDirectory() as state_dir:
            state = ReportState(state_dir)
            publisher = "Exists"
            timestamp = datetime.datetime.now(datetime.timezone.utc)
            self.assertIsNone(state.checkForFeedLastTimestamp(publisher))
            state.setFeedLastTimestamp(publisher, timestamp)
            self.assertEqual(timestamp, state.checkForFeedLastTimestamp(publisher))

    def test_loading_state(self):
        """Test making and then loading state."""
        publishers: list[str] = list()
        data: list[tuple[str, datetime.datetime]] = list()

        # Generate a bunch of random publishers and give them time stamps
        for i in range(100):
            publisher = str.join("", choices(ascii_letters, k=i + 1))
            publishers.append(publisher)
            data.append((publisher, datetime.datetime.now(datetime.timezone.utc)))

        with TemporaryDirectory() as state_dir:
            # Create a state object and store all the time stamps
            state_create = ReportState(state_dir)
            for d in data:
                state_create.setFeedLastTimestamp(d[0], d[1])

            # Create a new state object and ensure we can load all the values as expected
            state_load = ReportState(state_dir)
            for d in data:
                self.assertEqual(d[1], state_load.checkForFeedLastTimestamp(d[0]))

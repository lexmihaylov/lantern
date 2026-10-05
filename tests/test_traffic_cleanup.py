import signal
import unittest
from unittest.mock import patch

from lantern.libs.cli import _handle_termination_signal
from lantern.libs.traffic_view import _request_traffic_exit, _restore_with_retries


class FakeSession:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.active = True
        self.needs_restore = True
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1
        restored = next(self.outcomes)
        self.active = False
        if restored:
            self.needs_restore = False
        return restored


class TrafficCleanupTests(unittest.TestCase):
    @patch("lantern.libs.cli.signal.signal")
    def test_termination_signals_use_normal_cleanup_unwinding(self, set_signal):
        with self.assertRaises(KeyboardInterrupt):
            _handle_termination_signal(None, None)
        self.assertEqual(set_signal.call_count, 2)
        set_signal.assert_any_call(signal.SIGTERM, signal.SIG_IGN)
        set_signal.assert_any_call(signal.SIGHUP, signal.SIG_IGN)

    @patch("lantern.libs.traffic_view.restoration_failure_modal", return_value="retry")
    def test_failed_exit_restoration_can_retry_without_closing_session(self, prompt):
        session = FakeSession([False, True])

        can_exit = _request_traffic_exit(None, session)

        self.assertTrue(can_exit)
        self.assertEqual(session.stop_calls, 2)
        self.assertFalse(session.needs_restore)
        prompt.assert_called_once()

    @patch("lantern.libs.traffic_view.restoration_failure_modal", return_value="return")
    def test_user_can_return_to_capture_view_with_restore_pending(self, prompt):
        session = FakeSession([False])

        can_exit = _request_traffic_exit(None, session)

        self.assertFalse(can_exit)
        self.assertTrue(session.needs_restore)
        prompt.assert_called_once()

    @patch("lantern.libs.traffic_view.time.sleep")
    def test_final_cleanup_retries_restoration_before_giving_up(self, sleep):
        session = FakeSession([False, False, True])

        restored = _restore_with_retries(session)

        self.assertTrue(restored)
        self.assertEqual(session.stop_calls, 3)
        self.assertEqual(sleep.call_count, 2)


if __name__ == "__main__":
    unittest.main()

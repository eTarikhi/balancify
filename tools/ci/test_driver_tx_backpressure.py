import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICE_BINARY = (ROOT / "crates/service/src/bin/balancify-service.rs").read_text(encoding="utf-8")
DRIVER_DEVICE = (ROOT / "crates/service/src/driver_device.rs").read_text(encoding="utf-8")


class DriverTxBackpressureTests(unittest.TestCase):
    def test_dequeue_retry_policy_covers_unscheduled_outcomes(self):
        self.assertIn("pub fn should_retry_driver_tx(actions: &[super::Action]) -> bool", DRIVER_DEVICE)
        self.assertIn("!actions.iter().any(|action| matches!(action, super::Action::Send { .. }))", DRIVER_DEVICE)
        self.assertIn("driver_tx_retries_when_the_service_did_not_schedule_a_send", DRIVER_DEVICE)
        for outcome in ("Action::Hold", "Action::Refused", "Action::Send"):
            with self.subTest(outcome=outcome):
                self.assertIn(outcome, DRIVER_DEVICE)

    def test_service_retries_pending_packet_before_dequeuing_more(self):
        self.assertIn("let mut pending_driver_tx: Option<Vec<u8>> = None;", SERVICE_BINARY)
        polling = SERVICE_BINARY.split("// Poll a bounded batch from the miniport's driver-owned TX queue", 1)[1]
        polling = polling.split("// Optional synthetic raw-IP traffic", 1)[0]
        self.assertLess(polling.index("pending_driver_tx.take()"), polling.index("device.dequeue_tx()"))
        self.assertIn("if should_retry_driver_tx(&actions)", polling)
        self.assertIn("pending_driver_tx = Some(packet);", polling)
        self.assertIn("if pending_driver_tx.is_none()", polling)
        self.assertIn("let mut budget = 64;", polling)


if __name__ == "__main__":
    unittest.main()

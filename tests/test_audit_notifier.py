import importlib.util
import pathlib
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "src" / "audit_notifier.py"
SPEC = importlib.util.spec_from_file_location("audit_notifier", MODULE_PATH)
audit_notifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(audit_notifier)


class AuditNotifierTests(unittest.TestCase):
    def setUp(self) -> None:
        audit_notifier._dedup.clear()

    def test_ignores_service_account(self) -> None:
        self.assertTrue(
            audit_notifier.ignore_user({"username": "system:serviceaccount:argocd:controller"})
        )

    def test_classifies_exec(self) -> None:
        event = {"verb": "create", "objectRef": {"resource": "pods", "subresource": "exec"}}
        self.assertEqual(audit_notifier.classify(event), ("HIGH", "Shell direto no container"))

    def test_process_event_sends_once(self) -> None:
        event = {
            "stage": "RequestReceived",
            "verb": "create",
            "user": {"username": "junin"},
            "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "apps"},
            "sourceIPs": ["127.0.0.1"],
            "requestReceivedTimestamp": "2026-07-03T00:00:00Z",
        }
        with patch.object(audit_notifier, "send_telegram") as send:
            self.assertTrue(audit_notifier.process_event(event))
            self.assertFalse(audit_notifier.process_event(event))
        send.assert_called_once()


if __name__ == "__main__":
    unittest.main()

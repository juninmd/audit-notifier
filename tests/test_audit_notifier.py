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

    def test_status_subresource_is_noise_in_sensitive_namespace(self) -> None:
        event = {"verb": "update", "objectRef": {"resource": "pods", "subresource": "status", "namespace": "monitoring"}}
        self.assertIsNone(audit_notifier.classify(event))

    def test_pod_write_without_subresource_still_alerts_in_sensitive_namespace(self) -> None:
        event = {"verb": "delete", "objectRef": {"resource": "pods", "namespace": "kube-system"}}
        self.assertEqual(audit_notifier.classify(event), ("MEDIUM", "Escrita em namespace sensivel: pods"))

    def test_watching_secrets_in_sensitive_namespace_alerts_like_a_read(self) -> None:
        event = {"verb": "watch", "objectRef": {"resource": "secrets", "namespace": "argocd"}}
        self.assertEqual(audit_notifier.classify(event), ("HIGH", "secrets lido em namespace sensivel"))

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

    def test_failed_delivery_does_not_suppress_the_next_identical_event(self) -> None:
        event = {
            "stage": "RequestReceived",
            "verb": "create",
            "user": {"username": "junin"},
            "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "apps"},
        }
        with patch.object(audit_notifier, "send_telegram", side_effect=[False, True]) as send:
            self.assertFalse(audit_notifier.process_event(event))  # Telegram down
            self.assertTrue(audit_notifier.process_event(event))  # retried, not deduplicated
        self.assertEqual(send.call_count, 2)


    def test_dedup_prunes_expired_keys_and_keeps_fresh_ones(self) -> None:
        ttl = audit_notifier.DEDUP_TTL
        with patch.object(audit_notifier.time, "monotonic", side_effect=[0.0, 1.0, ttl * 2 + 0.5, ttl * 2 + 0.6]):
            self.assertFalse(audit_notifier.is_duplicate("old"))
            self.assertFalse(audit_notifier.is_duplicate("fresh"))
            self.assertFalse(audit_notifier.is_duplicate("new"))  # prunes "old" only
            self.assertFalse(audit_notifier.is_duplicate("fresh"))  # past TTL: alerts again
        self.assertEqual(list(audit_notifier._dedup), ["new", "fresh"])

    def test_fmt_ts_converts_offsets_to_utc(self) -> None:
        self.assertEqual(audit_notifier.fmt_ts("2026-07-03T10:00:00+03:00"), "03/07 07:00:00 UTC")
        self.assertEqual(audit_notifier.fmt_ts("2026-07-03T10:00:00Z"), "03/07 10:00:00 UTC")

    def test_fmt_ts_tolerates_missing_or_non_string_values(self) -> None:
        self.assertEqual(audit_notifier.fmt_ts(None), "-")
        self.assertEqual(audit_notifier.fmt_ts(123), "-")

    def test_null_timestamp_still_alerts_and_does_not_poison_dedup(self) -> None:
        event = {
            "stage": "RequestReceived",
            "verb": "create",
            "user": {"username": "junin"},
            "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "apps"},
            "requestReceivedTimestamp": None,
        }
        with patch.object(audit_notifier, "send_telegram", return_value=True) as send:
            self.assertTrue(audit_notifier.process_event(event))
        self.assertIn("Quando: -", send.call_args.args[0])


if __name__ == "__main__":
    unittest.main()

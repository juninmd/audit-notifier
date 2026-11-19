import http.client
import importlib.util
import json
import pathlib
import threading
import unittest
from http.server import HTTPServer
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "src" / "audit_notifier.py"
SPEC = importlib.util.spec_from_file_location("audit_notifier_http", MODULE_PATH)
audit_notifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(audit_notifier)

EXEC_EVENT = {
    "stage": "RequestReceived",
    "verb": "create",
    "user": {"username": "junin"},
    "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "apps", "name": "api"},
}


class WebhookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), audit_notifier.AuditHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        audit_notifier._dedup.clear()

    def post(self, body: bytes, headers: dict | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/audit", body=body, headers=headers or {})
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        return response.status, data

    def test_valid_event_list_is_notified(self) -> None:
        with patch.object(audit_notifier, "send_telegram") as send:
            status, data = self.post(json.dumps({"items": [EXEC_EVENT]}).encode())
        self.assertEqual((status, data["notified"]), (200, 1))
        send.assert_called_once()

    def test_non_object_json_is_a_400_not_a_dropped_connection(self) -> None:
        for body in (b"[]", b"null", b'"x"', b'{"items": 5}'):
            status, _ = self.post(body)
            self.assertEqual(status, 400, body)

    def test_invalid_utf8_is_a_400(self) -> None:
        status, data = self.post(b"\xff\xfe")
        self.assertEqual((status, data["error"]), (400, "invalid json"))

    def test_oversized_body_is_rejected_before_reading_it(self) -> None:
        with patch.object(audit_notifier, "MAX_BODY_BYTES", 10):
            status, _ = self.post(b'{"items": []}')
        self.assertEqual(status, 413)

    def test_bad_content_length_is_a_400(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("POST", "/audit")
        conn.putheader("Content-Length", "-5")
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 400)
        conn.close()


if __name__ == "__main__":
    unittest.main()

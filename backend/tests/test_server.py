import json
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from backend.server import Handler


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path, payload=None, origin=None):
        connection = HTTPConnection(*self.server.server_address, timeout=3)
        headers = {"Content-Type": "application/json"}
        if origin:
            headers["Origin"] = origin
        connection.request(
            method, path, json.dumps(payload) if payload is not None else None, headers
        )
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        return response.status, body

    @patch("backend.server.list_audits", return_value=[])
    def test_list_audits(self, listing):
        self.assertEqual(self.request("GET", "/api/audits"), (200, []))

    @patch("backend.server.run_audit")
    def test_authorization_is_required(self, run):
        status, body = self.request(
            "POST", "/api/audits", {"target": "https://example.com"}
        )
        self.assertEqual(status, 400)
        run.assert_not_called()

    @patch("backend.server.run_audit")
    def test_foreign_origin_is_rejected(self, run):
        status, body = self.request("POST", "/api/audits", {}, "https://other.example")
        self.assertEqual(status, 403)
        run.assert_not_called()

    @patch("backend.server.save_audit", side_effect=lambda value: dict(value, id=1))
    @patch("backend.server.run_audit", return_value={"score": 100, "findings": []})
    def test_successful_audit_is_saved(self, run, save):
        status, body = self.request(
            "POST",
            "/api/audits",
            {"target": "https://example.com", "authorized": True, "includeCves": True},
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["id"], 1)
        self.assertNotIn("demo", body)
        run.assert_called_once_with("https://example.com", include_cves=True)

    def test_non_object_payload_is_rejected(self):
        self.assertEqual(self.request("POST", "/api/audits", ["invalid"])[0], 400)

    def test_private_target_is_rejected_without_network_audit(self):
        status, body = self.request(
            "POST", "/api/audits", {"target": "http://127.0.0.1", "authorized": True}
        )
        self.assertEqual(status, 400)
        self.assertIn("publiques", body["error"])

    def test_health_endpoint(self):
        self.assertEqual(self.request("GET", "/api/health"), (200, {"status": "ok"}))

    def test_encoded_static_traversal_is_rejected(self):
        status, body = self.request("GET", "/%2e%2e/%2e%2e/server.py")
        self.assertEqual(status, 403)

    def test_unknown_static_asset_returns_404(self):
        status, body = self.request("GET", "/missing.js")
        self.assertEqual(status, 404)

    @patch("backend.server.run_audit", side_effect=OSError("connection refused"))
    def test_unreachable_target_returns_actionable_error(self, run):
        status, body = self.request(
            "POST", "/api/audits", {"target": "https://example.com", "authorized": True}
        )
        self.assertEqual(status, 502)
        self.assertIn("inaccessible", body["error"])

    @patch("backend.server.save_audit", side_effect=lambda value: dict(value, id=1))
    @patch("backend.server.run_audit", return_value={"score": 100, "findings": []})
    def test_scheme_is_normalized_before_storage(self, run, save):
        status, body = self.request(
            "POST", "/api/audits", {"target": "example.com", "authorized": True}
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["target"], "https://example.com")

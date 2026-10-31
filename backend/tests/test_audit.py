import tempfile
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.audit import parse_target, resolve_public, run_audit
from backend import storage


class TargetTests(unittest.TestCase):
    def test_requires_supported_protocol(self):
        for value in (
            "file:///etc/passwd",
            "ftp://example.com",
            "https://user:secret@example.com",
            "http://example.com:0",
            "http://example.com:70000",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_target(value)

    def test_default_scheme(self):
        self.assertEqual(parse_target("example.com").scheme, "https")

    def test_private_and_mixed_addresses_are_rejected(self):
        for addresses in (
            ["127.0.0.1"],
            ["169.254.169.254"],
            ["::1"],
            ["93.184.216.34", "10.0.0.1"],
        ):
            records = [(2, 1, 6, "", (ip, 0)) for ip in addresses]
            with self.subTest(addresses=addresses), patch(
                "socket.getaddrinfo", return_value=records
            ), self.assertRaises(ValueError):
                resolve_public("example.com")

    @patch(
        "backend.audit.check_port",
        side_effect=lambda address, port: port if port == 6379 else None,
    )
    @patch("backend.audit.PinnedHTTPSConnection")
    @patch("backend.audit.resolve_public", return_value="93.184.216.34")
    def test_audit_flags_exposed_redis_and_missing_headers(
        self, resolve, connection, port
    ):
        response = connection.return_value.getresponse.return_value
        response.getheaders.return_value = [("Content-Type", "text/html")]
        response.status = 200
        result = run_audit("https://example.com")
        self.assertTrue(any(f["severity"] == "critical" for f in result["findings"]))
        self.assertTrue(any(f["title"] == "HSTS absent" for f in result["findings"]))
        self.assertEqual(result["ports"], [{"port": 6379, "service": "Redis"}])
        self.assertEqual(result["score"], 41)

    @patch("backend.audit.check_port", return_value=None)
    @patch("backend.audit.PinnedHTTPSConnection")
    @patch("backend.audit.resolve_public", return_value="93.184.216.34")
    def test_frame_ancestors_replaces_x_frame_options(self, resolve, connection, port):
        connection.return_value.getresponse.return_value.getheaders.return_value = [
            ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("X-Content-Type-Options", "nosniff"),
        ]
        result = run_audit("https://example.com")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["score"], 100)


class StorageTests(unittest.TestCase):
    def test_round_trip_and_latest_first(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(
            storage, "DATABASE", Path(folder) / "audits.sqlite3"
        ):
            first = storage.save_audit(
                {"target": "https://example.com", "findings": []}
            )
            second = storage.save_audit(
                {"target": "https://example.org", "findings": []}
            )
            self.assertEqual(storage.list_audits(), [second, first])


class TlsTests(unittest.TestCase):
    @patch("backend.audit.check_port", return_value=None)
    @patch("backend.audit.PinnedHTTPSConnection")
    @patch("backend.audit.resolve_public", return_value="93.184.216.34")
    def test_invalid_certificate_becomes_a_critical_finding(
        self, resolve, connection, port
    ):
        connection.return_value.request.side_effect = ssl.SSLCertVerificationError(
            "certificate expired"
        )
        audit = run_audit("https://example.com")
        self.assertEqual(audit["tls"], {"valid": False})
        self.assertIsNone(audit["httpStatus"])
        self.assertEqual(audit["findings"][0]["severity"], "critical")
        self.assertEqual(audit["score"], 75)
        self.assertEqual(audit["headers"], {})

    def test_control_characters_and_empty_credentials_are_rejected(self):
        for target in (
            "https://example.com/\r\nInjected: value",
            "https://@example.com",
            "",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                parse_target(target)

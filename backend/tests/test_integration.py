import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from backend import storage
from backend.cli import main
from backend.server import Handler


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.visited.append(self.path)
        self.send_response(302 if self.path == "/redirect" else 200)
        self.send_header(
            "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if self.path == "/redirect":
            self.send_header("Location", "/destination")
        self.end_headers()

    def log_message(self, *args):
        pass


class AuditIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target_server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        cls.target_server.visited = []
        cls.api_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.threads = []
        for server in (cls.target_server, cls.api_server):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target_server, cls.api_server):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.database = patch.object(
            storage, "DATABASE", Path(self.folder.name) / "audits.sqlite3"
        )
        self.database.start()
        self.addCleanup(self.database.stop)
        # Only substitute the DNS boundary: HTTP, TCP, API and SQLite run normally.
        self.resolver = patch("backend.audit.resolve_public", return_value="127.0.0.1")
        self.resolver.start()
        self.addCleanup(self.resolver.stop)
        self.port = self.target_server.server_port
        self.ports = patch.dict("backend.audit.PORTS", {self.port: "HTTP"}, clear=True)
        self.ports.start()
        self.addCleanup(self.ports.stop)
        self.target_server.visited.clear()

    def request(self, method, path, body=None):
        connection = HTTPConnection(*self.api_server.server_address, timeout=5)
        connection.request(
            method,
            path,
            json.dumps(body) if body is not None else None,
            {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        data = json.loads(response.read())
        connection.close()
        return response.status, data

    def test_empty_then_audit_then_persisted_history(self):
        self.assertEqual(self.request("GET", "/api/audits"), (200, []))
        target = f"http://audit.test:{self.port}/"
        status, audit = self.request(
            "POST", "/api/audits", {"target": target, "authorized": True}
        )
        self.assertEqual(status, 201)
        self.assertEqual(audit["httpStatus"], 200)
        self.assertEqual(
            audit["score"], 82
        )  # HTTP (15) and exposed test-server version (3).
        self.assertEqual(audit["ports"], [{"port": self.port, "service": "HTTP"}])
        self.assertEqual(audit["headers"]["x-content-type-options"], "nosniff")
        self.assertEqual(self.request("GET", "/api/audits"), (200, [audit]))
        self.assertEqual(self.target_server.visited, ["/"])

    def test_redirect_is_recorded_but_not_followed(self):
        status, audit = self.request(
            "POST",
            "/api/audits",
            {"target": f"http://audit.test:{self.port}/redirect", "authorized": True},
        )
        self.assertEqual(status, 201)
        self.assertEqual(audit["httpStatus"], 302)
        self.assertEqual(self.target_server.visited, ["/redirect"])

    def test_cli_uses_the_same_audit_and_database(self):
        output = io.StringIO()
        with patch(
            "sys.argv", ["audit", f"http://audit.test:{self.port}/"]
        ), contextlib.redirect_stdout(output):
            result = main()
        self.assertEqual(result, 0)
        audit = json.loads(output.getvalue())
        self.assertEqual(audit["httpStatus"], 200)
        self.assertEqual(storage.list_audits(), [audit])

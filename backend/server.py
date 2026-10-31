import json
import mimetypes
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPException
from pathlib import Path
from urllib.parse import urlsplit, unquote

from backend.audit import parse_target, run_audit
from backend.storage import list_audits, save_audit

FRONTEND = (
    Path(__file__).resolve().parents[1] / "frontend" / "dist" / "dashaudit" / "browser"
)
AUDIT_SLOTS = threading.BoundedSemaphore(2)


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path == "/api/health":
            return self.send_json(200, {"status": "ok"})
        if path == "/api/audits":
            return self.send_json(200, list_audits())
        if path.startswith("/api/"):
            return self.send_json(404, {"error": "Route introuvable."})
        requested = (FRONTEND / path.lstrip("/")).resolve()
        if not requested.is_relative_to(FRONTEND.resolve()):
            return self.send_json(403, {"error": "Accès refusé."})
        if not requested.is_file():
            if requested.suffix:
                return self.send_json(404, {"error": "Fichier introuvable."})
            requested = FRONTEND / "index.html"
        if not requested.exists():
            return self.send_json(
                503, {"error": "Compiler le frontend avec npm run build."}
            )
        body = requested.read_bytes()
        self.send_response(200)
        self.send_header(
            "Content-Type",
            mimetypes.guess_type(str(requested))[0] or "application/octet-stream",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/api/audits":
            return self.send_json(404, {"error": "Route introuvable."})
        if self.headers.get("Origin") and self.headers["Origin"] not in (
            "http://127.0.0.1:4200",
            "http://localhost:4200",
            "http://127.0.0.1:8000",
            "http://localhost:8000",
        ):
            return self.send_json(403, {"error": "Origine refusée."})
        if not AUDIT_SLOTS.acquire(blocking=False):
            return self.send_json(429, {"error": "Deux audits sont déjà en cours."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                raise ValueError("Requête trop longue ou vide.")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict) or not isinstance(
                payload.get("target"), str
            ):
                raise ValueError("La cible doit être une chaîne de caractères.")
            target = payload["target"].strip()
            if not target or len(target) > 250:
                raise ValueError("Indiquer une cible de moins de 250 caractères.")
            if payload.get("authorized") is not True:
                raise ValueError(
                    "Confirmer votre autorisation pour auditer cette cible."
                )
            target = parse_target(target).geturl()
            result = run_audit(target, include_cves=payload.get("includeCves") is True)
            audit = dict(
                target=target, date=datetime.now(timezone.utc).isoformat(), **result
            )
            self.send_json(201, save_audit(audit))
        except (ValueError, TypeError, AttributeError) as error:
            self.send_json(400, {"error": str(error)})
        except (OSError, HTTPException) as error:
            self.send_json(502, {"error": f"Cible inaccessible : {error}"})
        except Exception:
            self.send_json(500, {"error": "L’audit a échoué."})
        finally:
            AUDIT_SLOTS.release()


if __name__ == "__main__":
    print("DashAudit → http://127.0.0.1:8000", flush=True)
    with ThreadingHTTPServer(("127.0.0.1", 8000), Handler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

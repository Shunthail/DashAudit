import concurrent.futures
import http.client
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

from backend.vulnerabilities import lookup_vulnerabilities

PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP alternatif",
}
PENALTIES = {"critical": 25, "high": 15, "medium": 8, "low": 3}
HEADERS = {
    "content-security-policy": (
        "high",
        "Politique de contenu absente",
        "Définir une Content-Security-Policy adaptée au site.",
    ),
    "strict-transport-security": (
        "medium",
        "HSTS absent",
        "Activer Strict-Transport-Security sur les réponses HTTPS.",
    ),
    "x-content-type-options": (
        "low",
        "Protection MIME absente",
        "Ajouter X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        "medium",
        "Protection contre le framing absente",
        "Définir frame-ancestors dans CSP ou X-Frame-Options.",
    ),
}


def parse_target(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 250:
        raise ValueError("Indiquer une cible de moins de 250 caractères.")
    value = value.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("La cible contient des caractères interdits.")
    target = urlsplit(value if "://" in value else "https://" + value)
    if (
        target.scheme not in ("http", "https")
        or not target.hostname
        or target.username is not None
        or target.password is not None
    ):
        raise ValueError("Utiliser une URL HTTP ou HTTPS sans identifiants.")
    if target.port is not None and not 1 <= target.port <= 65535:
        raise ValueError("Le port doit être compris entre 1 et 65535.")
    return target._replace(fragment="")


def resolve_public(host):
    addresses = sorted(
        {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    )
    if not addresses or any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        raise ValueError("La cible doit avoir uniquement des adresses IP publiques.")
    return addresses[0]


def check_port(address, port):
    try:
        with socket.create_connection((address, port), timeout=1):
            return port
    except OSError:
        return None


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Keep TLS verification and SNI while using the IP validated before the request."""

    def __init__(self, host, address, port):
        super().__init__(
            host, port=port, timeout=7, context=ssl.create_default_context()
        )
        self.address = address

    def connect(self):
        connection = socket.create_connection(
            (self.address, self.port), timeout=self.timeout
        )
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except Exception:
            connection.close()
            raise


def run_audit(value, include_cves=False):
    target = parse_target(value)
    host = target.hostname.encode("idna").decode("ascii")
    address = resolve_public(host)
    port = target.port or (443 if target.scheme == "https" else 80)
    findings = []
    tls = None
    headers = {}
    status = None

    def finding(severity, title, detail, category):
        findings.append(
            dict(severity=severity, title=title, detail=detail, category=category)
        )

    connection = (
        PinnedHTTPSConnection(host, address, port)
        if target.scheme == "https"
        else http.client.HTTPConnection(address, port=port, timeout=7)
    )
    host_header = f"[{host}]" if ":" in host else host
    if target.port:
        host_header += f":{target.port}"
    path = quote(target.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if target.query:
        path += "?" + quote(target.query, safe="%=&/?@:!$'()*+,;~-._")
    try:
        connection.request(
            "GET", path, headers={"Host": host_header, "User-Agent": "DashAudit/1.0"}
        )
        if target.scheme == "https":
            tls = {"valid": True}
            if connection.sock:
                protocol = connection.sock.version()
                if isinstance(protocol, str):
                    tls["protocol"] = protocol
                certificate = connection.sock.getpeercert()
                if isinstance(certificate, dict) and certificate.get("notAfter"):
                    expires = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc
                    )
                    tls["expiresAt"] = expires.isoformat()
                    if (expires - datetime.now(timezone.utc)).days < 14:
                        finding(
                            "medium",
                            "Certificat TLS bientôt expiré",
                            "Renouveler le certificat avant son expiration.",
                            "TLS",
                        )
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
    except ssl.SSLCertVerificationError as error:
        tls = {"valid": False}
        finding(
            "critical",
            "Certificat TLS invalide",
            str(getattr(error, "verify_message", "") or error),
            "TLS",
        )
    finally:
        connection.close()

    if target.scheme == "http":
        finding(
            "high",
            "Connexion non chiffrée",
            "Utiliser HTTPS et rediriger les requêtes HTTP.",
            "TLS",
        )
    if status is not None:
        for header, (severity, title, detail) in HEADERS.items():
            if header == "strict-transport-security" and target.scheme != "https":
                continue
            if (
                header == "x-frame-options"
                and "frame-ancestors"
                in headers.get("content-security-policy", "").lower()
            ):
                continue
            if not headers.get(header, "").strip():
                finding(severity, title, detail, "Headers")
        if re.search(r"\d+\.\d+", headers.get("server", "")):
            finding("low", "Version du serveur exposée", headers["server"], "Headers")

    tested_ports = dict(PORTS)
    tested_ports.setdefault(port, "HTTPS" if target.scheme == "https" else "HTTP")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        opened = [
            result
            for result in pool.map(
                lambda number: check_port(address, number), tested_ports
            )
            if result
        ]
    for number in opened:
        if number in (21, 3306, 5432, 6379):
            finding(
                "critical" if number == 6379 else "high",
                f"{PORTS[number]} accessible publiquement",
                f"Port TCP {number} ouvert. Restreindre son accès au réseau autorisé.",
                "Ports",
            )
    candidates, note = (
        lookup_vulnerabilities(headers.get("server", ""))
        if include_cves
        else ([], "Recherche CVE désactivée pour cet audit.")
    )
    return dict(
        findings=findings,
        score=max(0, 100 - sum(PENALTIES[item["severity"]] for item in findings)),
        ports=[
            dict(port=number, service=tested_ports[number]) for number in sorted(opened)
        ],
        httpStatus=status,
        headers=headers,
        address=address,
        tls=tls,
        vulnerabilityCandidates=candidates,
        vulnerabilityNote=note,
    )

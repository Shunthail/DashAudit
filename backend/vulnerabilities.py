import json
import re
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def lookup_vulnerabilities(server):
    """Search NVD by a detected product/version; results require manual verification."""
    match = re.search(r"(nginx|Apache)/(\d+(?:\.\d+){1,3})", server, re.IGNORECASE)
    if not match:
        return (
            [],
            "Recherche CVE non effectuée : aucune version Apache ou nginx identifiable.",
        )
    product, version = match.groups()
    params = urlencode({"keywordSearch": f"{product} {version}", "resultsPerPage": 10})
    request = Request(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?" + params,
        headers={"User-Agent": "DashAudit/1.0", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=8) as response:
            payload = json.load(response)
        candidates = []
        for item in payload.get("vulnerabilities", []):
            cve = item["cve"]
            identifier = cve["id"]
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
                continue
            description = next(
                (
                    text["value"]
                    for text in cve.get("descriptions", [])
                    if text["lang"] == "en"
                ),
                "",
            )
            candidates.append(
                {
                    "id": identifier,
                    "description": description,
                    "url": "https://nvd.nist.gov/vuln/detail/" + identifier,
                }
            )
        return (
            candidates,
            f"NVD : recherche par mots-clés pour {product} {version}. Résultats à vérifier, sans confirmation d’applicabilité et exclus du score. Au plus 10 références.",
        )
    except (URLError, OSError, ValueError, KeyError, TypeError, AttributeError):
        return (
            [],
            "NVD indisponible ou limite de requêtes atteinte. Les autres contrôles restent disponibles.",
        )

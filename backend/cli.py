import argparse
import json
import sys
from http.client import HTTPException
from datetime import datetime, timezone

from backend.audit import parse_target, run_audit
from backend.storage import save_audit


def main():
    parser = argparse.ArgumentParser(
        description="Audit HTTP/TLS et ports TCP d’une cible autorisée."
    )
    parser.add_argument("target")
    parser.add_argument(
        "--cves",
        action="store_true",
        help="Rechercher les références CVE NVD de la version exposée.",
    )
    args = parser.parse_args()
    target = args.target
    try:
        target = parse_target(target).geturl()
        result = run_audit(target, include_cves=args.cves)
        audit = save_audit(
            dict(target=target, date=datetime.now(timezone.utc).isoformat(), **result)
        )
        print(json.dumps(audit, indent=2, ensure_ascii=False))
        return (
            2
            if any(item["severity"] == "critical" for item in audit["findings"])
            else 0
        )
    except (ValueError, OSError, HTTPException) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

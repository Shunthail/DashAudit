import io
import json
import unittest
from unittest.mock import patch
from urllib.error import URLError

from backend.vulnerabilities import lookup_vulnerabilities


class VulnerabilityTests(unittest.TestCase):
    @patch("backend.vulnerabilities.urlopen")
    def test_unknown_version_does_not_query_nvd(self, request):
        candidates, note = lookup_vulnerabilities("nginx")
        request.assert_not_called()
        self.assertEqual(candidates, [])
        self.assertIn("aucune version", note)

    @patch("backend.vulnerabilities.urlopen")
    def test_nvd_results_remain_unconfirmed(self, request):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-12345",
                        "descriptions": [
                            {"lang": "en", "value": "Example vulnerability."}
                        ],
                    }
                }
            ]
        }
        request.return_value.__enter__.return_value = io.StringIO(json.dumps(payload))
        candidates, note = lookup_vulnerabilities("nginx/1.20.1")
        self.assertEqual(candidates[0]["id"], "CVE-2024-12345")
        self.assertIn("sans confirmation", note)
        self.assertIn("keywordSearch=nginx+1.20.1", request.call_args.args[0].full_url)

    @patch("backend.vulnerabilities.urlopen", side_effect=URLError("offline"))
    def test_nvd_failure_is_reported_without_stopping_audit(self, request):
        candidates, note = lookup_vulnerabilities("Apache/2.4.49")
        self.assertEqual(candidates, [])
        self.assertIn("indisponible", note)

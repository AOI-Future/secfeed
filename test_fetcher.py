import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fetcher import SecurityDB


class ThreatSummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = SecurityDB(str(Path(self.tmpdir.name) / "secfeed.db"))

    def tearDown(self):
        self.tmpdir.cleanup()

    def _insert_kev(self, cve_id: str, date_added: str) -> None:
        self.db.upsert_vulnerability({
            "id": cve_id,
            "source": "cisa_kev",
            "title": f"Test KEV {cve_id}",
            "description": "fixture",
            "severity": "CRITICAL",
            "published_at": date_added,
            "in_cisa_kev": 1,
        })

    def test_summary_separates_total_from_recent_kev_additions(self):
        today = datetime.now(timezone.utc).date().isoformat()
        old = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        self._insert_kev("CVE-2099-0001", today)
        self._insert_kev("CVE-2099-0002", old)

        summary = self.db.get_summary()

        self.assertEqual(summary["cisa_kev_total"], 2)
        self.assertEqual(summary["new_cisa_kev_24h"], 1)
        self.assertEqual(
            summary["new_cisa_kev_items"],
            [{
                "id": "CVE-2099-0001",
                "title": "Test KEV CVE-2099-0001",
                "date_added": today,
            }],
        )

    def test_refetch_does_not_make_old_kev_new_again(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        self._insert_kev("CVE-2099-0003", old)
        self._insert_kev("CVE-2099-0003", old)

        summary = self.db.get_summary()

        self.assertEqual(summary["cisa_kev_total"], 1)
        self.assertEqual(summary["new_cisa_kev_24h"], 0)
        self.assertEqual(summary["new_cisa_kev_items"], [])


if __name__ == "__main__":
    unittest.main()

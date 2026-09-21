import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

# Avoid default /data path when importing server in tests
os.environ.setdefault("SECFEED_DB_PATH", str(Path(tempfile.gettempdir()) / "secfeed-test-server.db"))

import server  # noqa: E402
from fetcher import SecurityDB  # noqa: E402


class GetCveDetailCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.test_db = SecurityDB(str(Path(self.tmpdir.name) / "secfeed.db"))
        self._orig_db = server.db
        server.db = self.test_db
        self.fetch_mock = AsyncMock(
            return_value={"id": "CVE-2099-0100", "description": "from-nvd"}
        )
        self._fetch_patcher = patch.object(
            server.fetcher, "fetch_cve_detail", self.fetch_mock
        )
        self._fetch_patcher.start()

    def tearDown(self):
        self._fetch_patcher.stop()
        server.db = self._orig_db
        self.tmpdir.cleanup()

    def _run(self, coro):
        return asyncio.run(coro)

    def test_cache_hit_skips_nvd(self):
        self.test_db.upsert_vulnerability({
            "id": "CVE-2099-0100",
            "source": "nvd",
            "title": "CVE-2099-0100",
            "description": "cached body",
            "severity": "HIGH",
        })

        raw = self._run(server.get_cve_detail("CVE-2099-0100"))
        data = json.loads(raw)

        self.fetch_mock.assert_not_called()
        self.assertEqual(data["description"], "cached body")

    def test_refresh_bypasses_cache(self):
        self.test_db.upsert_vulnerability({
            "id": "CVE-2099-0100",
            "source": "nvd",
            "title": "CVE-2099-0100",
            "description": "cached body",
            "severity": "HIGH",
        })

        raw = self._run(server.get_cve_detail("CVE-2099-0100", refresh=True))

        self.fetch_mock.assert_awaited_once_with("CVE-2099-0100")
        self.assertIn("from-nvd", raw)

    def test_nvd_failure_falls_back_to_cache(self):
        self.test_db.upsert_vulnerability({
            "id": "CVE-2099-0100",
            "source": "nvd",
            "title": "CVE-2099-0100",
            "description": "cached body",
            "severity": "HIGH",
        })
        self.fetch_mock.reset_mock()
        self.fetch_mock.return_value = None

        raw = self._run(server.get_cve_detail("CVE-2099-0100", refresh=True))
        data = json.loads(raw)

        self.assertEqual(data["description"], "cached body")
        self.assertIn("local cache", data.get("_note", ""))


if __name__ == "__main__":
    unittest.main()

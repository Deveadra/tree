import unittest
from pathlib import Path
from unittest.mock import patch

from core import service


class FindDuplicatesFacadeTests(unittest.TestCase):
    def test_compare_mode_is_not_forwarded_to_dupe_core(self):
        captured = {}

        def fake_find_dupes_from_db(**kwargs):
            captured.update(kwargs)
            return []

        with patch("core.hash_index.find_dupes_from_db", side_effect=fake_find_dupes_from_db):
            result = service.find_duplicates(
                db_path=Path("dupes.db"),
                cancel_flag=lambda: False,
                metrics_cb=lambda _metrics: None,
                compare_mode=True,
                error_log_path=Path("errors.log"),
                required_roots=(0, 1),
            )

        self.assertEqual(result, [])
        self.assertNotIn("compare_mode", captured)
        self.assertEqual(captured["required_roots"], (0, 1))


if __name__ == "__main__":
    unittest.main()

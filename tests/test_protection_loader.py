import os
import tempfile
import unittest
from pathlib import Path

from config.protection_loader import resolve_protection_config


class ProtectionLoaderTests(unittest.TestCase):
    def test_precedence_and_merge(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "protection.toml"
            path.write_text(
                """
enforce_safe_delete_roots = true
protected_prefixes = ["D:\\\\data"]
protected_dir_names = ["Secret"]
safe_delete_roots = ["D:\\\\trash"]
""",
                encoding="utf-8",
            )
            os.environ["DUPES_PROTECTED_PREFIXES"] = r"E:\\more"
            os.environ["DUPES_SAFE_DELETE_ROOTS"] = r"E:\\safe"
            cfg = resolve_protection_config(path)

        self.assertIn(r"c:\windows", cfg.protected_prefixes)
        self.assertIn(r"d:\data", cfg.protected_prefixes)
        self.assertIn(r"e:\more", cfg.protected_prefixes)
        self.assertEqual(cfg.safe_delete_roots, [r"e:\safe"])
        self.assertIn("secret", cfg.protected_dir_names)
        del os.environ["DUPES_PROTECTED_PREFIXES"]
        del os.environ["DUPES_SAFE_DELETE_ROOTS"]

    def test_warning_when_safe_roots_missing(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "protection.toml"
            path.write_text("enforce_safe_delete_roots = true\nsafe_delete_roots = []\n", encoding="utf-8")
            cfg = resolve_protection_config(path)
        self.assertTrue(any("safe_delete_roots missing" in w for w in cfg.warnings))


if __name__ == "__main__":
    unittest.main()

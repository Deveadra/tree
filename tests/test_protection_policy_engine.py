from pathlib import Path
import unittest

from core.protection_policy import (
    contains_protected_dir_name,
    evaluate_delete_permission,
    is_under_protected_prefix,
    is_within_safe_delete_roots,
)


class ProtectionPolicyEngineUnitTests(unittest.TestCase):
    def test_protected_prefix_block(self):
        blocked = is_under_protected_prefix(
            r"C:/Windows/System32/drivers/etc/hosts",
            protected_prefixes=[r"c:\\windows"],
        )
        self.assertEqual(blocked, r"c:\windows")

        perm = evaluate_delete_permission(
            r"C:/Windows/System32/drivers/etc/hosts",
            mode="recycle",
            action_type="delete",
            safe_roots=[Path(r"C:/")],
        )
        self.assertFalse(perm["allow"])
        self.assertEqual(perm["reason_code"], "protected_prefix")

    def test_protected_dir_name_block(self):
        part = contains_protected_dir_name(
            r"D:/Users/alice/Program Files/App/data.bin",
            protected_dir_names=["program files"],
        )
        self.assertEqual(part.lower(), "program files")

        perm = evaluate_delete_permission(
            r"D:/Users/alice/Program Files/App/data.bin",
            mode="recycle",
            action_type="delete",
            safe_roots=[Path(r"D:/")],
            policy=None,
        )
        self.assertFalse(perm["allow"])
        self.assertEqual(perm["reason_code"], "protected_dir_name")

    def test_safe_delete_root_allow_and_deny(self):
        roots = [Path(r"E:/safe")]
        self.assertTrue(is_within_safe_delete_roots(r"E:/safe/a.txt", safe_roots=roots))
        self.assertFalse(is_within_safe_delete_roots(r"E:/outside/a.txt", safe_roots=roots))

        allow = evaluate_delete_permission(
            r"E:/safe/a.txt",
            mode="recycle",
            action_type="delete",
            safe_roots=roots,
        )
        deny = evaluate_delete_permission(
            r"E:/outside/a.txt",
            mode="recycle",
            action_type="delete",
            safe_roots=roots,
        )
        self.assertTrue(allow["allow"])
        self.assertEqual(allow["reason_code"], "allowed")
        self.assertFalse(deny["allow"])
        self.assertEqual(deny["reason_code"], "outside_safe_roots")

    def test_normalization_edge_cases_windows_path_forms(self):
        prefix = is_under_protected_prefix(
            r"C:\\foo\\bar\\baz.txt",
            protected_prefixes=[r"c:/foo/"],
        )
        self.assertEqual(prefix, r"c:\foo")


if __name__ == "__main__":
    unittest.main()

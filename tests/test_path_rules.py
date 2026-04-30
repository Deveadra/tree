import unittest

from config.path_rules import canonicalize_path, evaluate_rules, match_pattern, validate_rule_inputs


class PathRuleTests(unittest.TestCase):
    def test_trailing_slash_equivalence(self):
        self.assertEqual(canonicalize_path(r"C:\foo").canonical, canonicalize_path(r"C:\foo\\").canonical)

    def test_case_variants(self):
        self.assertTrue(match_pattern(r"C:\Foo\Bar", r"c:\foo"))

    def test_drive_root_handling(self):
        self.assertTrue(match_pattern(r"C:\foo", r"C:"))

    def test_mixed_slashes(self):
        self.assertTrue(match_pattern(r"C:/foo/bar", r"C:\foo"))

    def test_glob_pathspec(self):
        self.assertTrue(match_pattern(r"C:\foo\bar\a.txt", r"C:\foo\**\*.txt"))

    def test_precedence_exclude_wins(self):
        allowed, reason = evaluate_rules(r"C:\foo\secret.txt", [r"C:\foo\**"], [r"C:\foo\secret*"])
        self.assertFalse(allowed)
        self.assertIn("excluded", reason)

    def test_validation_warnings(self):
        warns = validate_rule_inputs([r"C:bad", r"%DOES_NOT_EXIST%\\x"])
        self.assertGreaterEqual(len(warns), 2)


if __name__ == "__main__":
    unittest.main()

import unittest

try:
    from checks.scanner import TargetScopeError, _validate_url, calculate_score
except ModuleNotFoundError:  # Optional runtime dependencies may be absent in a bare checkout.
    TargetScopeError = None
    _validate_url = None
    calculate_score = None


@unittest.skipIf(_validate_url is None, "Dependencias del escáner no instaladas")
class ScannerSafetyTests(unittest.TestCase):
    def test_rejects_credentials_in_url(self):
        with self.assertRaises(TargetScopeError):
            _validate_url("https://user:password@example.com", check_public=False)

    def test_missing_best_practice_warnings_do_not_zero_score(self):
        findings = [
            {"status": "warn", "severity": "medium"},
            {"status": "warn", "severity": "medium"},
            {"status": "warn", "severity": "low"},
        ]
        self.assertGreaterEqual(calculate_score(findings), 75)


if __name__ == "__main__":
    unittest.main()

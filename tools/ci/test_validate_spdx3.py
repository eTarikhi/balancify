import contextlib
import io
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from validate_spdx3 import SPDX_VERSION, main, validate_document


class ValidateSpdx3Tests(unittest.TestCase):
    def test_validation_result_controls_success_and_pins_spec_version(self):
        calls = []

        class Result:
            def __init__(self, valid, details=""):
                self.valid = valid
                self.details = details

            def __bool__(self):
                return self.valid

            def __str__(self):
                return self.details

        def fake_validate(source, *, version):
            calls.append((source, version))
            return Result(True)

        module = types.SimpleNamespace(validate=fake_validate)
        with patch.dict(sys.modules, {"spdx3_validate": module}):
            valid, details = validate_document(Path("sbom.spdx3.json"))

        self.assertTrue(valid)
        self.assertEqual(details, "")
        self.assertEqual(calls, [("sbom.spdx3.json", SPDX_VERSION)])

    def test_reported_schema_errors_are_failures_even_without_exceptions(self):
        class InvalidResult:
            def __bool__(self):
                return False

            def __str__(self):
                return "software_sbomType must be an array"

        module = types.SimpleNamespace(validate=lambda source, *, version: InvalidResult())
        with patch.dict(sys.modules, {"spdx3_validate": module}):
            valid, details = validate_document(Path("sbom.spdx3.json"))

        self.assertFalse(valid)
        self.assertIn("software_sbomType must be an array", details)

    def test_main_exits_nonzero_when_the_validator_reports_findings(self):
        class InvalidResult:
            def __bool__(self):
                return False

            def __str__(self):
                return "schema finding"

        module = types.SimpleNamespace(validate=lambda source, *, version: InvalidResult())
        stderr = io.StringIO()
        with patch.dict(sys.modules, {"spdx3_validate": module}), contextlib.redirect_stderr(stderr):
            exit_code = main(["sbom.spdx3.json"])

        self.assertEqual(exit_code, 1)
        self.assertIn("schema finding", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

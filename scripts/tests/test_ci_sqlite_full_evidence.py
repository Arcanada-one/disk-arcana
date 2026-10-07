"""Accounting/CI contract controls only; no Cargo or SQLite suite execution."""
import importlib.util
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sqlite_evidence", ROOT / "scripts/ci-sqlite-full-evidence.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NAMES = sorted(name for names in module.TESTS.values() for name in names)


def output():
    return "".join(
        "+ cargo test -p disk-personal-sqlite --locked " + mode + " -- --include-ignored\n"
        + "".join("test " + name + " ... ok\n" for name in NAMES)
        + "test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n"
        for mode in module.MODES)


class AccountingControls(unittest.TestCase):
    def test_exact_two_complete_positive_modes(self):
        self.assertEqual(set(module.validate_output(output(), NAMES)), set(module.MODES))

    def test_missing_duplicate_or_foreign_test_refuses(self):
        for text in (output().replace("test " + NAMES[0] + " ... ok\n", "", 1),
                     output().replace("test " + NAMES[0], "test " + NAMES[1], 1),
                     output().replace("test " + NAMES[0], "test foreign", 1)):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                module.validate_output(text, NAMES)

    def test_ignored_failed_or_filtered_refuses(self):
        for text in (output().replace("... ok", "... ignored", 1),
                     output().replace("... ok", "... FAILED", 1),
                     output().replace("0 filtered out", "1 filtered out", 1),
                     output().replace("0 ignored", "1 ignored", 1)):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                module.validate_output(text, NAMES)

    def test_zero_or_inconsistent_count_refuses(self):
        for count in ("0", "6", "8"):
            with self.subTest(count=count), self.assertRaises(ValueError):
                module.validate_output(output().replace("7 passed", count + " passed", 1), NAMES)

    def test_weaker_duplicate_or_reordered_modes_refuse(self):
        for text in (output().replace("--include-ignored", "", 1),
                     output().replace("--locked", "", 1),
                     output().replace("--no-default-features", "--all-features", 1),
                     output().replace("--no-default-features", "TEMP").replace("--all-features", "--no-default-features").replace("TEMP", "--all-features")):
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                module.validate_output(text, NAMES)

    def test_extra_child_command_refuses(self):
        with self.assertRaises(ValueError):
            module.validate_output(output() + "+ cargo test -p another\n", NAMES)

    def test_source_has_exact_seven_declarations(self):
        self.assertEqual(len(NAMES), 7)
        for path, names in module.TESTS.items():
            text = (ROOT / module.PACKAGE / path).read_text()
            self.assertEqual(text.count("#[test]"), len(names))
            for name in names:
                self.assertIn("fn " + name.split("::")[-1] + "()", text)

    def test_workflow_exact_declared_group_and_status_contract(self):
        document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = document["jobs"]["sqlite-abi-full"]
        self.assertEqual(job["runs-on"], ["arcana-dbs-ci"])
        self.assertEqual(job["timeout-minutes"], 40)
        step = next(s for s in job["steps"] if s.get("name") == "Verify the declared SQLite ABI FULL group")
        body = step["run"]
        self.assertNotIn("continue-on-error", step)
        self.assertNotIn("if", step)
        self.assertIn("cd crates/disk-personal/sqlite-abi", body)
        self.assertIn("timeout --signal=TERM --kill-after=10s 1800s python3 ../../../scripts/full-test-group.py disk-personal-sqlite", body)
        self.assertIn('exit "$sqlite_full_exit"', body)
        self.assertIn('SQLITE_FULL_PROCESS_EXIT=%s', body)
        self.assertIn('ci-sqlite-full-evidence.py verify', body)


if __name__ == "__main__":
    unittest.main()

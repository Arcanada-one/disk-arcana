"""Contract: build-macos-client must target the org mac-release self-hosted pool.

Reads the committed workflow file in this tree (not a moving git ref).
"""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-deploy.yml"
EXPECTED_LABELS = ["self-hosted", "macOS", "ARM64", "mac-release"]
FORBIDDEN_HOSTED = {"macos-14", "macos-15", "macos-latest", "ubuntu-latest", "windows-latest"}


class MacosClientRunnerLabels(unittest.TestCase):
    def test_build_macos_client_uses_mac_release_labels(self):
        document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        job = document["jobs"]["build-macos-client"]
        runs_on = job["runs-on"]
        self.assertIsInstance(runs_on, list)
        self.assertEqual(runs_on, EXPECTED_LABELS)
        for label in runs_on:
            self.assertNotIn(label, FORBIDDEN_HOSTED)

    def test_workflow_text_has_no_github_hosted_macos_for_client_job(self):
        import re

        text = WORKFLOW.read_text(encoding="utf-8")
        # Job keys under `jobs:` are indented exactly two spaces.
        match = re.search(
            r"(?ms)^  build-macos-client:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
            text,
        )
        self.assertIsNotNone(match)
        block = match.group(0)
        self.assertIn("runs-on:", block)
        for hosted in ("macos-14", "macos-15", "macos-latest"):
            self.assertNotIn(f"runs-on: {hosted}", block)


if __name__ == "__main__":
    unittest.main()

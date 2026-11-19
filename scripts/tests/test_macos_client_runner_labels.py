"""Contract: build-macos-client must target the org mac-release self-hosted pool.

Reads the committed workflow file in this tree (not a moving git ref).
"""
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-deploy.yml"
ACTIONLINT = ROOT / ".github" / "actionlint.yaml"
EXPECTED_LABELS = ["self-hosted", "macOS", "ARM64", "mac-release"]
FORBIDDEN_HOSTED = {"macos-14", "macos-15", "macos-latest", "ubuntu-latest", "windows-latest"}
FORK_DENY = "github.event.pull_request.head.repo.full_name == github.repository"


def _macos_client_job_block(text: str) -> str:
    match = re.search(
        r"(?ms)^  build-macos-client:\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        text,
    )
    assert match is not None, "build-macos-client job missing"
    return match.group(0)


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
        text = WORKFLOW.read_text(encoding="utf-8")
        block = _macos_client_job_block(text)
        self.assertIn("runs-on:", block)
        for hosted in ("macos-14", "macos-15", "macos-latest"):
            self.assertNotIn(f"runs-on: {hosted}", block)

    def test_actionlint_allowlists_mac_release_labels(self):
        text = ACTIONLINT.read_text(encoding="utf-8")
        for label in ("macOS", "ARM64", "mac-release"):
            self.assertRegex(text, rf"(?m)^    - {label}$")

    def test_build_macos_client_has_job_level_fork_deny(self):
        document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        condition = document["jobs"]["build-macos-client"].get("if", "")
        self.assertIn(FORK_DENY, condition)

    def test_build_macos_client_has_always_keychain_teardown(self):
        block = _macos_client_job_block(WORKFLOW.read_text(encoding="utf-8"))
        self.assertRegex(
            block,
            r"(?ms)if:\s*always\(\)[\s\S]{0,800}delete-keychain",
        )
        self.assertIn("disk-sign.keychain", block)


if __name__ == "__main__":
    unittest.main()

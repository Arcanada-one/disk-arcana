"""Offline causal receiver fixtures; no real CI, FULL, tool or syscall execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("personal_reuse", ROOT / "scripts/ci-personal-job-reuse.py")
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


def inputs():
    current = {"repository": reuse.REPOSITORY, "head": "a" * 40, "tree": "b" * 40,
               "closure": {"sha256": "c" * 64, "excluded_paths": [], "count": 20},
               "tool_environment_binding": {"complete": True, "tools": {"rustc": "actual-fixture-hash"}},
               "receiver_policy_sha256": "d" * 64, "workflow_sha256": "e" * 64,
               "declared_argv": reuse.COMMAND, "cwd": reuse.DEP, "features": reuse.MODES,
               "timeout_seconds": 1800}
    identity = {"source_commit": "f" * 40, "checkout_commit": "f" * 40,
                "run_id": 10, "job_id": 11, "run_attempt": 1}
    evidence = {**identity, "schema": "GitHubFullSuiteEvidence/v1",
                "scope": "global_fallback_full_suite", "repository": reuse.REPOSITORY,
                "deployable": reuse.DEP, "command": reuse.COMMAND,
                "log": {"sha256": "sha256:" + "9" * 64}}
    manifest = {**copy.deepcopy(current), "schema": "PersonalJobExecution/v1",
                "tests_executed_now": True, "suite_exit": 0, "current_steps_success": True,
                "prior_identity": identity, "head": identity["source_commit"]}
    proof = {**identity, "verdict": "verified", "errors": [],
             "log_sha256": evidence["log"]["sha256"]}
    return current, manifest, evidence, proof


class ReceiverControls(unittest.TestCase):
    def test_complete_authenticated_fixture_hit(self):
        current, manifest, evidence, proof = inputs()
        reuse.validate_reuse(current, manifest, evidence, proof)
        with patch.object(reuse, "snapshot", return_value=(current, b"fixture")):
            decision = reuse.select(ROOT, lambda *_: (evidence, manifest), lambda *_: proof)
        self.assertEqual(decision["mode"], "reuse")

    def test_old_missing_manifest_cold(self):
        current, _, _, _ = inputs()
        def absent(*_):
            raise ValueError("manifest missing or expired")
        with patch.object(reuse, "snapshot", return_value=(current, b"fixture")):
            self.assertEqual(reuse.select(ROOT, absent)["mode"], "execute")

    def test_authenticated_artifact_missing_or_stale_is_cold(self):
        current, _, evidence, _ = inputs()
        for artifacts in ([], [{"name": "personal-job-reuse-10-1", "expired": True}]):
            with patch.object(reuse, "git", return_value=json.dumps(evidence).encode()), \
                 patch.object(reuse.subprocess, "check_output", return_value=json.dumps({"artifacts": artifacts}).encode()), \
                 self.assertRaisesRegex(ValueError, "absent or retention-stale"):
                reuse.read_prior(ROOT, current)

    def test_manifest_source_and_checkout_must_match(self):
        current, manifest, evidence, proof = inputs()
        with self.assertRaisesRegex(ValueError, "manifest source/checkout"):
            reuse.validate_reuse(current, {**manifest, "head": "0" * 40}, evidence, proof)

    def test_malformed_prior_is_cold_not_success(self):
        current, manifest, evidence, proof = inputs()
        with patch.object(reuse, "snapshot", return_value=(current, b"fixture")):
            for malformed in ([], None, {**manifest, "tool_environment_binding": "bad"}):
                with self.subTest(malformed=malformed):
                    self.assertEqual(reuse.select(ROOT, lambda *_: (evidence, malformed), lambda *_: proof)["mode"], "execute")

    def test_unknown_environment_cold_before_authentication(self):
        current, _, _, _ = inputs()
        current["tool_environment_binding"]["complete"] = False
        with patch.object(reuse, "snapshot", return_value=(current, b"fixture")):
            result = reuse.select(ROOT, lambda *_: self.fail("unknown env consulted prior job"))
        self.assertEqual(result["mode"], "execute")

    def test_every_fingerprint_dimension_is_required(self):
        current, manifest, evidence, proof = inputs()
        for key in ("repository", "closure", "tool_environment_binding", "receiver_policy_sha256",
                    "workflow_sha256", "declared_argv", "cwd", "features", "timeout_seconds"):
            changed = copy.deepcopy(manifest)
            changed[key] = "changed"
            with self.subTest(key=key), self.assertRaises((ValueError, AttributeError)):
                reuse.validate_reuse(current, changed, evidence, proof)

    def test_unknown_prior_schema_or_environment_refuses(self):
        current, manifest, evidence, proof = inputs()
        for key, value in (("schema", "unknown"), ("tests_executed_now", False),
                           ("suite_exit", 1), ("current_steps_success", False),
                           ("tool_environment_binding", {"complete": False})):
            changed = {**manifest, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                reuse.validate_reuse(current, changed, evidence, proof)

    def test_wrong_source_job_attempt_repository_or_log_refuses(self):
        current, manifest, evidence, proof = inputs()
        for key in ("source_commit", "checkout_commit", "run_id", "job_id", "run_attempt", "repository", "schema"):
            changed = {**evidence, key: "wrong"}
            with self.subTest(key=key), self.assertRaises(ValueError):
                reuse.validate_reuse(current, manifest, changed, proof)
        with self.assertRaises(ValueError):
            reuse.validate_reuse(current, manifest, {**evidence, "log": {"sha256": "edited"}}, proof)

    def test_canonical_failure_skip_incomplete_or_absent_refuses(self):
        current, manifest, evidence, proof = inputs()
        for result in ({}, {**proof, "verdict": "failed"}, {**proof, "verdict": "not_measured"},
                       {**proof, "errors": ["skipped"]}, {**proof, "job_id": 12}):
            with self.subTest(result=result), self.assertRaises(ValueError):
                reuse.validate_reuse(current, manifest, evidence, result)

    def test_production_bundle_absence_is_not_an_override(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "not installed"):
                reuse.canonical_proof(Path(directory), inputs()[0], inputs()[2])

    def test_unknown_environment_never_exposes_values(self):
        with patch.dict(os.environ, {"PATH": "/safe", "UNREVIEWED_TOKEN": "secret-fixture"}, clear=True):
            binding = reuse.environment_binding()
        self.assertFalse(binding["complete"])
        self.assertNotIn("secret-fixture", json.dumps(binding))

    def test_final_status_never_green_on_failed_cancelled_or_skipped(self):
        current, _, _, _ = inputs()
        decision = {"schema": "PersonalJobReuse/v1", "mode": "execute", "current": current}
        guard = {"schema": "PersonalCurrentCapability/v1", "head": current["head"],
                 "success": True, "errno": 0, "resolve": 13, "syscall": 437,
                 "system": "Linux", "machine": "x86_64", "job": "personal-provider",
                 "run_id": "10", "attempt": "1"}
        good = {k: {"outcome": "success"} for k in ["selector", "guard", *reuse.REQUIRED_EXECUTE]}
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1"}):
            reuse.final_status(decision, guard, good, suite_exit=0)
            for key in good:
                for status in ("failure", "cancelled", "skipped", "unknown"):
                    with self.subTest(key=key, status=status), self.assertRaises(ValueError):
                        reuse.final_status(decision, guard, {**good, key: {"outcome": status}}, suite_exit=0)
            for wrong in ({**guard, "head": "0" * 40}, {**guard, "resolve": 0},
                          {**guard, "success": False, "errno": 38}, {**guard, "attempt": "0"}):
                with self.assertRaises(ValueError):
                    reuse.final_status(decision, wrong, good, suite_exit=0)
            with self.assertRaises(ValueError):
                reuse.final_status({}, guard, good, suite_exit=0)

    def test_reuse_receiving_record_must_match_current_decision(self):
        current, _, evidence, _ = inputs()
        decision = {"schema": "PersonalJobReuse/v1", "mode": "reuse", "current": current, "prior": evidence}
        guard = {"schema": "PersonalCurrentCapability/v1", "head": current["head"],
                 "success": True, "errno": 0, "resolve": 13, "syscall": 437,
                 "system": "Linux", "machine": "x86_64", "job": "personal-provider",
                 "run_id": "10", "attempt": "1"}
        record = {"schema": "PersonalJobReuse/v1", "mode": "REUSED_PRIOR_COMPLETED_JOB",
                  "tests_executed_now": False, "current_head": current["head"],
                  "current_closure_sha256": current["closure"]["sha256"],
                  "current_capability_observation": guard, "canonical_record_delta_verdict": "verified"}
        for key, prior in (("prior_source_commit", "source_commit"), ("prior_checkout_commit", "checkout_commit"),
                           ("prior_run_id", "run_id"), ("prior_job_id", "job_id"), ("prior_run_attempt", "run_attempt")):
            record[key] = evidence[prior]
        steps = {k: {"outcome": "skipped"} for k in reuse.REQUIRED_EXECUTE}
        steps.update({k: {"outcome": "success"} for k in ("selector", "guard", "reuse")})
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1"}):
            reuse.final_status(decision, guard, steps, record)
            for key in record:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    reuse.final_status(decision, guard, steps, {**record, key: None})
            with self.assertRaises(ValueError):
                reuse.final_status(decision, guard, {**steps, "toolchain": {"outcome": "failure"}}, record)

    def test_current_syscall_flags_and_errno_preserved(self):
        seen = []
        def syscall(number, root, path, how, size):
            seen.append((number, how._obj.resolve, how._obj.flags))
            reuse.ctypes.set_errno(38)
            return -1
        with patch.object(reuse, "git", return_value=b"a" * 40), \
             patch.object(reuse.platform, "machine", return_value="x86_64"), \
             patch.object(reuse.platform, "system", return_value="Linux"), \
             patch.object(reuse.os, "open", return_value=100), patch.object(reuse.os, "close"), \
             patch.object(reuse.ctypes, "CDLL") as libc:
            libc.return_value.syscall.side_effect = syscall
            guard = reuse.current_guard(ROOT)
        self.assertEqual(guard["errno"], 38)
        self.assertFalse(guard["success"])
        self.assertEqual(seen[0][:2], (437, 13))
        self.assertTrue(seen[0][2] & os.O_NOFOLLOW)

    def test_full_tree_closure_tracks_transitive_files_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-c", "commit.gpgsign=false", "-C", str(root), *args], stderr=subprocess.DEVNULL)
            git("init")
            for path in ("Cargo.lock", "member/Cargo.toml", "workflow.yml", "receipts/proof.json"):
                p = root / path
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("original")
            git("add", ".")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
            first, raw = reuse.closure(root, "HEAD")
            self.assertEqual(first["count"], 4)
            self.assertIn(b"member/Cargo.toml\0", raw)
            for path in ("Cargo.lock", "member/Cargo.toml", "workflow.yml", "receipts/proof.json"):
                (root / path).write_text("changed")
                git("add", path)
                tree = git("write-tree").decode().strip()
                self.assertNotEqual(reuse.closure(root, tree)[0]["sha256"], first["sha256"])
            (root / "alias").symlink_to("Cargo.lock")
            git("add", "alias")
            with self.assertRaises(ValueError):
                reuse.closure(root, git("write-tree").decode().strip())

    def test_workflow_retains_unconditional_job_guard_and_final_status(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        job = text.split("  personal-provider:\n", 1)[1].split("  lint:\n", 1)[0]
        self.assertIn("name: Personal provider foundation (Rust 1.97.1)", job)
        self.assertIn("runs-on: [arcana-dbs-ci]", job)
        self.assertIn("timeout-minutes: 55", job)
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("paths-ignore", text)
        self.assertIn("id: guard\n        if: always()\n        run: python3 -B scripts/ci-personal-job-reuse.py guard", job)
        self.assertIn("id: receiving_verdict\n        if: always()", job)
        self.assertEqual(job.count("if: steps.selector.outputs.mode == 'execute'"), 4)
        self.assertIn("timeout --signal=TERM --kill-after=10s 1800s python3 ../../scripts/full-test-group.py disk-personal", job)
        self.assertIn("exit \"$personal_full_exit\"", job)


if __name__ == "__main__":
    unittest.main()

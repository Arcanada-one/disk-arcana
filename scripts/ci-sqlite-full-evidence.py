#!/usr/bin/env python3
"""Bind the declared SQLite FULL group to source and complete test inventories.

This helper never runs Cargo, a suite, a binary, or storage. Synthetic output
fixtures validate accounting only; CI supplies the real bounded runner output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "crates/disk-personal/sqlite-abi"
TESTS = {
    "src/lib.rs": [
        "tests::actual_engine_commit_rollback_reopen_and_bound_parameters",
        "tests::sync_error_and_unknown_namespace_never_succeed",
        "tests::abi_short_read_zero_fill_and_lock_levels",
        "tests::single_main_connection_and_retired_registration_refuse_safely",
    ],
    "src/registration.rs": [
        "registration::tests::exact_capacity_and_refusal_never_wrap_or_restore",
        "registration::tests::last_slot_returns_original_identity_then_refuses",
        "registration::tests::contended_reservations_are_unique_and_never_exceed_capacity",
    ],
}
INPUTS = (
    "Cargo.toml", "Cargo.lock", ".arcana/verify.json", ".github/workflows/ci.yml",
    "scripts/full-test-group.py", "scripts/ci-ensure-cc.sh",
    "scripts/ci-sqlite-full-evidence.py",
    "scripts/tests/test_ci_sqlite_full_evidence.py",
    PACKAGE + "/Cargo.toml", PACKAGE + "/src/lib.rs",
    PACKAGE + "/src/registration.rs", PACKAGE + "/src/test_vfs.rs",
)
MODES = ("--no-default-features", "--all-features")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], timeout=10)
    head = git("rev-parse", "HEAD").decode().strip()
    files = {}
    for path in INPUTS:
        raw = (root / path).read_bytes()
        if raw != git("show", head + ":" + path):
            raise ValueError("source differs from checkout: " + path)
        files[path] = sha(raw)
    profile = json.loads((root / ".arcana/verify.json").read_text())
    declaration = profile["deployables"][PACKAGE]
    if declaration != {"full_test": ["python3", "../../../scripts/full-test-group.py",
                                    "disk-personal-sqlite"],
                       "full_test_timeout_seconds": 1800}:
        raise ValueError("SQLite FULL declaration changed")
    names = []
    for path, expected in TESTS.items():
        raw = (root / PACKAGE / path).read_text()
        found = re.findall(r"#\[test\]\s+fn\s+(\w+)\s*\(", raw)
        if (sorted(found) != sorted(x.split("::")[-1] for x in expected)
                or len(found) != raw.count("#[test]")
                or "#[ignore" in raw):
            raise ValueError("SQLite source test inventory changed: " + path)
        names.extend(expected)
    context = {key: os.environ.get(key) for key in
               ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB",
                "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA",
                "RUNNER_OS")}
    if os.environ.get("GITHUB_ACTIONS") == "true" and not all(context.values()):
        raise ValueError("CI provenance is incomplete")
    return {"schema": "SQLiteFullInput/v1", "head": head, "ci": context,
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "source_sha256": files, "tests": sorted(names),
            "declaration": declaration, "cwd": PACKAGE}


def validate_output(raw, expected):
    text = re.sub(r"\x1b\[[0-9;]*m", "", raw)
    lines = text.splitlines()
    commands = ["+ cargo test -p disk-personal-sqlite --locked " + mode
                + " -- --include-ignored" for mode in MODES]
    if any(lines.count(command) != 1 for command in commands):
        raise ValueError("both unique declared modes are required")
    first, second = (lines.index(command) for command in commands)
    if first >= second or any(line.startswith("+ ") and line not in commands for line in lines):
        raise ValueError("unexpected runner command or mode order")
    result = {}
    for mode, segment in zip(MODES, (lines[first:second], lines[second:])):
        body = "\n".join(segment)
        cases = re.findall(r"^test (\S+) \.\.\. (\S+)(?: .*)?$", body, re.MULTILINE)
        if (sorted(name for name, _ in cases) != sorted(expected)
                or any(status != "ok" for _, status in cases)):
            raise ValueError("missing, duplicate, ignored or failed SQLite test")
        counts = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                            r"(\d+) measured; (\d+) filtered out;", body, re.MULTILINE)
        if (not counts or sum(int(row[0]) for row in counts) != len(expected)
                or any(any(int(n) for n in row[1:]) for row in counts)):
            raise ValueError("SQLite summary is incomplete or disagrees with inventory")
        result[mode] = {"passed": len(expected), "tests": sorted(expected)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inventory", "verify"))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.operation == "inventory":
        data = inventory(ROOT)
        args.input.write_text(json.dumps(data, sort_keys=True) + "\n")
        print("SQLITE_FULL_INPUT=" + json.dumps(data, sort_keys=True), flush=True)
        return
    if not args.log or not args.out:
        parser.error("verify requires --log and --out")
    before = json.loads(args.input.read_text())
    if before != inventory(ROOT):
        raise ValueError("source or inventory changed during SQLite FULL")
    raw = args.log.read_bytes()
    result = {"schema": "SQLiteFullOutput/v1", "input": before,
              "log_sha256": sha(raw), "log_bytes": len(raw),
              "modes": validate_output(raw.decode("utf-8"), before["tests"])}
    args.out.write_text(json.dumps(result, sort_keys=True) + "\n")
    print("SQLITE_FULL_INVENTORY=" + json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Self-test for audit-metadb.py (DISK-0083).

A checking tool that cannot be shown to fail on a known-bad input is worth
nothing — that is the exact way the original "0 false tombstones" number was
produced. So this builds a database with deliberately planted defects and
asserts the tool finds each one, and equally that it does NOT flag the benign
case that once sent me chasing a phantom.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "audit-metadb.py")

SCHEMA = """
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT, vault_id TEXT NOT NULL DEFAULT 'default', user_id TEXT,
    path TEXT NOT NULL, content_hash BLOB NOT NULL, size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL, inode INTEGER,
    vector_clock TEXT NOT NULL DEFAULT '{}', sync_state TEXT NOT NULL DEFAULT 'clean',
    last_synced INTEGER, version_id TEXT, parent_version_id TEXT,
    encryption_nonce BLOB, created_at INTEGER, updated_at INTEGER,
    deleted INTEGER NOT NULL DEFAULT 0, deleted_at INTEGER
);
"""


def row(con, vault, path, deleted):
    con.execute(
        "INSERT INTO files (vault_id, path, content_hash, size, mtime_ns, deleted) "
        "VALUES (?,?,?,?,?,?)",
        (vault, path, b"\x00" * 32, 1, 1, 1 if deleted else 0),
    )


def main():
    tmp = tempfile.mkdtemp()
    root = os.path.join(tmp, "kb")
    os.makedirs(os.path.join(root, "notes"))
    os.makedirs(os.path.join(root, ".version-blobs", "ab"))

    # On disk.
    open(os.path.join(root, "notes", "healthy.md"), "w").write("ok")
    open(os.path.join(root, "notes", "wrongly-tombstoned.md"), "w").write("bytes are here")

    # DISK-0090: a file reachable only THROUGH a symlinked directory. The
    # indexer refuses symlinks, so its row is legitimately absent/tombstoned —
    # counting it as a defect is a false positive, and six such paths under
    # qa/playwright-CUBR-0081/{after,before} did exactly that on canon.
    os.makedirs(os.path.join(root, "run-real"))
    open(os.path.join(root, "run-real", "report.md"), "w").write("real bytes")
    os.symlink("run-real", os.path.join(root, "linked"))

    db = os.path.join(tmp, "meta.sqlite")
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)

    row(con, "kb", "notes/healthy.md", deleted=False)              # correct
    row(con, "kb", "notes/wrongly-tombstoned.md", deleted=True)    # DEFECT 1
    row(con, "kb", "notes/vanished.md", deleted=False)             # DEFECT 2
    row(con, "kb", "notes/properly-deleted.md", deleted=True)      # correct
    row(con, "kb", ".version-blobs/ab", deleted=True)              # benign: a directory
    row(con, "kb", "linked/report.md", deleted=True)               # benign: behind a symlink
    row(con, "other", "somewhere.md", deleted=False)               # no root configured
    con.commit()
    con.close()

    proc = subprocess.run(
        [sys.executable, TOOL, "--db", db, "--roots", f"kb:{root}", "--json"],
        capture_output=True, text=True,
    )
    report = json.loads(proc.stdout)
    kb = report["vaults"]["kb"]

    failures = []

    if kb.get("unindexable_behind_symlink") != 1:
        failures.append(
            f"expected the symlinked path to be benign, got "
            f"{kb.get('unindexable_behind_symlink')} — a file the indexer cannot "
            "reach is not a defect"
        )
    if "linked/report.md" in kb["sample_tombstoned_but_present"]:
        failures.append("a path behind a symlink was miscounted as a defect")

    if kb["tombstoned_but_present_on_disk"] != 1:
        failures.append(
            f"expected 1 tombstoned-but-present, got {kb['tombstoned_but_present_on_disk']} "
            "— this is the exact number the broken check always reported as 0"
        )
    if "notes/wrongly-tombstoned.md" not in kb["sample_tombstoned_but_present"]:
        failures.append("the offending path was not named")

    if kb["live_but_missing_from_disk"] != 1:
        failures.append(
            f"expected 1 live-but-missing, got {kb['live_but_missing_from_disk']}"
        )

    if kb["tombstoned_paths_that_are_directories"] != 1:
        failures.append(
            f"expected the directory row to be counted as benign, got "
            f"{kb['tombstoned_paths_that_are_directories']}"
        )
    if kb["tombstoned_but_present_on_disk"] > 1:
        failures.append("a directory was miscounted as a defect — the phantom-regression bug")

    if not any(u["vault"] == "other" for u in report["unrooted_vaults"]):
        failures.append("a vault with no configured root must be reported, not silently skipped")

    if proc.returncode != 1:
        failures.append(f"exit code must be 1 when defects exist, got {proc.returncode}")

    # And the clean case must exit 0.
    clean_root = os.path.join(tmp, "clean")
    os.makedirs(os.path.join(clean_root, "notes"))
    open(os.path.join(clean_root, "notes", "a.md"), "w").write("x")
    db2 = os.path.join(tmp, "clean.sqlite")
    con = sqlite3.connect(db2)
    con.executescript(SCHEMA)
    row(con, "kb", "notes/a.md", deleted=False)
    con.commit()
    con.close()
    clean = subprocess.run(
        [sys.executable, TOOL, "--db", db2, "--roots", f"kb:{clean_root}"],
        capture_output=True, text=True,
    )
    if clean.returncode != 0:
        failures.append(f"a healthy index must exit 0, got {clean.returncode}")

    if failures:
        print("SELF-TEST FAILED")
        for f in failures:
            print("  -", f)
        return 1
    print("SELF-TEST PASSED: 1 tombstoned-but-present found, 1 live-but-missing found, "
          "1 directory and 1 symlinked path correctly treated as benign, "
          "unrooted vault reported, exit codes correct")
    return 0


if __name__ == "__main__":
    sys.exit(main())

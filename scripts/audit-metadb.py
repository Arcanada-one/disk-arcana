#!/usr/bin/env python3
"""Audit a Disk Arcana MetaDb against the filesystem.

DISK-0083. Every operational check of this index has so far been written from
scratch at the keyboard, and two of mine were wrong in ways that produced
confident, meaningless numbers:

  * `files.path` is RELATIVE to its share root. Testing `os.path.exists(path)`
    resolves against the process CWD, so it answers False for everything and
    the "false tombstone" count is structurally pinned at zero. I reported
    "0 of 403" and "0 of 464" that way, repeatedly, and they proved nothing.

  * The index tracks FILES. A row whose path is now a directory is not a
    defect, but `os.path.exists` says True for both, which turned 14 ordinary
    `.version-blobs/XX` directories into a phantom regression I chased.

This tool exists so the next person does not rediscover either. It reads the
share roots from the server's own environment rather than taking them on the
command line, so an operator cannot silently audit against the wrong root.

Usage:
    audit-metadb.py [--db PATH] [--roots share:/abs/path,...] [--json]

With no --roots it reads DISK_SHARE_ROOTS from the running user unit.
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys

DEFAULT_DB = os.path.expanduser("~/.local/share/disk-arcana/disk.db")


def roots_from_unit():
    """Read DISK_SHARE_ROOTS from the running server unit, if present."""
    try:
        out = subprocess.run(
            ["systemctl", "--user", "show", "disk-arcana-server", "-p", "Environment", "--value"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return {}
    for token in out.split():
        if token.startswith("DISK_SHARE_ROOTS="):
            return parse_roots(token.split("=", 1)[1])
    return {}


def parse_roots(spec):
    """`share:/abs/path,share2:/abs/path2` -> {share: path}."""
    roots = {}
    for pair in spec.split(","):
        pair = pair.strip()
        if not pair:
            continue
        name, _, path = pair.partition(":")
        if name and path:
            roots[name] = path
    return roots


def _reached_through_symlink(root, rel_path):
    """True when the path is, or sits behind, a symlink.

    The indexer refuses symlinked entries so it cannot escape the share
    root. A path reachable only by traversing one is therefore correctly
    missing from the index, and counting it as a defect is a false
    positive.
    """
    cur = root
    for part in rel_path.split("/")[:-1]:
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            return True
    return os.path.islink(os.path.join(root, rel_path))


def audit(db_path, roots):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    report = {"db": db_path, "roots": roots, "vaults": {}, "unrooted_vaults": []}

    for (vault,) in con.execute("select distinct vault_id from files"):
        root = roots.get(vault)
        if root is None:
            # A vault with no configured root cannot be audited: we do not know
            # what its paths are relative to. Say so instead of guessing.
            n = con.execute(
                "select count(*) from files where vault_id=?", (vault,)
            ).fetchone()[0]
            report["unrooted_vaults"].append({"vault": vault, "rows": n})
            continue

        live = dead = 0
        unindexable = 0               # reachable only through a symlink: correctly absent
        tombstoned_but_present = []   # the real defect: bytes on disk, row says deleted
        tombstoned_dirs = 0           # NOT a defect: index tracks files only
        live_but_missing = []         # row says present, nothing on disk

        for path, deleted in con.execute(
            "select path, deleted from files where vault_id=?", (vault,)
        ):
            abs_path = os.path.join(root, path)
            is_file = os.path.isfile(abs_path)
            is_dir = os.path.isdir(abs_path)
            # DISK-0090: the indexer never follows symlinks -- walk_files rejects
            # a symlinked entry outright, so a file reachable only THROUGH a
            # symlinked directory legitimately has no live row. os.path.isfile()
            # DOES follow symlinks, so without this check those paths read as
            # "tombstoned but present" forever. Measured on canon: six files
            # under qa/playwright-CUBR-0081/{after,before}/ -- both symlinks to
            # run-* directories -- were reported as defects while the index was
            # in fact correct to omit them.
            if is_file and _reached_through_symlink(root, path):
                unindexable += 1
                continue
            if deleted:
                dead += 1
                if is_file:
                    tombstoned_but_present.append(path)
                elif is_dir:
                    tombstoned_dirs += 1
            else:
                live += 1
                if not is_file:
                    live_but_missing.append(path)

        report["vaults"][vault] = {
            "root": root,
            "live_rows": live,
            "tombstoned_rows": dead,
            "tombstoned_but_present_on_disk": len(tombstoned_but_present),
            "tombstoned_paths_that_are_directories": tombstoned_dirs,
            "unindexable_behind_symlink": unindexable,
            "live_but_missing_from_disk": len(live_but_missing),
            "sample_tombstoned_but_present": tombstoned_but_present[:10],
            "sample_live_but_missing": live_but_missing[:10],
        }
    con.close()
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--roots", default=None,
                    help="share:/abs/path,... (default: read from the server unit)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"error: no such database: {args.db}", file=sys.stderr)
        return 2

    roots = parse_roots(args.roots) if args.roots else roots_from_unit()
    if not roots:
        print("error: no share roots. Pass --roots share:/abs/path, or run where "
              "the disk-arcana-server user unit is available.", file=sys.stderr)
        return 2

    report = audit(args.db, roots)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"database: {report['db']}")
        for vault, r in report["vaults"].items():
            print(f"\nvault {vault}  (root {r['root']})")
            print(f"  live rows                        {r['live_rows']}")
            print(f"  tombstoned rows                  {r['tombstoned_rows']}")
            print(f"  DEFECT tombstoned but on disk    {r['tombstoned_but_present_on_disk']}")
            print(f"  DEFECT live but missing on disk  {r['live_but_missing_from_disk']}")
            print(f"  benign: tombstoned dirs          {r['tombstoned_paths_that_are_directories']}")
            print(f"  benign: behind a symlink         {r['unindexable_behind_symlink']}")
            for p in r["sample_tombstoned_but_present"]:
                print(f"    tombstoned-but-present: {p}")
            for p in r["sample_live_but_missing"]:
                print(f"    live-but-missing:       {p}")
        for u in report["unrooted_vaults"]:
            print(f"\nvault {u['vault']}: {u['rows']} rows, NO CONFIGURED ROOT — not audited "
                  f"(paths are relative to a root this tool cannot identify)")

    defects = sum(r["tombstoned_but_present_on_disk"] + r["live_but_missing_from_disk"]
                  for r in report["vaults"].values())
    return 1 if defects else 0


if __name__ == "__main__":
    sys.exit(main())

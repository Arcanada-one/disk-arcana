"""Fail-closed source and probe validation shared by native canary consumers.

Integrity checks do not authenticate the measurement harness. Its source claim
is trusted evidence, explicitly scoped to the committed Git subject checked here.
"""
from __future__ import annotations
import os
import stat
import hashlib
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime

RANK = {"verified": 0, "not_measured": 1, "failed": 2}
SOURCE_FIELDS = {
    "ReadinessReceipt/v1": "source_head",
    "ControlledAuthOidcFlagProof/v1": "source",
    "ControlledEmailVerificationProof/v1": "source",
    "MeasuredGitSource/v1": "commit",
}


MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 10

# DEC-AUP-0040 (KB-040). A canary result must be COMMITTED to be cashed (DEC-AUP-0037 R1) and a git
# commit cannot contain its own object id, so a subject pinned to the candidate head has no fixed
# point: every card measuring a canary-mandatory entity was condemned to paused_safe or to a
# hand-written exemption. The measured subject may therefore be an ANCESTOR of the candidate, on one
# condition that is provable from git objects alone: the whole delta between them is record
# documents. Then the code at the candidate is byte-for-byte the code the canary measured, which is
# the invariant — evidence about one tree must never vouch for a different tree's code.
#
# Deny-by-default. Widening this tuple widens what a measurement may skip over, and is a decision,
# not a patch: `receipts/` is where evidence and receipts live, `governance/design/` is the note a
# record commit writes beside them. Nothing executable and nothing policy-bearing is in here --
# `governance/decisions/`, `contracts/`, `tools/`, `.github/` are all outside it on purpose.
RECORD_NAMESPACES = ("receipts/", "governance/design/")
# A prefix is not inertness, measured on this tree: `receipts/prompt-cache/.../run_mutants.py` is
# indexed as a code_unit by build_graph (any .py under any directory), `receipts/graph/work-item-
# evidence/` is admit_change.LEDGER_DIR and is READ by check C13, and a dotfile
# (`.gitignore`, `.gitattributes`) changes how git and the gate see the rest of the tree. So the
# namespace is narrowed three more ways, all deny-by-default: a denied sub-namespace, no dotfiles,
# and an extension allowlist that covers 3591 of the 3620 files currently under these prefixes
# (`git ls-files receipts governance/design`) and excludes the one .py, the one .patch and the 27
# .zip that live there.
RECORD_DENIED_PREFIXES = ("receipts/graph/work-item-evidence/",)
# `receipts/graph/work-item-evidence/<id>.json` has three slashes; anything deeper is not an entry.
LEDGER_REL_DEPTH = RECORD_DENIED_PREFIXES[0].count("/")
RECORD_SUFFIXES = (".json", ".jsonl", ".md", ".txt", ".log")
RECORD_FILE_MODE = "100644"
MAX_REPORTED_DELTA_PATHS = 8


# A2-263 (KB-041). Two measured defects with one root: the gate resolved evidence through the
# FILESYSTEM and through the PRODUCER's absolute paths.
#
#  * `admit_change.canary_coverage` opened `output_ref` from the working tree. `.gitignore:15`
#    ignores `receipts/graph/verifier-out/**/graph-*.json`, and `impact.Repo.dirty()` is
#    `git status --porcelain`, which does not list ignored files. Measured on a clean checkout of
#    b8e298b9: a CanaryResult in NO commit credited `code_unit:apps/web/lib/api/tasks.ts` with full
#    coverage and zero problems while the worktree reported clean. CI's fresh checkout would not
#    have had the file; the LOCAL gate — the authoritative one under DEC-AUP-0007 — cashed it.
#  * A committed `CanaryResult/v2` resolved its plan and its source evidence relative to
#    `plan.path`, an absolute path on the machine that produced it. #119's canary therefore
#    verifies on this host only because `/home/dev/aup/arc2/runs/A2-247b/` still exists; with that
#    one directory hidden (private mount namespace, everything else identical) the same bytes at
#    the same commit yield 0 rows.
#
# The rule both halves now obey: an evidence document is read from GIT OBJECTS at the admitted
# head, and the documents it references are its SIBLINGS in the repository, named by basename. The
# reference's directory part is advisory and ignored; the bytes are pinned by digest either way
# (`plan.digest`, `subject.evidence.sha256`), so the basename decides only where to look, and the
# digest decides whether the right thing was found.
EVIDENCE_AT_HEAD_REQUIRED = "evidence must be read from a commit, not from the working tree"


def read_at_commit(repo, commit, rel):
    """Bytes of a repo-relative path AS COMMITTED at `commit`. Never touches the working tree."""
    out = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", f"{commit}:{rel}"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         timeout=GIT_TIMEOUT_SECONDS)
    if out.returncode != 0:
        raise OSError(f"{rel} is in no commit at {str(commit)[:12]}")
    if len(out.stdout) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence exceeded size limit during read")
    return out.stdout


def reference_name(reference):
    """The bare file name a reference points at, refusing anything that is not one."""
    text = str(reference).replace("\\", "/")
    name = text.rsplit("/", 1)[-1]
    if not name or name in (".", "..") or text.endswith("/"):
        raise ValueError(f"{reference!r} does not name a document beside the result")
    return name


def sibling_ref(rel, reference):
    """The repo-relative path of a document referenced BESIDE `rel`.

    A reference is a file name next to the result document. `plan.path` in every result written so
    far is the producer's absolute scratch path, which is exactly the portability defect, so the
    directory part is dropped rather than trusted. `..`, an empty name and a bare `.` are refused
    instead of being normalised into something.
    """
    name = reference_name(reference)
    parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
    return f"{parent}/{name}" if parent else name


def worktree_reader(result_path):
    """Producer-side reader: the documents a result references, beside it ON DISK.

    The sibling is tried FIRST, so a committed result whose `plan.path` still spells the producer's
    absolute scratch path resolves to the copy committed next to it. The literal reference remains
    as a fallback, because a canary is produced before anything is committed and the producer's own
    layout is the only one that exists then.
    """
    base = Path(result_path).parent

    def read(reference):
        try:
            return read_regular(base / reference_name(reference))
        except (OSError, ValueError):
            ref = Path(reference)
            return read_regular(ref if ref.is_absolute() else base / ref)
    return read


def commit_reader(repo, commit, result_rel):
    """Gate-side reader: siblings of the result document, AS COMMITTED at the admitted head.

    Nothing here can reach the working tree, so an ignored or uncommitted file cannot be cashed
    (A2-263 §5.3) and no absolute producer path can be followed (A2-263 §5.2).
    """
    def read(reference):
        return read_at_commit(repo, commit, sibling_ref(result_rel, reference))
    return read


def read_regular(path):
    """Bounded descriptor read; reject FIFO/device/symlink before reading bytes."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence is not a bounded regular file")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_EVIDENCE_BYTES + 1 - total))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > MAX_EVIDENCE_BYTES:
                raise ValueError("evidence exceeded size limit during read")
            chunks.append(chunk)
    finally:
        os.close(fd)


def structure_errors(doc):
    errors = []
    if not isinstance(doc, dict) or doc.get("schema") not in ("CanaryResult/v1", "CanaryResult/v2"):
        return ["not a CanaryResult/v1 object"]
    if not isinstance(doc.get("environment"), str) or not doc["environment"]:
        errors.append("missing environment")
    if doc.get("phase") not in ("pre", "post"):
        errors.append("invalid phase")
    if not isinstance(doc.get("plan"), dict) or not isinstance(doc["plan"].get("id"), str) or not doc["plan"]["id"]:
        errors.append("missing plan id")
    if not isinstance(doc.get("read_only"), bool):
        errors.append("missing read_only")
    elif not doc["read_only"] and not doc.get("mutating_owner"):
        errors.append("missing mutating owner")
    timestamp = doc.get("captured_at_utc")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) if isinstance(timestamp, str) else None
        if parsed is None or parsed.tzinfo is None:
            errors.append("missing timezone-aware capture timestamp")
    except ValueError:
        errors.append("invalid capture timestamp")
    if "resident_version" not in doc or "model" not in doc:
        errors.append("missing required result metadata")
    probes = doc.get("probes")
    rows = doc.get("entity_verdicts")
    if not isinstance(probes, list) or not isinstance(rows, list):
        return errors + ["probes and entity_verdicts must be arrays"]
    by_id = {}
    for p in probes:
        if not isinstance(p, dict) or not isinstance(p.get("id"), str) or not p["id"]:
            errors.append("malformed probe")
            continue
        if p["id"] in by_id:
            errors.append("duplicate probe id")
        by_id[p["id"]] = p
        if not isinstance(p.get("outcome"), str) or p["outcome"] not in RANK:
            errors.append("invalid probe outcome")
        if doc.get("schema") == "CanaryResult/v2":
            if p.get("kind") == "process":
                import process_observation
                errors.extend(process_observation.result_errors(p))
                continue
            if p.get("kind") != "process":
                errors.append("v2 currently supports process observations only")
                continue
        elif p.get("kind") not in (None, "http"):
            errors.append("v1 supports HTTP observations only")
        status = p.get("status")
        if p.get("outcome") in ("verified", "failed") and (type(status) is not int or not 100 <= status <= 599):
            errors.append("measured probe lacks actual HTTP status")
        if p.get("outcome") == "verified" and (p.get("executed") is False or p.get("offline") is True):
            errors.append("unrun probe reported verified")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("entity"), str) or not row["entity"]:
            errors.append("malformed entity verdict")
            continue
        if row["entity"] in seen:
            errors.append("duplicate entity id")
        seen.add(row["entity"])
        if not isinstance(row.get("verdict"), str) or row["verdict"] not in RANK:
            errors.append("invalid entity verdict")
        if not isinstance(row.get("reason"), str):
            errors.append("entity reason must be a string")
        ids = row.get("probe_ids")
        if not isinstance(ids, list) or not ids or any(not isinstance(i, str) or i not in by_id for i in ids):
            errors.append("entity has missing probe references")
            continue
        if len(ids) != len(set(ids)):
            errors.append("duplicate entity probe references")
        outcomes = [by_id[i].get("outcome") for i in ids]
        if all(isinstance(o, str) and o in RANK for o in outcomes) and (row.get("verdict") == "verified" and any(o != "verified" for o in outcomes) or row.get("verdict") == "failed" and "failed" not in outcomes or row.get("verdict") == "not_measured" and "failed" in outcomes):
            errors.append("entity verdict contradicts cited probes")
    return errors


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL, timeout=GIT_TIMEOUT_SECONDS).strip()


def executed_paths(doc):
    """Absolute paths of every file the result's process probes actually executed.

    The probes run against a scratch copy, so these are not repository paths; they are matched by
    suffix. A probe may legitimately execute BYTES THAT DIFFER from the head's (the A2-247 canary
    perturbs `ci_gate.py` on purpose, to observe the producer refuse a tree that differs from its
    ref), so this is not a digest pin on covered entities -- it is a guard that the record delta
    never moves a file the measurement ran.
    """
    out = set()
    if not isinstance(doc, dict):
        return out
    for probe in doc.get("probes") or []:
        if not isinstance(probe, dict):
            continue
        for item in probe.get("execution_files") or []:
            if isinstance(item, dict) and isinstance(item.get("path"), str) and item["path"]:
                out.add(item["path"])
    return out


def tree_entries(repo, commit):
    """path -> (mode, object id) for every blob and gitlink of a commit's tree.

    `git ls-tree` reads the tree objects and nothing else. `git diff` does not: a
    `submodule.<name>.ignore = all` in `.gitmodules` or in `.git/config` makes diff, --name-status
    and diff-tree alike report an EMPTY delta between two demonstrably different trees (measured by
    the consilium's reproducible-builds engineer, reproduced in this repository's own test suite).
    Rename detection, `core.quotepath`, `--diff-filter` and pathspecs are three further knobs on the
    same primitive. The completeness claim of DEC-AUP-0040 R1 -- "nothing but record documents
    differs" -- is therefore computed here, from enumerations, not from a diff.
    """
    raw = subprocess.check_output(["git", "-C", str(repo), "ls-tree", "-r", "-z", "--full-tree", commit],
                                  stderr=subprocess.DEVNULL, timeout=GIT_TIMEOUT_SECONDS).decode("utf-8", "surrogateescape")
    entries = {}
    for record in raw.split("\0"):
        if not record:
            continue
        meta, _, path = record.partition("\t")
        parts = meta.split(" ")
        if not path or len(parts) != 3:
            raise ValueError("unreadable tree entry")
        entries[path] = (parts[0], parts[2])
    return entries


LEDGER_ENTRY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json")


def blob_at(repo, oid):
    return subprocess.check_output(["git", "-C", str(repo), "cat-file", "blob", oid],
                                   stderr=subprocess.DEVNULL, timeout=GIT_TIMEOUT_SECONDS)


def ledger_append_errors(repo, candidate_commit, candidate_entries, path, before, after):
    """DEC-AUP-0061. The ONE shape of ledger delta a measurement may skip over: an APPEND whose every
    new attachment names a receipt that is in the candidate tree with exactly the bytes it claims.

    Why this carve-out exists at all, measured on 2026-09-27 (A2-408): a change that needs a canary
    AND must carry a work-item evidence attachment could not be admitted at any commit order. The
    receipt has to bind the full range, so the canary commit cannot follow it (C06
    CHANGE_SET_INCOMPLETE); the ledger was denied here unconditionally, so it could not follow the
    canary either. Re-issuing the receipt moves the ledger; re-taking the canary moves the canary
    files. Three iterations, the two refusals alternating, and no fixed point exists: the head sha
    is inside the receipt bytes, the digest of those bytes is inside the ledger, and the ledger is
    inside the head tree.

    Why it is safe to skip over, which is a different question and the one that decides it: what the
    subject relaxation protects is «the code at the candidate is byte-for-byte the code the canary
    measured». A ledger entry is not code and the canary never reads it. The reason the whole
    directory was denied is that the GATE reads it (C13) — so the danger is a record commit that
    slips in evidence about something the change does not contain. That is exactly what the last
    condition forbids: an appended attachment may only name a receipt standing in the candidate tree
    whose bytes hash to the digest the attachment records. A digest that names nothing, or names
    other bytes, is refused here and the whole delta with it.

    Deny-by-default is preserved in every other direction: a rewrite, a withdrawal, a reordering, a
    change to any other key, a nested path, a non-regular file — all still refused.
    """
    name = path.split("/")[-1]
    if not LEDGER_ENTRY_NAME.fullmatch(name) or path.count("/") != LEDGER_REL_DEPTH:
        return [f"{path} is evidence the gate itself reads and is not even a work-item ledger entry "
                f"(<id>.json directly under {RECORD_DENIED_PREFIXES[0]})"]
    if after is None:
        return [f"{path} is evidence the gate itself reads: an entry may be appended to by a record "
                f"commit, never withdrawn by one"]
    if after[0] != RECORD_FILE_MODE or (before is not None and before[0] != RECORD_FILE_MODE):
        return [f"{path}: a work-item ledger entry must be a regular non-executable file "
                f"(mode {after[0]})"]
    try:
        new = json.loads(blob_at(repo, after[1]))
        old = json.loads(blob_at(repo, before[1])) if before is not None else {"attachments": []}
    except (OSError, ValueError, subprocess.SubprocessError):
        return [f"{path} is evidence the gate itself reads and cannot be read as JSON at both revisions"]
    if not isinstance(new, dict) or not isinstance(old, dict):
        return [f"{path} is evidence the gate itself reads and is not an object at both revisions"]
    new_atts, old_atts = new.get("attachments"), old.get("attachments")
    if not isinstance(new_atts, list) or not isinstance(old_atts, list):
        return [f"{path} is evidence the gate itself reads and carries no attachments list"]
    if {k: v for k, v in new.items() if k != "attachments"} != {k: v for k, v in old.items() if k != "attachments"} and before is not None:
        return [f"{path} is evidence the gate itself reads: a record commit may append an attachment "
                f"and change nothing else about the entry"]
    if len(new_atts) <= len(old_atts) or new_atts[:len(old_atts)] != old_atts:
        return [f"{path} is evidence the gate itself reads: only an APPEND may be skipped over, and "
                f"this delta rewrites, reorders or removes what was already recorded"]
    errors = []
    for att in new_atts[len(old_atts):]:
        ref = (att or {}).get("evidence_ref") or {}
        rel, digest = (att or {}).get("receipt_path"), ref.get("digest")
        if not isinstance(rel, str) or not isinstance(digest, str) or not digest.startswith("sha256:"):
            errors.append(f"{path}: an appended attachment without a receipt_path and a sha256 "
                          f"evidence digest names nothing the candidate can be checked against")
            continue
        entry = candidate_entries.get(rel)
        if entry is None or entry[0] != RECORD_FILE_MODE:
            errors.append(f"{path}: the appended attachment names {rel}, which is not a regular file "
                          f"in the candidate tree — a measurement may not skip over evidence about "
                          f"bytes the change does not contain")
            continue
        try:
            actual = "sha256:" + hashlib.sha256(blob_at(repo, entry[1])).hexdigest()
        except (OSError, subprocess.SubprocessError):
            errors.append(f"{path}: {rel} cannot be read out of the candidate tree")
            continue
        if actual != digest:
            errors.append(f"{path}: the appended attachment records {digest[:19]}… for {rel}, but the "
                          f"candidate tree holds {actual[:19]}… — the entry names other bytes")
    return errors


def record_delta_errors(repo, measured_commit, candidate_commit, executed=()):
    """DEC-AUP-0040 R1: every refusal is named, and a path is named with it.

    Returns [] only when `measured_commit` is an ancestor of `candidate_commit` AND every path whose
    (mode, object id) differs between the two trees is a record document: inside RECORD_NAMESPACES,
    outside RECORD_DENIED_PREFIXES, not a dotfile, one of RECORD_SUFFIXES, landing as a regular
    non-executable file of unchanged type, and not a path the canary's own probes executed.
    """
    try:
        ancestry = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                                   measured_commit, candidate_commit],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=GIT_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError):
        return ["ancestry of the measured subject cannot be decided in this repository"]
    if ancestry.returncode != 0:
        return [f"measured subject {measured_commit[:12]} is not an ancestor of candidate "
                f"{candidate_commit[:12]}: evidence may only be cashed by a descendant that records it"]
    try:
        measured, candidate = tree_entries(repo, measured_commit), tree_entries(repo, candidate_commit)
    except (OSError, ValueError, subprocess.SubprocessError):
        return ["the trees of the measured subject and the candidate cannot be enumerated"]
    errors = []
    for path in sorted(set(measured) | set(candidate)):
        before, after = measured.get(path), candidate.get(path)
        if before == after:
            continue
        if not any(path.startswith(ns) for ns in RECORD_NAMESPACES):
            errors.append(f"{path} is not a record document: the delta between the measured subject and "
                          f"the candidate may only touch {', '.join(RECORD_NAMESPACES)}")
            continue
        if any(path.startswith(ns) for ns in RECORD_DENIED_PREFIXES):
            # DEC-AUP-0061: still denied, with exactly one proved-from-git-objects exception.
            ledger = ledger_append_errors(repo, candidate_commit, candidate, path, before, after)
            if ledger:
                errors.extend(ledger)
            continue
        if path.rsplit("/", 1)[-1].startswith(".") or not path.endswith(RECORD_SUFFIXES):
            errors.append(f"{path} is not a record document: a record document is a "
                          f"{'/'.join(RECORD_SUFFIXES)} file that nothing executes and nothing reads as policy")
            continue
        if after is not None and after[0] != RECORD_FILE_MODE:
            errors.append(f"{path}: a record document must land as a regular non-executable file "
                          f"(mode {after[0]})")
            continue
        if before is not None and after is not None and before[0] != after[0]:
            errors.append(f"{path}: the object type or mode changed ({before[0]} -> {after[0]}); a record "
                          f"document is added, rewritten or withdrawn, never retyped")
            continue
        if any(x == path or x.endswith("/" + path) for x in executed):
            errors.append(f"{path} is a path this canary's probes executed: the record commit may not "
                          f"move what the measurement ran")
    return errors[:MAX_REPORTED_DELTA_PATHS]


def source_errors(doc, read, repo, commit, *, dirty=False):
    if dirty:
        return ["dirty worktree has no supported immutable measured subject"]
    subject = doc.get("subject")
    if not isinstance(subject, dict) or subject.get("schema") != "GitCanarySubject/v1":
        return ["missing supported immutable source subject"]
    try:
        actual_commit = git(repo, "rev-parse", "--verify", commit + "^{commit}")
        actual_tree = git(repo, "rev-parse", "--verify", actual_commit + "^{tree}")
        measured_commit, measured_tree = subject.get("commit"), subject.get("tree")
        if measured_commit != actual_commit or measured_tree != actual_tree:
            # DEC-AUP-0040 R1. The subject is not the candidate; it may still bind, as the commit the
            # candidate's record commits were stacked on. Self-consistency first (a forged tree is
            # refused before any ancestry is computed), then the delta.
            if not isinstance(measured_commit, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", measured_commit):
                return ["measured subject differs from candidate commit/tree"]
            try:
                resolved_commit = git(repo, "rev-parse", "--verify", measured_commit + "^{commit}")
                resolved_tree = git(repo, "rev-parse", "--verify", resolved_commit + "^{tree}")
            except subprocess.SubprocessError:
                return ["measured subject commit does not resolve in this repository"]
            if resolved_commit != measured_commit or measured_tree != resolved_tree:
                return ["measured subject tree is not the tree of the measured subject commit"]
            delta = record_delta_errors(repo, measured_commit, actual_commit, executed_paths(doc))
            if delta:
                return delta
        else:
            measured_commit, measured_tree = actual_commit, actual_tree
        ref = subject.get("evidence")
        if not isinstance(ref, dict) or not isinstance(ref.get("path"), str) or not re.fullmatch(r"[0-9a-f]{64}", str(ref.get("sha256", ""))):
            return ["missing measured source evidence reference"]
        raw = read(ref["path"])
        if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            return ["measured source evidence digest mismatch"]
        evidence = json.loads(raw)
        if not isinstance(evidence, dict) or evidence.get("schema") not in SOURCE_FIELDS:
            return ["unsupported measured source evidence schema"]
        field = SOURCE_FIELDS[evidence["schema"]]
        if ref.get("source_field") != field or evidence.get(field) != measured_commit:
            return ["original measured source claim differs from the measured subject"]
        if evidence.get("schema") == "MeasuredGitSource/v1" and (evidence.get("tree") != measured_tree or evidence.get("dirty") is not False or not evidence.get("producer") or not evidence.get("captured_at_utc")):
            return ["incomplete measured Git source claim"]
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return ["measured source evidence cannot be verified"]
    return []


def consume(path, repo, commit, *, dirty=False, at_head=None):
    """Return normalized rows and errors; invalid evidence never yields PASS.

    `at_head` — the repo-relative path of the result document. When given, EVERY read (the document
    itself and every document it references) goes through git objects at `commit`; a path that is
    in no commit there is refused and nothing on disk is consulted. That is what a consumer who is
    deciding admission must pass (A2-263). Omitted, the producer's on-disk layout is read, which is
    the only layout that exists while a canary is being produced.
    """
    if at_head is not None:
        try:
            raw = read_at_commit(repo, commit, at_head)
        except (OSError, ValueError, subprocess.SubprocessError):
            return {}, [f"canary evidence {at_head} is in no commit at {str(commit)[:12]}: "
                        f"{EVIDENCE_AT_HEAD_REQUIRED}"], {}
        read = commit_reader(repo, commit, at_head)
    else:
        try:
            raw = read_regular(path)
        except (OSError, ValueError):
            return {}, ["canary document cannot be read"], {}
        read = worktree_reader(path)
    try:
        doc = json.loads(raw)
    except ValueError:
        return {}, ["canary document cannot be read"], {}
    errors = structure_errors(doc)
    if not errors:
        reference = doc.get("plan", {}).get("path") if doc.get("schema") == "CanaryResult/v2" else None
        if doc.get("schema") == "CanaryResult/v2" and not isinstance(reference, (str, os.PathLike)):
            errors = ["invalid original plan reference"]
        else:
            errors = source_errors(doc, read, repo, commit, dirty=dirty)
    if not errors and doc.get("schema") == "CanaryResult/v2":
        import process_observation
        errors = process_observation.bound_errors(doc, read)
    if errors:
        return {}, errors, doc if isinstance(doc, dict) else {}
    return {r["entity"]: dict(r) for r in doc["entity_verdicts"]}, [], doc

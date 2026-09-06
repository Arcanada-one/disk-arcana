#!/usr/bin/env python3
"""AUP-GRAPH-006 gate0 — the admission gate: «нет receipt — нет мержа».

Subcommands
  gate           refuse / pause / admit a change range in a program-owned repository, from the
                 ChangeAdmissionReceipt/v1 documents that are bound to it (contract
                 contracts/graph-verified-change/admission-gate.v1.json).
  attach         build a WorkItemEvidenceAttachment/v1 for a receipt and append it to the program-side
                 evidence ledger; with --post, deliver it to Muneral when a work-item evidence route
                 exists (probe recorded, never a status write).
  charter-scan   scan the live charter surfaces of a host for TDD / test-first and classify every hit
                 (mandate_default | opt_in_reference | neutral_mention | historical).
  pr-coverage    measure which merges of a pilot repository carry a receipt (AM1 baseline / window).
  --selftest     fixtures + negative controls + mutation battery on a scratch git repository.

Python 3.12 stdlib only; deterministic; never writes to the repository it gates.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema_check  # noqa: E402  (sibling tool, reused as a library)

TOOL = "tools/graph/admit_change.py"
VERSION = "1.0.0"
MODEL = "claude-opus-5"
PROGRAM_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = PROGRAM_ROOT / "contracts/graph-verified-change/admission-gate.v1.json"
FIXTURE_DIR = PROGRAM_ROOT / "contracts/graph-verified-change/fixtures/admission"
LEDGER_DIR = PROGRAM_ROOT / "receipts/graph/work-item-evidence"

# The BLOCKING checks: the mutation battery disables each one and demands that at least one blocked
# fixture then gets through — a check that cannot be killed that way is a check that never blocked.
CHECK_IDS = ["C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "C10", "C11", "C12", "C13"]
# AUP-GRAPH-006:gate2a. C14/C15 are INFORMATIONAL: they name why the gate did or did not author a
# receipt on the automated-author path, and they never raise the verdict (their policy verdict is
# `admit`, rank 0). Disabling one therefore cannot let anything through, so the disabled-check battery
# would report a permanent survivor for a check that does not block by design. They are held to the
# property instead — asserted in the selftest — and their behaviour is measured by the dedicated
# gate2a mutation battery in ci_gate.py, where the four mutants of the card each flip the verdict.
INFORMATIONAL_CHECK_IDS = ["C14", "C15"]
VERDICT_RANK = {"admit": 0, "paused_safe": 1, "refuse": 2}
EXIT_OF = {"admit": 0, "paused_safe": 3, "refuse": 5}


# ------------------------------------------------------------------ helpers
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    return sha256_bytes(p.read_bytes())


def parse_iso(s):
    return schema_check.parse_iso(s)


def git(repo: Path, *args: str, check=True) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:300]}")
    return r.stdout


def git_ok(repo: Path, *args: str) -> bool:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True).returncode == 0


def load_policy(path: Path | None) -> dict:
    return json.loads((path or POLICY_PATH).read_text(encoding="utf-8"))


def write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ range + receipt discovery
def range_files(repo: Path, base: str, head: str) -> list[dict]:
    out = git(repo, "diff", "--name-status", "-M", f"{base}..{head}")
    files = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0][0]
        path = parts[-1]
        files.append({"path": path, "status": status})
    return sorted(files, key=lambda f: f["path"])


def range_commits(repo: Path, base: str, head: str) -> list[str]:
    return [c for c in git(repo, "rev-list", f"{base}..{head}").split() if c]


def discover_receipts(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for p in paths:
        if p.is_file():
            found.append(p)
            continue
        if not p.is_dir():
            continue
        for f in sorted(p.rglob("*.json")):
            try:
                # the schema key is sorted late in a canonically written receipt — scan the whole file, never a prefix
                if f.stat().st_size <= 32 * 1024 * 1024 and b"ChangeAdmissionReceipt" in f.read_bytes():
                    found.append(f)
            except OSError:
                continue
    return found


def read_receipt(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as e:
        return None, str(e)[:200]


def receipt_binds(repo: Path, doc: dict, base: str, head: str, commits: set[str]) -> tuple[bool, str]:
    """Is this receipt bound to exactly this change range?  (check C05)"""
    cs = doc.get("change_set") or {}
    tree = doc.get("tree") or {}
    mode = cs.get("mode")
    if mode == "diff":
        r_base, r_head = cs.get("base"), cs.get("head")
        if not (isinstance(r_base, str) and isinstance(r_head, str)):
            return False, "diff receipt without base/head"
        if r_head not in commits and r_head != head:
            return False, f"receipt head {r_head[:12]} is not a commit of {base[:12]}..{head[:12]}"
        if not git_ok(repo, "merge-base", "--is-ancestor", r_base, head):
            return False, f"receipt base {r_base[:12]} is not an ancestor of {head[:12]}"
        return True, f"diff {r_base[:12]}..{r_head[:12]}"
    if mode == "worktree":
        tc = tree.get("commit")
        if isinstance(tc, str) and (tc in commits or tc == head):
            return True, f"worktree at {tc[:12]}"
        return False, f"worktree receipt at {str(tc)[:12]} outside the range"
    return False, f"unknown change_set.mode {mode!r}"


# ------------------------------------------------------------------ the gate
# ------------------------------------------------------------------ AUP-GRAPH-006:gate2a
# The typed automated-author path: a dependency bot cannot author a ChangeAdmissionReceipt/v1, so
# making the gate a required check made every dependabot pull request need a human. The rule is not
# relaxed — the RECEIPT AUTHOR is typed. For a pull request whose author matches a registered
# automated author IN THE EVENT PAYLOAD, and whose diff touches only that author's path allowlist,
# the gate computes the impact set the same way as for anyone else and authors the receipt itself,
# with the typed exemption AUTOMATED_DEPENDENCY_UPDATE over ONE entity: the missing agent-authored
# receipt. Verification is never exempted: a lockfile/manifest change triggers the global fallback
# (impact = whole repository) and the repository's OWN test job is the verifier for it.

CONCLUSION_TO_VERDICT = {"success": "verified", "failure": "failed", "cancelled": "failed",
                         "timed_out": "failed", "action_required": "failed"}


def event_author(event: dict) -> dict:
    """The author fields the decision may look at — all from the payload GitHub delivered."""
    pr = event.get("pull_request") if isinstance(event.get("pull_request"), dict) else {}
    user = pr.get("user") if isinstance(pr.get("user"), dict) else {}
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    return {"login": user.get("login"), "id": user.get("id"), "type": user.get("type"),
            "author_association": pr.get("author_association"),
            # recorded, never consulted: the head branch name is chosen by whoever opens the PR
            "claimed_head_ref": head.get("ref"), "is_pull_request": bool(pr)}


def match_automated_author(policy: dict, event: dict | None) -> tuple[dict | None, dict]:
    """→ (author spec or None, evidence). Identity comes from the event payload, never the branch."""
    spec = policy.get("automated_authors") or {}
    authors = spec.get("authors") or []
    if not isinstance(event, dict) or not event:
        return None, {"matched": False, "reason": "no pull_request event payload was supplied to the gate"}
    who = event_author(event)
    if not who["is_pull_request"]:
        return None, {"matched": False, "reason": "the event payload carries no `pull_request` object", "author": who}
    for au in authors:
        if who["login"] == au.get("login") and who["id"] == au.get("user_id") and who["type"] == au.get("user_type"):
            return au, {"matched": True, "author_id": au.get("id"), "author": who,
                        "matched_on": ["pull_request.user.login", "pull_request.user.id", "pull_request.user.type"],
                        "branch_name_used": False}
    return None, {"matched": False, "author": who,
                  "reason": (f"login/id/type {who['login']!r}/{who['id']!r}/{who['type']!r} matches no registered "
                             f"automated author ({', '.join(str(a.get('login')) for a in authors) or 'none'}); "
                             f"the head branch name {who['claimed_head_ref']!r} is not evidence of authorship"),
                  "branch_name_used": False}


def allowlist_split(paths: list[str], globs: list[str]) -> tuple[list[str], list[str]]:
    inside = [p for p in paths if any(fnmatch.fnmatch(p, g) for g in globs)]
    return inside, [p for p in paths if p not in set(inside)]


def build_graph_at(repo: Path, rev: str, out: Path) -> dict | None:
    """Build the caller repository's graph at `rev` with the bundled builder (stdlib, deterministic)."""
    script = Path(__file__).resolve().parent / "build_graph.py"
    r = subprocess.run([sys.executable, str(script), str(repo), "--rev", rev, "--out", str(out)],
                       capture_output=True, text=True,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if r.returncode != 0 or not out.exists():
        return None
    try:
        return json.loads(out.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def synthesize_automated_receipt(repo: Path, base: str, head: str, files: list[dict], author: dict,
                                 policy: dict, *, repo_name: str, verifier_job: str | None,
                                 verifier_conclusion: str | None, verifier_output_ref: str | None,
                                 workdir: Path, event_evidence: dict) -> tuple[dict | None, str]:
    """The gate authors the receipt. → (receipt, note). None means the impact set could not be computed."""
    import impact as impact_mod  # sibling tool, reused as a library (bundled)

    gp = workdir / f"graph-{base[:12]}.json"
    graph = build_graph_at(repo, base, gp)
    if graph is None:
        return None, f"the graph could not be built at {base[:12]} — nothing to compute an impact set from"
    man = graph["manifest"]

    cs_files, fallback_files = [], []
    for f in files:
        kind = impact_mod.classify_file(f["path"], None)
        cs_files.append({"path": f["path"], "status": f["status"], "kind": kind, "node_id": None})
        if kind in impact_mod.FALLBACK_KINDS:
            fallback_files.append(f["path"])
    if not fallback_files:
        return None, ("no changed path classifies as a lockfile or a global config, so the whole-repository "
                      "fallback does not apply and this path has no impact set to stand on")

    total_nodes = len(graph.get("nodes") or [])
    captured = datetime.now(timezone.utc)
    ttl = int(author.get("exemption_ttl_days") or 30)
    expires = (captured + timedelta(days=ttl)).strftime("%Y-%m-%dT%H:%M:%SZ")
    repo_entity = f"repository:{repo_name}"
    authorship_entity = f"receipt_authorship:{repo_name}@{head[:12]}"

    concl = (verifier_conclusion or "").strip().lower()
    repo_verdict = CONCLUSION_TO_VERDICT.get(concl, "not_measured")
    exit_code = 0 if repo_verdict == "verified" else (1 if repo_verdict == "failed" else None)
    verifier = {
        "id": "repo-own-test-job",
        "kind": "other",
        "command": (f"GitHub Actions job {verifier_job!r} on {head[:12]} — the repository's OWN suite"
                    if verifier_job else "the repository's own test job — NOT NAMED by the caller"),
        "entities": [repo_entity],
        "exit_code": exit_code if exit_code is not None else 125,
        "output_ref": verifier_output_ref or f"github-actions:{repo_name}@{head[:12]}:{verifier_job or 'unnamed'}",
        "conclusion": concl or None,
        "note": ("verifier-matrix.v1.json defines `targeted_test` as tests covering the affected node, «never the "
                 "whole suite» — this is the whole suite, so it is recorded as kind `other`, which is what it is. "
                 "It is the verifier DEC-AUP-0008 prescribes for a global fallback (the Bazel/Nx rule): the "
                 "blast radius is the repository, so the repository's own suite is what must be green."),
    }
    verdicts = [
        {"entity": repo_entity, "verdict": repo_verdict,
         **({"verifier_ids": ["repo-own-test-job"]} if repo_verdict == "verified" else {}),
         "reason": (f"the repository's own test job {verifier_job!r} concluded {concl!r}"
                    if concl else
                    "the caller named no required verifier job, or its conclusion was not reported to the gate — "
                    "an unreported job is not a green one (DEC-AUP-0008 I4)")},
        {"entity": authorship_entity, "verdict": "not_measured",
         "reason": ("no agent-authored ChangeAdmissionReceipt/v1 exists for this change: it was opened by a "
                    f"registered automated author ({author.get('login')}), which cannot run the graph tooling. "
                    "This entity is the MISSING AUTHOR, not a missing measurement of the code.")},
    ]
    exemptions = [{
        "entity": authorship_entity,
        "code": author.get("exemption_code") or "AUTOMATED_DEPENDENCY_UPDATE",
        "owner": (policy.get("automated_authors") or {}).get("authors", [{}])[0].get("exemption_owner")
                 or author.get("exemption_owner") or "",
        "expires_at_utc": expires,
        "reason": ((policy.get("automated_authors") or {}).get("what_the_exemption_is_about") or "")
                  or "the receipt author is typed; verification is not exempted",
        "scope": ("receipt AUTHORSHIP only. It does not carry, and must never be extended to carry, "
                  f"{repo_entity} — if the repository's own test job is not green that entity is failed or "
                  "not_measured on its own and the change is refused or paused."),
        "evidence": event_evidence,
    }]
    adm = "admitted_with_exemptions" if repo_verdict == "verified" else (
        "refused" if repo_verdict == "failed" else "paused_safe")
    receipt = {
        "schema": "ChangeAdmissionReceipt/v1",
        "receipt_id": f"car-automated-{head[:12]}-{captured.strftime('%Y%m%dT%H%M%SZ')}",
        "captured_at_utc": captured.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {"tool": TOOL, "version": VERSION, "path": "automated_author"},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "decision_ref": "DEC-AUP-0008",
        "portion_id": "AUP-GRAPH-006:gate2a",
        "work_item": None,
        "authored_by": {
            "path": "automated_author",
            "rule": (policy.get("automated_authors") or {}).get("identity_rule", ""),
            **event_evidence,
        },
        "repo": {"name": repo_name, "path": str(repo)},
        "graph": {"source_commit": base, "graph_digest": man["graph_digest"],
                  "builder_version": man.get("builder_version") or man.get("version") or "unknown",
                  "built_at_utc": man.get("built_at_utc") or captured.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "nodes": total_nodes, "edges": len(graph.get("edges") or [])},
        "tree": {"commit": head, "dirty": False},
        "staleness": {"method": "the graph is built here, from git objects, at change_set.base",
                      "verdict": "fresh", "mismatched_nodes": []},
        "change_set": {"mode": "diff", "base": base, "head": head, "files": cs_files},
        "impact_set": {
            "method": ("global fallback: a lockfile / global-config change makes every node of the graph affected "
                       "(DEC-AUP-0008, the Bazel/Nx rule). The entities are NOT enumerated here: the verifier for "
                       "this impact is the repository's own test job, which makes one statement about the whole "
                       "repository, not one statement per node — enumerating would dress a single measurement up "
                       f"as {total_nodes} of them."),
            "scope": "whole_repository",
            "enumerated": False,
            "deterministic_core": [],
            "inferred_tail": [],
            "global_fallback": {"triggered": True, "files": fallback_files, "scope": "whole_repository",
                                "total_nodes": total_nodes,
                                "reason": (f"{', '.join(fallback_files)} changed ⇒ every node affected "
                                           f"(lockfile / global config: safe fallback, Bazel/Nx practice); "
                                           f"{total_nodes} nodes in the graph at {base[:12]}")},
            "total": total_nodes,
        },
        "verifiers": [verifier],
        "verdicts": verdicts,
        "exemptions": exemptions,
        "admission": {
            "verdict": adm,
            "rule": ("admitted_with_exemptions requires every non-verified entity to carry a valid exemption "
                     "(owner + expiry). Here exactly one entity is exempted — the missing agent-authored receipt. "
                     "The repository entity is never exempted: it is verified by the repository's own test job, "
                     "or it is failed / not_measured and this receipt refuses or pauses the change itself."),
        },
    }
    return receipt, (f"authored for {author.get('login')}: {len(cs_files)} allowlisted path(s), "
                     f"global fallback over {total_nodes} nodes, repository entity {repo_verdict}")


def gate(repo: Path, base: str, head: str, receipt_paths: list[Path], policy: dict, *,
         description: str = "", bypass_flag: bool = False, disabled: frozenset[str] = frozenset(),
         work_item_enforcement: str | None = None, ledger_dir: Path = LEDGER_DIR,
         repo_name: str | None = None, explicit_receipts: bool = True,
         event: dict | None = None, verifier_job: str | None = None,
         verifier_conclusion: str | None = None, verifier_output_ref: str | None = None,
         automated_workdir: Path | None = None) -> dict:
    checks: list[dict] = []
    enforcement = work_item_enforcement or policy["work_item_evidence"]["enforcement"]
    pol_checks = {c["id"]: c for c in policy["checks"]}

    def add(cid: str, detail: str, entities=None, verdict=None):
        if cid in disabled:
            return
        spec = pol_checks[cid]
        checks.append({"id": cid, "code": spec["code"], "verdict": verdict or spec["verdict"],
                       "detail": detail, **({"entities": entities[:40]} if entities else {})})

    desc_l = (description or "").lower()

    # C01 — bypass refused before any lookup
    env_bypass = [k for k in ("AUP_SKIP_RECEIPT", "AUP_ADMIT_BYPASS") if os.environ.get(k)]
    phrases = [p for p in pol_checks["C01"]["bypass_phrases"] if p in desc_l]
    if bypass_flag or env_bypass or phrases:
        src = (["--skip-receipt"] if bypass_flag else []) + [f"env:{k}" for k in env_bypass] + [f"phrase:{p}" for p in phrases]
        add("C01", "bypass attempt: " + ", ".join(src))

    commits = range_commits(repo, base, head)
    files = range_files(repo, base, head)
    changed = {f["path"] for f in files}

    # --- AUP-GRAPH-006:gate2a — the typed automated-author path -------------------------------
    # It runs BEFORE the receipt binding, and its only effect is to ADD a receipt to the list that
    # every downstream check then examines. Nothing downstream knows or cares who wrote a receipt.
    automated = {"eligible": False, "receipt_path": None}
    au_spec, au_evidence = match_automated_author(policy, event)
    automated["author_match"] = au_evidence
    if au_spec is not None:
        allowed = au_spec.get("path_allowlist") or []
        inside, outside = allowlist_split(sorted(changed), allowed)
        automated["path_allowlist"] = {"inside": inside, "outside": outside}
        if outside:
            add("C15", f"{au_spec.get('login')} authored this pull request, but {len(outside)} changed path(s) are "
                       f"outside the dependency-manifest allowlist ({', '.join(outside[:4])}"
                       f"{' …' if len(outside) > 4 else ''}) — no exemption is issued and the ordinary rule applies")
        else:
            wd = Path(automated_workdir) if automated_workdir else Path(tempfile.mkdtemp(prefix="gate2a-"))
            wd.mkdir(parents=True, exist_ok=True)
            rec_doc, note = synthesize_automated_receipt(
                repo, base, head, files, au_spec, policy,
                repo_name=repo_name or repo_remote_name(repo), verifier_job=verifier_job,
                verifier_conclusion=verifier_conclusion, verifier_output_ref=verifier_output_ref,
                workdir=wd, event_evidence=au_evidence)
            automated["note"] = note
            if rec_doc is None:
                add("C15", f"{au_spec.get('login')}: the gate could not author a receipt — {note}")
            else:
                rp = wd / "automated-author-receipt.json"
                write_json(rp, rec_doc)
                receipt_paths = list(receipt_paths) + [rp]
                automated.update({"eligible": True, "receipt_path": str(rp),
                                  "receipt_id": rec_doc["receipt_id"],
                                  "admission": rec_doc["admission"]["verdict"],
                                  "exemption_code": rec_doc["exemptions"][0]["code"]})
                add("C14", f"{au_spec.get('login')} is a registered automated author (matched on "
                           f"pull_request.user.login+id+type, NOT on the branch name "
                           f"{au_evidence.get('author', {}).get('claimed_head_ref')!r}); {note}. The receipt the "
                           f"gate authored is checked exactly like any other receipt below.")
    elif event is not None and au_evidence.get("reason"):
        add("C15", au_evidence["reason"])

    # bind receipts
    bound, unbound = [], []
    for p in receipt_paths:
        doc, err = read_receipt(p)
        rec = {"path": str(p), "digest": sha256_file(p) if p.exists() else None}
        if doc is None:
            rec.update({"bound": False, "reason": f"unreadable: {err}"})
            unbound.append(rec)
            continue
        if not str(doc.get("schema", "")).startswith("ChangeAdmissionReceipt"):
            continue  # a document that merely mentions the schema (a dossier, a readiness receipt) is not a receipt
        rec["receipt_id"] = doc.get("receipt_id")
        ok, why = receipt_binds(repo, doc, base, head, set(commits))
        rec.update({"bound": ok, "reason": why})
        (bound if ok else unbound).append(rec | {"_doc": doc})

    # C05 — a receipt was named for this change but belongs to another range
    if explicit_receipts:
        for rec in unbound:
            add("C05", f"{Path(rec['path']).name}: {rec['reason']}")

    # C02 / C03 — no receipt at all
    if not bound:
        claim = [m for m in pol_checks["C02"]["claim_markers"] if m in desc_l]
        if claim:
            add("C02", "the change description claims verification without a receipt: " + ", ".join(claim))
        add("C03", f"no ChangeAdmissionReceipt/v1 bound to {base[:12]}..{head[:12]} "
                   f"({len(unbound)} candidate receipt(s) examined)")

    covered: set[str] = set()
    all_codes: list[str] = []
    for rec in bound:
        doc = rec["_doc"]
        cls = schema_check.classify(doc)
        rec["schema_verdict"] = cls["verdict"]
        rec["schema_codes"] = cls.get("codes", [])
        all_codes += rec["schema_codes"]
        if cls["verdict"] != "conformant":
            add("C04", f"{Path(rec['path']).name}: " + ", ".join(cls["codes"][:8]))

        cs = doc.get("change_set") or {}
        for f in cs.get("files") or []:
            if isinstance(f, dict) and isinstance(f.get("path"), str):
                covered.add(f["path"])

        stale = (doc.get("staleness") or {}).get("verdict")
        if stale != "fresh":
            add("C07", f"{Path(rec['path']).name}: staleness.verdict={stale!r}")

        # verdict aggregation with admissible exemptions
        captured = parse_iso(doc.get("captured_at_utc")) or datetime.now(timezone.utc)
        verdict_of = {v["entity"]: v.get("verdict") for v in (doc.get("verdicts") or [])
                      if isinstance(v, dict) and "entity" in v}
        valid_exempt, bad_exempt = set(), []
        for x in doc.get("exemptions") or []:
            if not isinstance(x, dict):
                bad_exempt.append("exemption is not an object")
                continue
            exp = parse_iso(x.get("expires_at_utc"))
            if not x.get("owner"):
                bad_exempt.append(f"{x.get('entity')}: no owner")
            elif exp is None:
                bad_exempt.append(f"{x.get('entity')}: no expiry")
            elif exp <= captured:
                bad_exempt.append(f"{x.get('entity')}: expired {x.get('expires_at_utc')}")
            elif x.get("entity") not in verdict_of:
                bad_exempt.append(f"{x.get('entity')}: exempts an entity that has no verdict")
            else:
                valid_exempt.add(x["entity"])
        if bad_exempt:
            add("C10", f"{Path(rec['path']).name}: " + "; ".join(bad_exempt[:6]))

        failed = sorted(e for e, v in verdict_of.items() if v == "failed" and e not in valid_exempt)
        notm = sorted(e for e, v in verdict_of.items() if v == "not_measured" and e not in valid_exempt)
        rec["entity_counts"] = {
            "verified": sum(1 for v in verdict_of.values() if v == "verified"),
            "failed": sum(1 for v in verdict_of.values() if v == "failed"),
            "not_measured": sum(1 for v in verdict_of.values() if v == "not_measured"),
            "exempted": len(valid_exempt),
        }
        if failed:
            add("C08", f"{Path(rec['path']).name}: {len(failed)} entity(ies) failed without an exemption", failed)
        if notm:
            add("C09", f"{Path(rec['path']).name}: {len(notm)} entity(ies) not_measured without an exemption", notm)

        av = (doc.get("admission") or {}).get("verdict")
        rec["admission"] = av
        if av == "paused_safe":
            add("C11", f"{Path(rec['path']).name}: the receipt itself pauses the change", verdict="paused_safe")
        elif av not in ("admitted", "admitted_with_exemptions"):
            add("C11", f"{Path(rec['path']).name}: admission.verdict={av!r}")

        # C12 — inferred/observed hop onto a service boundary without a canary
        canary_entities = {e for v in (doc.get("verifiers") or [])
                           if isinstance(v, dict) and v.get("kind") == "canary" for e in (v.get("entities") or [])}
        imp = doc.get("impact_set") or {}
        boundary = []
        for section in ("deterministic_core", "inferred_tail"):
            for e in imp.get(section) or []:
                if not isinstance(e, dict) or e.get("boundary") not in ("service", "repo"):
                    continue
                hops = e.get("path") if isinstance(e.get("path"), list) else []
                if any(isinstance(h, dict) and h.get("provenance") in ("inferred", "observed") for h in hops):
                    if e["entity"] not in canary_entities and e["entity"] not in valid_exempt:
                        boundary.append(e["entity"])
        if boundary:
            add("C12", f"{Path(rec['path']).name}: {len(boundary)} boundary entity(ies) reached over an "
                       f"inferred/observed edge with no canary", sorted(set(boundary)))

    # C06 — the receipts must cover every changed file
    if bound:
        uncovered = sorted(changed - covered)
        if uncovered:
            add("C06", f"{len(uncovered)}/{len(changed)} changed file(s) are absent from the receipt change_set",
                uncovered)

    # C13 — work-item evidence attachment
    evidence = {"enforcement": enforcement, "entries": [], "status": "not_measured"}
    if bound and enforcement != "off":
        missing = []
        for rec in bound:
            doc = rec["_doc"]
            wi = doc.get("work_item")
            digest = rec["digest"]
            entry = ledger_lookup(ledger_dir, wi, digest)
            evidence["entries"].append({"receipt": Path(rec["path"]).name, "work_item": wi,
                                        "ledger": bool(entry),
                                        "delivery": (entry or {}).get("delivery", {}).get("status")})
            if not wi:
                missing.append(f"{Path(rec['path']).name}: receipt.work_item is null")
            elif not entry:
                missing.append(f"{Path(rec['path']).name}: no ledger entry with digest {str(digest)[:19]}…")
            elif enforcement == "muneral" and (entry.get("delivery") or {}).get("status") != "posted":
                missing.append(f"{Path(rec['path']).name}: Muneral delivery "
                               f"{(entry.get('delivery') or {}).get('status')!r}")
        evidence["status"] = "verified" if not missing else "not_measured"
        if missing:
            add("C13", "; ".join(missing[:6]))

    verdict = "admit"
    for c in checks:
        if VERDICT_RANK[c["verdict"]] > VERDICT_RANK[verdict]:
            verdict = c["verdict"]

    doc = {
        "schema": "AdmissionGateReceipt/v1",
        "gate_receipt_id": f"gate-{stamp()}",
        "captured_at_utc": now_iso(),
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "decision_ref": "DEC-AUP-0008",
        "policy": {"path": str(POLICY_PATH.relative_to(PROGRAM_ROOT)), "id": policy["id"],
                   "digest": sha256_bytes(canonical(policy).encode())},
        "repo": {"name": repo_name or repo_remote_name(repo), "path": str(repo)},
        "range": {"base": base, "head": head, "commits": len(commits), "files": files},
        "receipts": [{k: v for k, v in r.items() if not k.startswith("_")} for r in bound + unbound],
        "checks": checks,
        "work_item_evidence": evidence,
        "automated_author": automated,
        "verdict": verdict,
        "reason_codes": sorted({c["code"] for c in checks}),
        "exit_code": EXIT_OF[verdict],
        "rule": policy["purpose"],
        "disabled_checks": sorted(disabled),
    }
    return doc


def repo_remote_name(repo: Path) -> str:
    try:
        url = git(repo, "remote", "get-url", "origin").strip()
    except RuntimeError:
        return repo.name
    m = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?$", url)
    return m.group(1) if m else repo.name


# ------------------------------------------------------------------ work-item evidence ledger
def ledger_path(ledger_dir: Path, work_item) -> Path | None:
    wid = work_item_id(work_item)
    return (ledger_dir / f"{wid}.json") if wid else None


def work_item_id(work_item) -> str | None:
    if isinstance(work_item, str):
        return work_item
    if isinstance(work_item, dict):
        for k in ("id", "task_id", "key", "card"):
            if work_item.get(k):
                return str(work_item[k])
    return None


def ledger_lookup(ledger_dir: Path, work_item, digest: str | None) -> dict | None:
    p = ledger_path(ledger_dir, work_item)
    if not p or not p.exists() or not digest:
        return None
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for a in doc.get("attachments", []):
        if (a.get("evidence_ref") or {}).get("digest") == digest:
            return a
    return None


def build_attachment(receipt_path: Path, doc: dict, work_item: str, label: str, uri: str | None,
                     muneral_task_id: str | None = None) -> dict:
    digest = sha256_file(receipt_path)
    try:
        rel = str(receipt_path.resolve().relative_to(PROGRAM_ROOT))
    except ValueError:
        rel = str(receipt_path)
    return {
        "schema": "WorkItemEvidenceAttachment/v1",
        "attachment_kind": "evidence",
        "work_item": {"system": "muneral", "task_id": work_item, "muneral_task_id": muneral_task_id,
                      "epic": doc.get("work_item", {}).get("epic") if isinstance(doc.get("work_item"), dict) else None},
        "evidence_ref": {
            "uri": f"{uri or 'aup://arcanada-universal-program/'}{rel}"[:512],
            "digest": digest,
            "contentType": "application/json",
            "label": label[:128],
        },
        "receipt_path": rel,
        "receipt_id": doc.get("receipt_id"),
        "attached_at_utc": now_iso(),
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "delivery": {"target": "muneral", "status": "not_measured",
                     "reason_code": "MUNERAL_NO_WORK_ITEM_EVIDENCE_ROUTE",
                     "checked_at_utc": now_iso(), "probe": []},
    }


MUNERAL_CANDIDATE_ROUTES = [
    ("POST", "/tasks/{id}/evidence"),
    ("POST", "/tasks/{id}/attachments"),
    ("POST", "/tasks/{id}/receipts"),
    ("POST", "/work-items/{id}/evidence"),
]


def muneral_probe(task_id: str, key: str, base_url: str, ua: str) -> list[dict]:
    """Read-only discovery: does a work-item evidence route exist for an agent key?

    A 404 says the route does not exist; 401/403 says it exists but rejects an agent key.
    Probes are GETs — this function never writes to Muneral and never touches a status route.
    """
    out = []
    for _method, tmpl in MUNERAL_CANDIDATE_ROUTES:
        path = tmpl.format(id=task_id)
        req = urllib.request.Request(base_url + path, method="GET",
                                     headers={"Authorization": f"Bearer {key}", "User-Agent": ua})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except OSError as e:
            code = f"error:{type(e).__name__}"
        out.append({"probe": f"GET {path}", "status": code})
    return out


def cmd_attach(a) -> int:
    policy = load_policy(a.policy)
    receipt_path = Path(a.receipt).resolve()
    doc, err = read_receipt(receipt_path)
    if doc is None:
        print(f"unreadable receipt: {err}", file=sys.stderr)
        return 2
    wi = a.work_item or work_item_id(doc.get("work_item"))
    if not wi:
        print("no work item: pass --work-item or set receipt.work_item", file=sys.stderr)
        return 2
    att = build_attachment(receipt_path, doc, wi, a.label or f"ChangeAdmissionReceipt/v1 {doc.get('receipt_id')}",
                           a.uri, a.muneral_task_id)

    if a.post:
        key = os.environ.get("MUNERAL_API_KEY")
        m = policy["work_item_evidence"]["muneral"]
        if not key:
            att["delivery"]["reason_code"] = "NO_MUNERAL_API_KEY"
        else:
            att["delivery"]["probe"] = muneral_probe(a.muneral_task_id or wi, key, m["base_url"], m["user_agent"])
            live = [p for p in att["delivery"]["probe"] if p["status"] not in (404,)]
            att["delivery"]["checked_at_utc"] = now_iso()
            if not live:
                att["delivery"]["reason_code"] = "MUNERAL_NO_WORK_ITEM_EVIDENCE_ROUTE"
            else:
                att["delivery"]["reason_code"] = "MUNERAL_EVIDENCE_ROUTE_PRESENT_NOT_POSTED"
                att["delivery"]["note"] = ("a candidate route answered; posting is enabled only after the route "
                                           "is declared in admission-gate.v1.json work_item_evidence.muneral.evidence_route")

    ledger_dir = Path(a.ledger_dir) if a.ledger_dir else LEDGER_DIR
    p = ledger_path(ledger_dir, wi)
    ledger = {"schema": "WorkItemEvidenceLedger/v1", "work_item": wi, "system": "muneral", "attachments": []}
    if p.exists():
        try:
            ledger = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    existing = {(x.get("evidence_ref") or {}).get("digest") for x in ledger.get("attachments", [])}
    if att["evidence_ref"]["digest"] in existing:
        for i, x in enumerate(ledger["attachments"]):
            if (x.get("evidence_ref") or {}).get("digest") == att["evidence_ref"]["digest"]:
                ledger["attachments"][i] = att | {"attached_at_utc": x.get("attached_at_utc", att["attached_at_utc"])}
    else:
        ledger["attachments"].append(att)
    ledger["updated_at_utc"] = now_iso()
    write_json(p, ledger)
    print(json.dumps({"ledger": str(p), "work_item": wi, "digest": att["evidence_ref"]["digest"],
                      "delivery": att["delivery"]["status"], "reason_code": att["delivery"].get("reason_code")},
                     ensure_ascii=False))
    return 0


# ------------------------------------------------------------------ charter scan
def classify_line(path: str, line: str, policy: dict) -> str:
    tp = policy["tdd_policy"]
    low = line.lower()
    if any(m in path for m in tp["historical_path_markers"]):
        return "historical"
    # a line that describes the scanner itself (or a grep marker) prescribes nothing; the markers are enumerated in
    # the policy so that every line treated this way stays visible in the receipt under its own class
    if any(m in low for m in tp["meta_markers"]):
        return "meta_classifier_reference"
    if any(m in low for m in tp["opt_in_patterns"]):
        return "opt_in_reference"
    if any(m in low for m in tp["mandate_patterns"]):
        return "mandate_default"
    return "neutral_mention"


HIT_RE = re.compile(r"\bTDD\b|test-first|test first|Iron Law|tdd-required|tdd-discipline", re.IGNORECASE)


def git_surface_files(repo: Path, ref: str, path: str, glob: str | None) -> list[tuple[str, str]]:
    """(display path, content) for a charter surface read from a git ref — the authoritative document is the one on
    main, not the state a shared checkout happens to be parked at (program CLAUDE.md § Authority)."""
    listing = git(repo, "ls-tree", "-r", "--name-only", ref, "--", path).splitlines()
    out = []
    for f in listing:
        rel = f[len(path):].lstrip("/") if f != path else f
        if glob and f != path and not fnmatch.fnmatch(rel, glob):
            continue
        out.append((f, git(repo, "show", f"{ref}:{f}")))
    return out


def scan_surface(spec: dict, policy: dict) -> dict:
    if spec.get("repo"):
        repo, ref = Path(spec["repo"]), spec.get("ref", "origin/main")
        res = {"host": spec["host"], "path": f"{spec['repo']}@{ref}:{spec['path']}", "kind": spec["kind"],
               "hits": [], "status": "verified", "files_scanned": 0, "in_charter": spec.get("in_charter", True),
               "source": {"repo": spec["repo"], "ref": ref, "commit": git(repo, "rev-parse", ref).strip(),
                          "note": "authoritative content read from the git ref, not from the working tree"}}
        if spec.get("note"):
            res["note"] = spec["note"]
        files = git_surface_files(repo, ref, spec["path"], spec.get("glob"))
        res["files_scanned"] = len(files)
        for name, text in files:
            for i, line in enumerate(text.splitlines(), 1):
                if HIT_RE.search(line):
                    res["hits"].append({"file": name, "line": i, "class": classify_line(name, line, policy),
                                        "text": line.strip()[:200]})
        res["violations"] = [h for h in res["hits"] if h["class"] == "mandate_default"]
        if res["violations"]:
            res["status"] = "failed" if res["in_charter"] else "recorded_out_of_charter"
        return res
    p = Path(os.path.expanduser(spec["path"]))
    res = {"host": spec["host"], "path": spec["path"], "kind": spec["kind"], "hits": [],
           "status": "verified", "files_scanned": 0, "in_charter": spec.get("in_charter", True)}
    if spec.get("note"):
        res["note"] = spec["note"]
    if spec.get("writable") is False:
        res["writable"] = False
    if spec.get("reachable") is False:
        res["status"] = "not_measured"
        res["reason"] = spec.get("reason", "surface not reachable from this host")
        return res
    files: list[Path] = []
    if p.is_file():
        files = [p]
    elif p.is_dir():
        pattern = spec.get("glob", "*.md")
        files = sorted(f for f in p.rglob("*") if f.is_file() and fnmatch.fnmatch(str(f.relative_to(p)), pattern))
    elif spec.get("absent_is_clean"):
        res["status"] = "verified"
        res["reason"] = "surface absent: it defines nothing, therefore it mandates nothing"
        return res
    else:
        res["status"] = "not_measured"
        res["reason"] = "path does not exist on this host"
        return res
    res["files_scanned"] = len(files)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            res["hits"].append({"file": str(f), "line": 0, "class": "not_measured", "text": str(e)[:120]})
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if HIT_RE.search(line):
                res["hits"].append({"file": str(f), "line": i,
                                    "class": classify_line(str(f), line, policy),
                                    "text": line.strip()[:200]})
    res["violations"] = [h for h in res["hits"] if h["class"] == "mandate_default"]
    if res["violations"]:
        res["status"] = "failed" if res["in_charter"] else "recorded_out_of_charter"
    return res


def cmd_charter_scan(a) -> int:
    policy = load_policy(a.policy)
    surfaces = policy["tdd_policy"]["charter_surfaces"]
    if a.host:
        surfaces = [s for s in surfaces if s["host"] == a.host]
    results = [scan_surface(s, policy) for s in surfaces]
    counts = {}
    for r in results:
        for h in r["hits"]:
            counts[h["class"]] = counts.get(h["class"], 0) + 1
    in_charter = [r for r in results if r["in_charter"]]
    verdict = ("failed" if any(r["status"] == "failed" for r in in_charter)
               else "not_measured" if any(r["status"] == "not_measured" for r in in_charter)
               else "verified")
    out_of_charter = sum(len(r.get("violations", [])) for r in results if not r["in_charter"])
    doc = {"schema": "CharterScanReceipt/v1", "captured_at_utc": now_iso(),
           "producer": {"tool": TOOL, "version": VERSION}, "model": MODEL,
           "provisional_until_fable_review": True,
           "measure": "AM3 — a search for TDD across the live charters returns only opt-in contexts",
           "pattern": HIT_RE.pattern, "surfaces": results, "class_counts": counts, "verdict": verdict,
           "in_charter_surfaces": len(in_charter),
           "out_of_charter_mandate_hits": out_of_charter,
           "note": "verdict verified requires zero mandate_default hits on every reachable surface; an unreachable "
                   "surface keeps the whole measure not_measured — a charter updated on one host only is a failure "
                   "condition of AUP-GRAPH-006"}
    if a.out:
        write_json(Path(a.out), doc)
    print(json.dumps({"verdict": verdict, "class_counts": counts,
                      "out_of_charter_mandate_hits": out_of_charter,
                      "surfaces": [{"host": r["host"], "path": r["path"], "status": r["status"],
                                    "in_charter": r["in_charter"], "hits": len(r["hits"]),
                                    "violations": len(r.get("violations", []))}
                                   for r in results]}, ensure_ascii=False, indent=1))
    return 0 if verdict == "verified" else (3 if verdict == "not_measured" else 5)


# ------------------------------------------------------------------ PR / merge coverage
def cmd_pr_coverage(a) -> int:
    policy = load_policy(a.policy)
    repo = Path(a.repo).resolve()
    since = a.since or policy["scope"]["enabled_at_utc"]
    receipts = discover_receipts([Path(d) if Path(d).is_absolute() else repo / d
                                  for d in (a.receipt_dir or ["receipts"])])
    heads: dict[str, list[str]] = {}
    for p in receipts:
        doc, _ = read_receipt(p)
        if not isinstance(doc, dict):
            continue
        cs = doc.get("change_set") or {}
        for c in (cs.get("head"), (doc.get("tree") or {}).get("commit")):
            if isinstance(c, str) and len(c) == 40:
                heads.setdefault(c, []).append(str(p.relative_to(repo)) if p.is_relative_to(repo) else str(p))
    log = git(repo, "log", f"--since={since}", "--format=%H%x09%ct%x09%s", a.rev or "HEAD")
    rows = []
    for line in log.splitlines():
        if not line.strip():
            continue
        sha, ts, subject = line.split("\t", 2)
        covered = sha in heads
        rows.append({"commit": sha, "at_utc": datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "subject": subject[:120], "receipt": heads.get(sha, [])[:3], "covered": covered})
    n = len(rows)
    cov = sum(1 for r in rows if r["covered"])
    doc = {"schema": "AdmissionCoverageReceipt/v1", "captured_at_utc": now_iso(),
           "producer": {"tool": TOOL, "version": VERSION}, "model": MODEL,
           "provisional_until_fable_review": True,
           "measure": "AM1 — share of changes in a pilot repository that carry a ChangeAdmissionReceipt/v1",
           "repo": repo_remote_name(repo), "since_utc": since, "rev": a.rev or "HEAD",
           "window": {"enabled_at_utc": policy["scope"]["enabled_at_utc"],
                      "ends_utc": policy["scope"]["coverage_window_ends_utc"],
                      "phase": "baseline" if since <= policy["scope"]["enabled_at_utc"] else "window"},
           "counts": {"commits": n, "with_receipt": cov, "without_receipt": n - cov},
           "coverage": round(cov / n, 4) if n else None,
           "method": "a commit is covered when a ChangeAdmissionReceipt/v1 in the repository names it as "
                     "change_set.head or tree.commit; receipts written before the gate existed are historical (I14) "
                     "and are counted, never re-verified",
           "commits": rows}
    if a.out:
        write_json(Path(a.out), doc)
    print(json.dumps({k: doc[k] for k in ("repo", "since_utc", "counts", "coverage")}, ensure_ascii=False))
    return 0


# ------------------------------------------------------------------ fixtures
def base_receipt(base: str, head: str, *, wi="AUP-GRAPH-006") -> dict:
    return {
        "schema": "ChangeAdmissionReceipt/v1",
        "receipt_id": "car-fixture",
        "captured_at_utc": "2026-09-05T12:00:00Z",
        "producer": {"tool": "tools/graph/verify.py", "version": "1.0.0"},
        "decision_ref": "DEC-AUP-0008",
        "repo": {"name": "Arcanada-one/fixture"},
        "graph": {"source_commit": base, "graph_digest": "sha256:" + "a" * 64,
                  "builder_version": "1.0.0", "built_at_utc": "2026-09-05T11:00:00Z"},
        "tree": {"commit": head, "dirty": False},
        "staleness": {"method": "graph.source_commit == change_set.base; clean tree", "verdict": "fresh",
                      "checked_at_utc": "2026-09-05T12:00:00Z"},
        "change_set": {"mode": "diff", "base": base, "head": head, "files": [
            {"path": "src/a.ts", "status": "M", "kind": "code", "node_id": "code_unit:src/a.ts"},
            {"path": "src/c.ts", "status": "A", "kind": "code", "node_id": "code_unit:src/c.ts"}]},
        "impact_set": {"method": "reverse traversal (GRAPH-003)", "max_depth": 3,
                       "deterministic_core": [{"entity": "code_unit:src/b.ts", "depth": 1, "path": [
                           {"from": "code_unit:src/b.ts", "to": "code_unit:src/a.ts",
                            "edge_type": "imports", "provenance": "deterministic"}]}],
                       "inferred_tail": [], "global_fallback": {"triggered": False}},
        "verifiers": [{"id": "v-tsc", "kind": "type_check", "command": "tsc --noEmit",
                       "entities": ["code_unit:src/a.ts", "code_unit:src/b.ts", "code_unit:src/c.ts"],
                       "exit_code": 0, "output_ref": "verifier-out/tsc.txt"}],
        "verdicts": [{"entity": e, "verdict": "verified", "verifier_ids": ["v-tsc"], "reason": "tsc exit 0"}
                     for e in ("code_unit:src/a.ts", "code_unit:src/b.ts", "code_unit:src/c.ts")],
        "exemptions": [],
        "admission": {"verdict": "admitted", "rule": "admitted requires every verdict = verified"},
        "work_item": {"system": "muneral", "id": wi},
    }


def make_fixtures(base: str, head: str) -> dict[str, dict]:
    """name -> {receipt|None, expect_verdict, expect_codes, description, kwargs}"""
    F: dict[str, dict] = {}

    def add(name, expect, codes, desc, mutate=None, extra=None, **kw):
        r = base_receipt(base, head)
        if mutate:
            mutate(r)
        F[name] = {"receipt": r, "expect_verdict": expect, "expect_codes": codes, "description": desc,
                   "extra": extra or [], "kwargs": kw}

    add("conformant-admit", "admit", [], "a conformant receipt bound to the range, every entity verified")

    def exempt(r):
        r["verdicts"][1] = {"entity": "code_unit:src/b.ts", "verdict": "not_measured",
                            "reason": "no verifier covers a generated file"}
        r["exemptions"] = [{"entity": "code_unit:src/b.ts", "reason": "generated file, covered by the generator's own receipt",
                            "owner": "AUP-E29 executor aup-graph", "expires_at_utc": "2026-12-05T00:00:00Z"}]
        r["admission"] = {"verdict": "admitted_with_exemptions",
                          "rule": "admitted_with_exemptions requires every non-verified entity to carry a valid exemption"}
    add("conformant-admit-with-exemptions", "admit", [],
        "one not_measured entity carried by an exemption with owner and expiry", exempt)

    F["violation-RECEIPT_MISSING"] = {"receipt": None, "expect_verdict": "refuse",
                                      "expect_codes": ["RECEIPT_MISSING"], "extra": [],
                                      "description": "negative control: no receipt at all", "kwargs": {}}
    F["violation-RECEIPT_REPLACED_BY_CHECKBOX"] = {
        "receipt": None, "expect_verdict": "refuse",
        "expect_codes": ["RECEIPT_MISSING", "RECEIPT_REPLACED_BY_CHECKBOX"],
        "description": "the pull-request description claims «[x] graph-verified» and carries no receipt",
        "extra": [], "kwargs": {"description": "Refactor tasks module\n\n- [x] graph-verified\n"}}
    F["violation-MANUAL_BYPASS_REFUSED"] = {
        "receipt": None, "expect_verdict": "refuse",
        "expect_codes": ["MANUAL_BYPASS_REFUSED", "RECEIPT_MISSING"],
        "description": "a bypass flag refuses before any receipt lookup", "extra": [], "kwargs": {"bypass_flag": True}}
    F["violation-MANUAL_BYPASS_REFUSED-with-receipt"] = {
        "receipt": base_receipt(base, head), "expect_verdict": "refuse",
        "expect_codes": ["MANUAL_BYPASS_REFUSED"],
        "description": "even a conformant receipt does not survive a bypass phrase in the description",
        "extra": [], "kwargs": {"description": "hotfix: skip-graph-verify, ship it"}}

    def stale(r):
        r["staleness"]["verdict"] = "stale"
        r["staleness"]["mismatched_nodes"] = ["code_unit:src/a.ts"]
    add("violation-RECEIPT_ON_STALE_GRAPH", "refuse", ["RECEIPT_MALFORMED", "RECEIPT_ON_STALE_GRAPH"],
        "the receipt was issued on a stale graph", stale)

    def not_checked(r):
        r["staleness"]["verdict"] = "not_checked"
    add("violation-STALENESS_NOT_CHECKED", "refuse", ["RECEIPT_MALFORMED", "RECEIPT_ON_STALE_GRAPH"],
        "freshness was never checked — the graph selected nothing that can be trusted", not_checked)

    def partial(r):
        r["change_set"]["files"] = r["change_set"]["files"][:1]
        r["verdicts"] = [v for v in r["verdicts"] if v["entity"] != "code_unit:src/c.ts"]
    add("violation-CHANGE_SET_INCOMPLETE", "refuse", ["CHANGE_SET_INCOMPLETE"],
        "the receipt describes one of the two changed files", partial)

    def other_range(r):
        r["change_set"]["head"] = "b" * 40
        r["change_set"]["base"] = "c" * 40
        r["graph"]["source_commit"] = "c" * 40
        r["tree"]["commit"] = "b" * 40
    add("violation-RECEIPT_NOT_BOUND_TO_RANGE", "refuse", ["RECEIPT_MISSING", "RECEIPT_NOT_BOUND_TO_RANGE"],
        "a receipt for another branch never admits this change: it is reported as not bound AND the change counts "
        "as receipt-less", other_range)

    other = base_receipt("c" * 40, "b" * 40)
    other["receipt_id"] = "car-fixture-other-branch"
    other["tree"]["commit"] = "b" * 40
    add("violation-RECEIPT_NOT_BOUND_TO_RANGE-extra", "refuse", ["RECEIPT_NOT_BOUND_TO_RANGE"],
        "a conformant receipt for this range plus a receipt named for another branch: pointing the gate at the "
        "wrong receipt is refused, never silently ignored", extra=[other])

    def failed(r):
        r["verdicts"][1] = {"entity": "code_unit:src/b.ts", "verdict": "failed",
                            "verifier_ids": ["v-tsc"], "reason": "tsc TS2345"}
        r["admission"] = {"verdict": "refused", "rule": "failed without an exemption ⇒ refused"}
    add("violation-VERDICT_FAILED", "refuse", ["ADMISSION_NOT_ADMITTED", "VERDICT_FAILED"],
        "a failed entity refuses the change", failed)

    def notm(r):
        r["verdicts"][1] = {"entity": "code_unit:src/b.ts", "verdict": "not_measured",
                            "reason": "no verifier covers this entity"}
        r["admission"] = {"verdict": "paused_safe", "rule": "not_measured without an exemption ⇒ paused_safe"}
    add("violation-NOT_MEASURED_WITHOUT_EXEMPTION", "paused_safe",
        ["ADMISSION_NOT_ADMITTED", "NOT_MEASURED_WITHOUT_EXEMPTION"],
        "not_measured is a third verdict: the change pauses, it is never admitted", notm)

    def expired(r):
        exempt(r)
        r["exemptions"][0]["expires_at_utc"] = "2026-08-01T00:00:00Z"
    add("violation-EXEMPTION_INADMISSIBLE-expired", "refuse",
        ["EXEMPTION_INADMISSIBLE", "NOT_MEASURED_WITHOUT_EXEMPTION", "RECEIPT_MALFORMED"],
        "an expired exemption does not carry a not_measured entity", expired)

    def no_owner(r):
        exempt(r)
        r["exemptions"][0]["owner"] = ""
    add("violation-EXEMPTION_INADMISSIBLE-owner", "refuse",
        ["EXEMPTION_INADMISSIBLE", "NOT_MEASURED_WITHOUT_EXEMPTION", "RECEIPT_MALFORMED"],
        "an exemption without an owner is inadmissible", no_owner)

    def two_valued(r):
        r["verdicts"][1] = {"entity": "code_unit:src/b.ts", "verdict": "pass", "verifier_ids": ["v-tsc"]}
    add("violation-RECEIPT_MALFORMED-two-valued", "refuse", ["RECEIPT_MALFORMED"],
        "a two-valued verdict (pass) is not a tri-valued verdict", two_valued)

    def boundary(r):
        r["impact_set"]["inferred_tail"] = [{"entity": "route:GET /api/v1/tasks", "depth": 2, "boundary": "service",
                                             "path": [{"from": "route:GET /api/v1/tasks", "to": "code_unit:src/a.ts",
                                                       "edge_type": "consumes_contract", "provenance": "inferred"}]}]
        r["verdicts"].append({"entity": "route:GET /api/v1/tasks", "verdict": "verified",
                              "verifier_ids": ["v-tsc"], "reason": "provider compiles"})
    add("violation-INFERRED_BOUNDARY_WITHOUT_CANARY", "refuse",
        ["INFERRED_BOUNDARY_WITHOUT_CANARY", "RECEIPT_MALFORMED"],
        "an inferred edge across a service boundary needs a canary, never a bare verified", boundary)

    def empty_impact(r):
        r["impact_set"]["deterministic_core"] = []
        r["verdicts"] = [v for v in r["verdicts"] if v["entity"] != "code_unit:src/b.ts"]
    add("violation-EMPTY_IMPACT_WITHOUT_EXPLANATION", "refuse", ["RECEIPT_MALFORMED"],
        "an empty impact set on a code change is a prediction that must be explained", empty_impact)

    def no_wi(r):
        r["work_item"] = None
    add("violation-WORK_ITEM_EVIDENCE_MISSING", "paused_safe", ["WORK_ITEM_EVIDENCE_MISSING"],
        "a receipt that is attached to no Work Item pauses the change (evidence attachment, never a status)", no_wi)

    return F


def cmd_make_fixtures(a) -> int:
    F = make_fixtures("0" * 40, "1" * 40)
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    written = []
    for name, spec in sorted(F.items()):
        doc = {"schema": "AdmissionGateFixture/v1", "name": name, "description": spec["description"],
               "expect": {"verdict": spec["expect_verdict"], "codes": sorted(spec["expect_codes"])},
               "gate_kwargs": spec["kwargs"],
               "extra_receipts": spec.get("extra") or [],
               "placeholders": {"base": "0" * 40, "head": "1" * 40,
                                "note": "the selftest rewrites both placeholders to the commits of a scratch "
                                        "repository so the git binding (C05/C06) is exercised for real"},
               "receipt": spec["receipt"]}
        p = FIXTURE_DIR / f"{name}.json"
        write_json(p, doc)
        written.append(p.name)
    readme = FIXTURE_DIR / "README.md"
    readme.write_text(
        "# Admission-gate fixtures (AUP-GRAPH-006 gate0)\n\n"
        "Each file is an `AdmissionGateFixture/v1`: a `receipt` (a ChangeAdmissionReceipt/v1 with the placeholder\n"
        "commits `000…0` = base and `111…1` = head, or `null` for the no-receipt controls), the `gate_kwargs` that\n"
        "describe how the change is presented to the gate (pull-request description, bypass flag), and the `expect`\n"
        "verdict + reason codes.\n\n"
        "`python3 tools/graph/admit_change.py --selftest` builds a scratch git repository (two commits, `src/a.ts`\n"
        "modified and `src/c.ts` added), rewrites the placeholders to its real commits, runs the gate for every\n"
        "fixture and compares verdict and codes; then it runs the mutation battery (each check disabled in turn —\n"
        "at least one fixture must stop being blocked, otherwise the check is unobservable and the mutant survives).\n\n"
        "Regenerate with `python3 tools/graph/admit_change.py --make-fixtures` (deterministic).\n",
        encoding="utf-8")
    print(json.dumps({"fixtures": len(written), "dir": str(FIXTURE_DIR.relative_to(PROGRAM_ROOT))}))
    return 0


# ------------------------------------------------------------------ selftest
def scratch_repo(root: Path) -> tuple[Path, str, str]:
    repo = root / "repo"
    repo.mkdir(parents=True)
    env = {"GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "fixture",
           "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-05T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-09-05T00:00:00Z", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "HOME": str(root)}
    def g(*args):
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)}: {r.stderr[:200]}")
        return r.stdout
    g("init", "-q", "-b", "main")
    (repo / "src").mkdir()
    (repo / "src/a.ts").write_text("export const a = 1;\n")
    (repo / "src/b.ts").write_text("import { a } from './a';\nexport const b = a + 1;\n")
    (repo / "README.md").write_text("# fixture\n")
    g("add", "-A"); g("commit", "-q", "-m", "base")
    base = g("rev-parse", "HEAD").strip()
    (repo / "src/a.ts").write_text("export const a = 2;\n")
    (repo / "src/c.ts").write_text("export const c = 3;\n")
    g("add", "-A"); g("commit", "-q", "-m", "change")
    head = g("rev-parse", "HEAD").strip()
    return repo, base, head


def run_fixture(repo: Path, base: str, head: str, spec: dict, policy: dict, workdir: Path,
                disabled=frozenset(), ledger_dir: Path | None = None) -> dict:
    paths = []
    if spec["receipt"] is not None:
        doc = json.loads(json.dumps(spec["receipt"]).replace("0" * 40, base).replace("1" * 40, head))
        p = workdir / "receipt.json"
        write_json(p, doc)
        paths = [p]
    return gate(repo, base, head, paths, policy, disabled=disabled,
                ledger_dir=ledger_dir if ledger_dir is not None else (workdir / "ledger"),
                repo_name="Arcanada-one/fixture", **spec["kwargs"])


def selftest(receipt_out: Path | None, keep: bool = False) -> int:
    policy = load_policy(None)
    root = Path(tempfile.mkdtemp(prefix="admit-selftest-"))
    results, battery = [], []
    passed = failed = 0
    try:
        repo, base, head = scratch_repo(root)
        F = make_fixtures(base, head)
        # fixtures on disk must match the generated ones (drift control)
        drift = []
        for name in F:
            p = FIXTURE_DIR / f"{name}.json"
            if not p.exists():
                drift.append(f"{name}: missing on disk")
                continue
            on_disk = json.loads(p.read_text(encoding="utf-8"))
            gen = json.loads(json.dumps(F[name]["receipt"]).replace(base, "0" * 40).replace(head, "1" * 40)) \
                if F[name]["receipt"] is not None else None
            gen_extra = json.loads(json.dumps(F[name].get("extra") or []).replace(base, "0" * 40).replace(head, "1" * 40))
            if canonical(on_disk.get("extra_receipts") or []) != canonical(gen_extra) or \
                    canonical(on_disk.get("receipt")) != canonical(gen) or \
                    on_disk["expect"]["verdict"] != F[name]["expect_verdict"] or \
                    on_disk["expect"]["codes"] != sorted(F[name]["expect_codes"]):
                drift.append(f"{name}: fixture on disk differs from the generator")
        results.append({"case": "fixture-drift", "ok": not drift, "detail": drift[:5]})
        passed, failed = (passed + 1, failed) if not drift else (passed, failed + 1)

        ledger_dir = root / "ledger"

        # 1. every fixture reaches its expected verdict and codes
        for name, spec in sorted(F.items()):
            wd = root / "wd" / name
            wd.mkdir(parents=True)
            # each fixture's receipt is re-written into wd; the ledger holds the attachment for the same bytes
            paths = []
            for i, ex in enumerate(spec.get("extra") or []):
                ep = wd / f"extra{i}.json"
                write_json(ep, json.loads(json.dumps(ex).replace("0" * 40, base).replace("1" * 40, head)))
                paths.append(ep)
            if spec["receipt"] is not None:
                doc = json.loads(json.dumps(spec["receipt"]).replace("0" * 40, base).replace("1" * 40, head))
                p = wd / "receipt.json"
                write_json(p, doc)
                paths = [p] + paths
                wi = work_item_id(doc.get("work_item"))
                if wi:
                    att = build_attachment(p, doc, wi, f"fixture {name}", None)
                    lp = ledger_path(ledger_dir, wi)
                    led = json.loads(lp.read_text(encoding="utf-8")) if lp.exists() else \
                        {"schema": "WorkItemEvidenceLedger/v1", "work_item": wi, "system": "muneral", "attachments": []}
                    led["attachments"].append(att)
                    write_json(lp, led)
            g = gate(repo, base, head, paths, policy, ledger_dir=ledger_dir,
                     repo_name="Arcanada-one/fixture", **spec["kwargs"])
            ok = g["verdict"] == spec["expect_verdict"] and g["reason_codes"] == sorted(spec["expect_codes"])
            results.append({"case": f"fixture:{name}", "ok": ok, "expect": spec["expect_verdict"],
                            "got": g["verdict"], "expect_codes": sorted(spec["expect_codes"]),
                            "got_codes": g["reason_codes"], "exit": g["exit_code"]})
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 2. determinism — the same input twice yields the same decision (timestamps excluded)
        def strip(d):
            return canonical({k: v for k, v in d.items() if k not in ("captured_at_utc", "gate_receipt_id")})
        wd = root / "wd" / "conformant-admit"
        g1 = gate(repo, base, head, [wd / "receipt.json"], policy, ledger_dir=ledger_dir, repo_name="Arcanada-one/fixture")
        g2 = gate(repo, base, head, [wd / "receipt.json"], policy, ledger_dir=ledger_dir, repo_name="Arcanada-one/fixture")
        ok = strip(g1) == strip(g2)
        results.append({"case": "determinism", "ok": ok})
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 3. environment bypass is refused too
        os.environ["AUP_SKIP_RECEIPT"] = "1"
        try:
            g3 = gate(repo, base, head, [wd / "receipt.json"], policy, ledger_dir=ledger_dir,
                      repo_name="Arcanada-one/fixture")
        finally:
            del os.environ["AUP_SKIP_RECEIPT"]
        ok = g3["verdict"] == "refuse" and "MANUAL_BYPASS_REFUSED" in g3["reason_codes"]
        results.append({"case": "env-bypass-refused", "ok": ok, "got": g3["verdict"], "codes": g3["reason_codes"]})
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 4. mutation battery — disabling a check must let at least one blocked fixture through
        battery = []
        for cid in CHECK_IDS:
            relaxed, silenced = [], []
            for name, spec in sorted(F.items()):
                if spec["expect_verdict"] == "admit":
                    continue
                wd2 = root / "wd" / name
                paths = [wd2 / "receipt.json"] + [wd2 / f"extra{i}.json" for i in range(len(spec.get("extra") or []))] \
                    if spec["receipt"] is not None else [wd2 / f"extra{i}.json" for i in range(len(spec.get("extra") or []))]
                gm = gate(repo, base, head, paths, policy, disabled=frozenset({cid}), ledger_dir=ledger_dir,
                          repo_name="Arcanada-one/fixture", **spec["kwargs"])
                if gm["reason_codes"] != sorted(spec["expect_codes"]):
                    silenced.append(name)
                if VERDICT_RANK[gm["verdict"]] < VERDICT_RANK[spec["expect_verdict"]]:
                    relaxed.append(name)
            killed = bool(silenced)
            battery.append({"check": cid, "code": {c["id"]: c["code"] for c in policy["checks"]}[cid],
                            "mutant_killed": killed, "fixtures_silenced": silenced[:6],
                            "fixtures_relaxed_to_a_weaker_verdict": relaxed[:6]})
            results.append({"case": f"mutant:{cid}", "ok": killed, "silenced": silenced[:6], "relaxed": relaxed[:6]})
            passed, failed = (passed + 1, failed) if killed else (passed, failed + 1)

        # 4b. the informational checks must in fact be informational (AUP-GRAPH-006:gate2a).
        # This is the property that exempts them from the disable battery, so it is asserted, not assumed.
        by_id = {c["id"]: c for c in policy["checks"]}
        for cid in INFORMATIONAL_CHECK_IDS:
            spec = by_id.get(cid)
            ok = bool(spec) and spec["verdict"] == "admit" and VERDICT_RANK[spec["verdict"]] == 0
            results.append({"case": f"informational:{cid}", "ok": ok,
                            "verdict": (spec or {}).get("verdict"), "code": (spec or {}).get("code"),
                            "rule": "an informational check never raises the gate verdict"})
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
        # and no check id may be in both lists
        overlap = sorted(set(CHECK_IDS) & set(INFORMATIONAL_CHECK_IDS))
        results.append({"case": "informational:disjoint", "ok": not overlap, "overlap": overlap})
        passed, failed = (passed + 1, failed) if not overlap else (passed, failed + 1)
        # every check in the policy is classified as one or the other
        unclassified = sorted({c["id"] for c in policy["checks"]} - set(CHECK_IDS) - set(INFORMATIONAL_CHECK_IDS))
        results.append({"case": "informational:policy-fully-classified", "ok": not unclassified,
                        "unclassified": unclassified})
        passed, failed = (passed + 1, failed) if not unclassified else (passed, failed + 1)

        # 5. charter-scan classification unit checks
        cls_cases = [
            ("/home/x/.claude/agents/developer.md", "- Write tests (TDD).", "mandate_default"),
            ("/home/x/.claude/agents/developer.md", "TDD is opt-in for client spaces", "opt_in_reference"),
            ("/home/x/ws/spaces/arcanada/space.yml", 'vendor_canary_marker: "tdd-discipline"', "meta_classifier_reference"),
            ("/home/x/ws/documentation/mandates/m.md", "TDD is mandatory for every change", "mandate_default"),
            ("/home/x/ws/datarim/reflection/x.md", "Iron Law: no production code without a failing test", "historical"),
            ("/home/x/ws/documentation/mandates/m.md", "verification_policy: tdd-required in space.yml", "opt_in_reference"),
        ]
        for path, line, want in cls_cases:
            got = classify_line(path, line, policy)
            ok = got == want
            results.append({"case": f"classify:{want}", "ok": ok, "got": got, "line": line[:60]})
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 6. the attachment is evidence-shaped and never a status
        p = wd / "receipt.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        att = build_attachment(p, doc, "AUP-GRAPH-006", "selftest", None)
        ok = (att["attachment_kind"] == "evidence" and att["evidence_ref"]["contentType"] == "application/json"
              and re.match(r"^sha256:[0-9a-f]{64}$", att["evidence_ref"]["digest"])
              and len(att["evidence_ref"]["uri"]) <= 512 and len(att["evidence_ref"]["label"]) <= 128
              and att["delivery"]["status"] == "not_measured"
              and "status" not in att and "transition" not in canonical(att).lower())
        results.append({"case": "attachment-shape", "ok": ok})
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

        # 7. no status/transition route is reachable from this tool
        src = Path(__file__).read_text(encoding="utf-8")
        needles = ["/trans" + "itions", "/sta" + "tus", "method=" + "\"POST\""]
        ok = not any(n in src for n in needles)
        results.append({"case": "no-status-write-path", "ok": ok})
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)

    verdict = "PASS" if failed == 0 else "FAIL"
    doc = {
        "schema": "ReadinessReceipt/v1",
        "portion_id": "AUP-GRAPH-006:gate0",
        "captured_at_utc": now_iso(),
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "decision_ref": ["DEC-AUP-0008", "DEC-AUP-0015"],
        "checks": {"passed": passed, "failed": failed, "total": passed + failed},
        "results": results,
        "battery": battery,
        "verdict": verdict,
    }
    if receipt_out:
        write_json(receipt_out, doc)
    print(json.dumps({"verdict": verdict, "passed": passed, "failed": failed}, ensure_ascii=False))
    for r in results:
        if not r["ok"]:
            print("  FAIL " + canonical(r)[:300], file=sys.stderr)
    return 0 if failed == 0 else 1


# ------------------------------------------------------------------ cli
def cmd_gate(a) -> int:
    policy = load_policy(a.policy)
    repo = Path(a.repo).resolve()
    if a.range:
        base, head = a.range.split("..", 1)
    else:
        base, head = a.base, a.head
    base = git(repo, "rev-parse", base).strip()
    head = git(repo, "rev-parse", head).strip()
    desc = a.description or ""
    if a.description_file:
        desc += "\n" + Path(a.description_file).read_text(encoding="utf-8")
    search = [Path(p) if Path(p).is_absolute() else repo / p for p in (a.receipt_dir or ["receipts"])]
    paths = [Path(p) for p in (a.receipt or [])] or discover_receipts(search)
    event = None
    if a.event_file:
        ep = Path(a.event_file)
        if ep.exists():
            try:
                event = json.loads(ep.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError as e:
                event = {"_unparsable": str(e)}
    doc = gate(repo, base, head, paths, policy, description=desc, bypass_flag=a.skip_receipt,
               work_item_enforcement=a.enforcement, explicit_receipts=bool(a.receipt),
               ledger_dir=Path(a.ledger_dir) if a.ledger_dir else LEDGER_DIR,
               repo_name=a.repo_name, event=event, verifier_job=a.verifier_job,
               verifier_conclusion=a.verifier_conclusion, verifier_output_ref=a.verifier_output_ref,
               automated_workdir=Path(a.workdir) if a.workdir else None)
    if a.out:
        write_json(Path(a.out), doc)
    if a.json:
        print(json.dumps(doc, ensure_ascii=False, indent=1))
    else:
        print(f"{doc['verdict'].upper()}  {doc['repo']['name']}  {base[:12]}..{head[:12]}  "
              f"files={len(doc['range']['files'])}  receipts={sum(1 for r in doc['receipts'] if r.get('bound'))}"
              f"  codes={','.join(doc['reason_codes']) or '-'}")
        for c in doc["checks"]:
            print(f"  [{c['verdict']}] {c['code']}: {c['detail']}")
    return doc["exit_code"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--make-fixtures", action="store_true")
    ap.add_argument("--receipt-out", type=Path, help="with --selftest: ReadinessReceipt/v1 path")
    ap.add_argument("--keep", action="store_true", help="with --selftest: keep the scratch repository")
    sub = ap.add_subparsers(dest="cmd")

    g = sub.add_parser("gate", help="admit / pause / refuse a change range")
    g.add_argument("--repo", required=True)
    g.add_argument("--range", help="<base>..<head>")
    g.add_argument("--base"), g.add_argument("--head")
    g.add_argument("--receipt", action="append", help="explicit ChangeAdmissionReceipt/v1 (repeatable)")
    g.add_argument("--receipt-dir", action="append", help="search directory (default receipts/)")
    g.add_argument("--description", default="", help="pull-request / commit description text")
    g.add_argument("--description-file")
    g.add_argument("--skip-receipt", action="store_true", help="bypass attempt — always refused (negative control)")
    g.add_argument("--enforcement", choices=["off", "ledger", "muneral"])
    g.add_argument("--ledger-dir")
    g.add_argument("--policy", type=Path)
    g.add_argument("--out")
    g.add_argument("--json", action="store_true")
    g.add_argument("--repo-name")
    g.add_argument("--event-file", help="the GitHub `pull_request` event payload (GITHUB_EVENT_PATH). The ONLY "
                                        "source of author identity for the automated-author path — never the branch name.")
    g.add_argument("--verifier-job", help="name of the repository's own test job, the verifier of a whole-repository "
                                          "(global fallback) impact")
    g.add_argument("--verifier-conclusion", help="that job's conclusion (success|failure|cancelled|timed_out|skipped); "
                                                 "anything else, or absent, is not_measured — never an assumed pass")
    g.add_argument("--verifier-output-ref", help="a URL or id the verdict can be traced to (the workflow run)")
    g.add_argument("--workdir", help="scratch directory for the graph build and an authored receipt")
    g.set_defaults(fn=cmd_gate)

    at = sub.add_parser("attach", help="attach a receipt to a Work Item as evidence (never a status)")
    at.add_argument("--receipt", required=True)
    at.add_argument("--work-item")
    at.add_argument("--muneral-task-id", help="the Muneral task uuid the evidence belongs to (receipts/muneral/*task-map*)")
    at.add_argument("--label")
    at.add_argument("--uri")
    at.add_argument("--ledger-dir")
    at.add_argument("--policy", type=Path)
    at.add_argument("--post", action="store_true", help="probe Muneral for a work-item evidence route and record it")
    at.set_defaults(fn=cmd_attach)

    cs = sub.add_parser("charter-scan", help="classify TDD / test-first hits across the live charter surfaces")
    cs.add_argument("--host")
    cs.add_argument("--policy", type=Path)
    cs.add_argument("--out")
    cs.set_defaults(fn=cmd_charter_scan)

    pc = sub.add_parser("pr-coverage", help="measure receipt coverage of the merges of a pilot repository")
    pc.add_argument("--repo", required=True)
    pc.add_argument("--since")
    pc.add_argument("--rev")
    pc.add_argument("--receipt-dir", action="append")
    pc.add_argument("--policy", type=Path)
    pc.add_argument("--out")
    pc.set_defaults(fn=cmd_pr_coverage)

    a = ap.parse_args(argv)
    if a.selftest:
        return selftest(a.receipt_out, a.keep)
    if a.make_fixtures:
        return cmd_make_fixtures(a)
    if not a.cmd:
        ap.print_help()
        return 2
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

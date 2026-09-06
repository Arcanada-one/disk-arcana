#!/usr/bin/env python3
"""AUP-GRAPH-006 `gate1` — the admission gate as a CI check (`.github/workflows/graph-admission.yml`).

DEC-AUP-0007 makes CI a POST-HOC gate: the authoritative admission is the local
`tools/graph/admit_change.py gate` run by the agent that makes the change. This driver is what the
reusable workflow executes on a pull request:

  1. `bundle`  — vendor the gate tools of a pinned program-repo SHA into a caller repository
                 (`.github/graph-admission/`) with a `BUNDLE.json` manifest of per-file sha256.
                 The program repository is private: a caller's `GITHUB_TOKEN` cannot check it out,
                 and no shared PAT exists. Vendoring keeps the promise that matters — the gate runs
                 the code of ONE pinned program SHA, never `main` — without inventing a credential.
  2. `run`     — verify the bundle, classify the change, collect the receipts, run the gate, and
                 write the check text.

Verdict mapping (the job's own status IS the `graph-admission` check):
    admit                    → green
    doc-only change          → green, verdict `not_measured`, stated in the check text
    paused_safe / refuse     → red, with the typed reason codes of the gate receipt
    no receipt               → red (`RECEIPT_MISSING`)
    bundle tampered/mismatch → red (`BUNDLE_*`)

Receipt sources (both supported, both reported):
    a) files in the pull-request head tree matching `--receipt-glob` (default the caller's
       `receipts/graph/**` and `receipts/**/change-admission-*.json`);
    b) a fenced ```json block in the PR body whose `schema` starts with `ChangeAdmissionReceipt`.
    The PR body is read from a FILE (the workflow passes it through an environment variable and a
    file, never through a shell interpolation) — a PR body is attacker-controlled text.

stdlib only (Python 3.12), deterministic, no network.
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
from pathlib import Path

TOOL = "tools/graph/ci_gate.py"
VERSION = "1.0.0"
MODEL = "claude-opus-5"
PROGRAM_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_FILES = [
    "tools/graph/admit_change.py",
    "tools/graph/schema_check.py",
    "tools/graph/build_graph.py",
    "tools/graph/ci_gate.py",
    "contracts/graph-verified-change/admission-gate.v1.json",
    "contracts/graph-verified-change/relationship-graph.v1.json",
    "contracts/graph-verified-change/change-admission-receipt.v1.json",
    "contracts/graph-verified-change/verifier-matrix.v1.json",
]
DEFAULT_RECEIPT_GLOBS = ["receipts/graph/**/*.json", "receipts/**/change-admission-*.json"]


def sha256_file(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


# --------------------------------------------------------------------------------------- bundle
def cmd_bundle(a) -> int:
    out = Path(a.out).resolve()
    ref = a.program_ref or git(PROGRAM_ROOT, "rev-parse", "HEAD").strip()
    files = []
    if getattr(a, "workflow_out", None):
        # The reusable workflow itself, vendored next to the tools. A caller CAN call it across
        # repositories (`uses: Arcanada-one/arcanada-universal-program/.github/workflows/…@<sha>`)
        # when GitHub resolves that reference; a caller whose runs fail to start on the cross-repo
        # reference calls the vendored copy locally (`uses: ./.github/workflows/graph-admission.yml`)
        # — the same file, its sha256 recorded here against the same pinned program SHA.
        wf = Path(a.workflow_out)
        wf.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROGRAM_ROOT / ".github/workflows/graph-admission.yml", wf)
        files.append({"path": ".github/workflows/graph-admission.yml", "sha256": sha256_file(wf),
                      "vendored_to": str(wf.name), "verified_by_the_job": False,
                      "note": "the workflow file itself; it is already running by the time the job checks the bundle"})
    for rel in BUNDLE_FILES:
        src = PROGRAM_ROOT / rel
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        files.append({"path": rel, "sha256": sha256_file(src)})
    manifest = {
        "schema": "GraphAdmissionBundle/v1",
        "program_repo": "Arcanada-one/arcanada-universal-program",
        "program_ref": ref,
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "files": files,
        "rule": ("The workflow refuses unless every file's sha256 matches this manifest AND the caller's "
                 "`program_ref` input matches `program_ref` here. The bundle is a VENDORED copy of one pinned "
                 "program-repo SHA (the program repository is private and no shared credential exists to check it "
                 "out from a caller's CI). A pull request that changes anything under the bundle directory is "
                 "refused by the gate job — a bundle refresh is its own pull request."),
    }
    manifest["bundle_digest"] = "sha256:" + hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    (out / "BUNDLE.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    print(f"{out}: {len(files)} files, program_ref {ref[:12]}, bundle_digest {manifest['bundle_digest'][:23]}…")
    return 0


def verify_bundle(tools: Path, program_ref: str | None) -> tuple[dict | None, list[str]]:
    """→ (manifest, problems). A problem is a typed one-line reason for the check text."""
    mp = tools / "BUNDLE.json"
    if not mp.exists():
        return None, [f"BUNDLE_MISSING: no {mp.name} under {tools}"]
    try:
        man = json.loads(mp.read_text())
    except json.JSONDecodeError as e:
        return None, [f"BUNDLE_MALFORMED: {e}"]
    problems = []
    for f in man.get("files", []):
        if f.get("verified_by_the_job") is False:
            continue
        p = tools / f["path"]
        if not p.exists():
            problems.append(f"BUNDLE_FILE_MISSING: {f['path']}")
        elif sha256_file(p) != f["sha256"]:
            problems.append(f"BUNDLE_DIGEST_MISMATCH: {f['path']} is not the file of program_ref "
                            f"{str(man.get('program_ref'))[:12]}")
    if program_ref and man.get("program_ref") != program_ref:
        problems.append(f"BUNDLE_REF_MISMATCH: caller pinned program_ref {program_ref[:12]}, "
                        f"bundle carries {str(man.get('program_ref'))[:12]}")
    return man, problems


# --------------------------------------------------------------------------------------- run
def changed_files(repo: Path, base: str, head: str) -> list[str]:
    out = git(repo, "diff", "--name-only", f"{base}..{head}")
    return [l for l in out.splitlines() if l]


def is_doc_only(paths: list[str], globs: list[str]) -> bool:
    return bool(paths) and all(any(fnmatch.fnmatch(p, g) for g in globs) for p in paths)


def receipts_from_body(body: str, workdir: Path) -> list[Path]:
    out = []
    for i, m in enumerate(re.finditer(r"```(?:json)?\s*\n(.*?)```", body, re.S)):
        try:
            doc = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and str(doc.get("schema", "")).startswith("ChangeAdmissionReceipt"):
            p = workdir / f"pr-body-receipt-{i}.json"
            p.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
            out.append(p)
    return out


def receipts_from_tree(repo: Path, globs: list[str]) -> list[Path]:
    out = []
    for g in globs:
        for p in sorted(repo.glob(g)):
            if not p.is_file():
                continue
            try:
                doc = json.loads(p.read_text())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(doc, dict) and str(doc.get("schema", "")).startswith("ChangeAdmissionReceipt"):
                out.append(p)
    return out


def cmd_run(a) -> int:
    repo = Path(a.repo).resolve()
    tools = Path(a.tools).resolve()
    work = Path(a.workdir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    base = git(repo, "rev-parse", a.base).strip()
    head = git(repo, "rev-parse", a.head).strip()
    result = {
        "schema": "GraphAdmissionCiResult/v1",
        "producer": {"tool": TOOL, "version": VERSION},
        "model": MODEL,
        "provisional_until_fable_review": True,
        "decision_refs": ["DEC-AUP-0008", "DEC-AUP-0007"],
        "repo": a.repo_name or repo.name,
        "range": {"base": base, "head": head},
        "receipt_sources": {"tree": [], "pr_body": []},
        "checks": [],
        "verdict": None,
        "conclusion": None,
        "reason_codes": [],
    }

    def fail(code: str, detail: str) -> int:
        result["verdict"] = "refused"
        result["conclusion"] = "failure"
        result["reason_codes"] = sorted(set(result["reason_codes"] + [code]))
        result["checks"].append({"code": code, "detail": detail, "verdict": "refuse"})
        return finish(1)

    def finish(rc: int) -> int:
        Path(a.out).write_text(json.dumps(result, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        lines = [f"### graph-admission — {result['verdict']} ({result['conclusion']})",
                 "",
                 f"- repository `{result['repo']}`, range `{base[:12]}..{head[:12]}`, "
                 f"{len(result['range'].get('files', []))} changed file(s)",
                 f"- receipts: {len(result['receipt_sources']['tree'])} from the head tree, "
                 f"{len(result['receipt_sources']['pr_body'])} from the pull-request body",
                 f"- reason codes: {', '.join(result['reason_codes']) or '—'}",
                 ""]
        for c in result["checks"]:
            lines.append(f"- **{c['verdict']}** `{c['code']}` — {c['detail']}")
        lines += ["", "Rule (DEC-AUP-0008, AUP-GRAPH-006): «нет receipt — нет мержа». `not_measured` is a third "
                      "verdict, never read as pass. CI is a POST-HOC gate (DEC-AUP-0007): the authoritative "
                      "admission is the local `tools/graph/admit_change.py gate` run of the agent that made the change."]
        text = "\n".join(lines) + "\n"
        if a.summary:
            Path(a.summary).write_text(text)
        print(text)
        return rc

    man, problems = verify_bundle(tools, a.program_ref)
    result["bundle"] = {"path": str(tools.relative_to(repo)) if tools.is_relative_to(repo) else str(tools),
                        "program_ref": (man or {}).get("program_ref"),
                        "bundle_digest": (man or {}).get("bundle_digest"), "problems": problems}
    if problems:
        return fail(problems[0].split(":")[0], "; ".join(problems))

    files = changed_files(repo, base, head)
    result["range"]["files"] = files
    bundle_rel = str(tools.relative_to(repo)) if tools.is_relative_to(repo) else None
    if bundle_rel:
        prefix = bundle_rel.rstrip("/") + "/"
        status = {}
        for line in git(repo, "diff", "--name-status", f"{base}..{head}").splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                status[parts[-1]] = parts[0][0]
        touched = {f: status.get(f, "?") for f in files if f.startswith(prefix)}
        edited = {f: st for f, st in touched.items() if st != "A"}
        if edited:
            # An EDIT or a DELETE of a vendored tool is the tamper path — refused. A pure ADDITION is
            # the installing pull request itself (the bundle cannot pre-exist its own installation);
            # it is recorded, and the sha256 check above still binds every added file to BUNDLE.json.
            return fail("BUNDLE_MODIFIED_BY_PR",
                        f"this pull request edits or removes {len(edited)} file(s) under the vendored gate bundle "
                        f"({', '.join(sorted(edited)[:3])}) — a bundle refresh is its own pull request, gated on its own")
        if touched:
            result["checks"].append({"code": "BUNDLE_INSTALLED_BY_PR", "verdict": "not_measured",
                                     "detail": f"this pull request ADDS the vendored gate bundle "
                                               f"({len(touched)} new file(s)); every added file matches BUNDLE.json and "
                                               f"the pinned program_ref, but a bundle installed by the very change it "
                                               f"gates is a tripwire, not a proof — CI is post-hoc (DEC-AUP-0007)."})

    policy = json.loads((tools / "contracts/graph-verified-change/admission-gate.v1.json").read_text())
    doc_globs = ((policy.get("ci_gate") or {}).get("doc_only_globs")) or []
    result["doc_only_globs"] = doc_globs
    if is_doc_only(files, doc_globs):
        result["verdict"] = "not_measured"
        result["conclusion"] = "success"
        result["reason_codes"] = ["DOC_ONLY_NOT_MEASURED"]
        result["checks"].append({"code": "DOC_ONLY_NOT_MEASURED", "verdict": "not_measured",
                                 "detail": f"every one of the {len(files)} changed path(s) matches the policy's "
                                           f"doc_only_globs — the gate measured NOTHING about code here. "
                                           f"`not_measured` is not a pass: it says no code entity was affected, so "
                                           f"no verifier was selected (DEC-AUP-0008 I4)."})
        return finish(0)

    body = ""
    if a.pr_body_file and Path(a.pr_body_file).exists():
        body = Path(a.pr_body_file).read_text(errors="replace")
    body_receipts = receipts_from_body(body, work)
    tree_receipts = receipts_from_tree(repo, a.receipt_glob or DEFAULT_RECEIPT_GLOBS)
    result["receipt_sources"]["tree"] = [str(p.relative_to(repo)) for p in tree_receipts]
    result["receipt_sources"]["pr_body"] = [p.name for p in body_receipts]
    receipts = tree_receipts + body_receipts
    cmd = [sys.executable, str(tools / "tools/graph/admit_change.py"), "gate", "--repo", str(repo),
           "--range", f"{base}..{head}", "--json", "--out", str(work / "gate.json"),
           "--enforcement", a.enforcement]
    if receipts:
        for p in receipts:
            cmd += ["--receipt", str(p)]
    else:
        # no receipt was found in either source — the GATE still runs, so that it, and not this driver,
        # types the reason (C03 RECEIPT_MISSING, or C02 RECEIPT_REPLACED_BY_CHECKBOX when the description
        # claims verification instead). Its search directory is an empty one: nothing unrelated is picked up.
        empty = work / "no-receipts"
        empty.mkdir(exist_ok=True)
        cmd += ["--receipt-dir", str(empty)]
        result["checks"].append({"code": "RECEIPT_SOURCES_EMPTY", "verdict": "refuse",
                                 "detail": "no ChangeAdmissionReceipt/v1 in the head tree "
                                           f"({', '.join(a.receipt_glob or DEFAULT_RECEIPT_GLOBS)}) and none as a "
                                           "```json block in the pull-request body. «Нет receipt — нет мержа»."})
    if a.pr_body_file and Path(a.pr_body_file).exists():
        cmd += ["--description-file", a.pr_body_file]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    try:
        gate_doc = json.loads((work / "gate.json").read_text())
    except (OSError, json.JSONDecodeError):
        return fail("GATE_TOOL_FAILED", f"admit_change.py gate exited {proc.returncode}: "
                                        f"{(proc.stderr or proc.stdout).strip()[:400]}")
    result["gate"] = {"gate_receipt_id": gate_doc.get("gate_receipt_id"), "verdict": gate_doc.get("verdict"),
                      "exit_code": gate_doc.get("exit_code"), "reason_codes": gate_doc.get("reason_codes"),
                      "receipts": gate_doc.get("receipts"), "policy": gate_doc.get("policy")}
    result["checks"] += [{"code": c["code"], "verdict": c["verdict"], "detail": c["detail"]} for c in gate_doc["checks"]]
    result["reason_codes"] = sorted(set(result["reason_codes"] + list(gate_doc.get("reason_codes") or [])))

    # the caller repository's own graph, built here from the pinned bundle, cross-checked against the receipt
    if a.build_graph:
        bound = [r for r in gate_doc.get("receipts", []) if r.get("bound")]
        for rec in bound:
            src = next((json.loads(Path(p).read_text()) for p in map(str, receipts) if Path(p).name == Path(rec["path"]).name), None)
            g = (src or {}).get("graph") or {}
            if not g.get("source_commit") or not g.get("graph_digest"):
                result["checks"].append({"code": "GRAPH_NOT_REBUILT", "verdict": "not_measured",
                                         "detail": f"{Path(rec['path']).name}: the receipt names no graph "
                                                   "source_commit/digest to rebuild against"})
                continue
            gp = work / f"graph-{g['source_commit'][:12]}.json"
            b = subprocess.run([sys.executable, str(tools / "tools/graph/build_graph.py"), str(repo),
                                "--rev", g["source_commit"], "--out", str(gp)], capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            if b.returncode != 0:
                result["checks"].append({"code": "GRAPH_BUILD_FAILED", "verdict": "not_measured",
                                         "detail": (b.stderr or b.stdout).strip()[:300]})
                continue
            built = json.loads(gp.read_text())["manifest"]["graph_digest"]
            same = built == g["graph_digest"]
            result["checks"].append({"code": "GRAPH_REBUILT_MATCHES" if same else "GRAPH_DIGEST_MISMATCH",
                                     "verdict": "verified" if same else "refuse",
                                     "detail": (f"{Path(rec['path']).name}: graph rebuilt here at "
                                                f"{g['source_commit'][:12]} → {built[:23]}… "
                                                + ("equals the digest the receipt was produced against"
                                                   if same else f"but the receipt claims {g['graph_digest'][:23]}…"))})
            if not same:
                result["reason_codes"] = sorted(set(result["reason_codes"] + ["GRAPH_DIGEST_MISMATCH"]))

    hard = [c for c in result["checks"] if c["verdict"] == "refuse"]
    gv = gate_doc.get("verdict")
    result["verdict"] = {"admit": "admitted", "paused_safe": "paused", "refuse": "refused"}.get(gv, gv)
    if hard and result["verdict"] == "admitted":
        result["verdict"] = "refused"
    exempt = any(r.get("exemptions") for r in gate_doc.get("receipts", []) if r.get("bound"))
    if result["verdict"] == "admitted" and exempt:
        result["verdict"] = "admitted_with_exemptions"
    result["conclusion"] = "success" if result["verdict"].startswith("admitted") else "failure"
    return finish(0 if result["conclusion"] == "success" else 1)


# --------------------------------------------------------------------------------------- selftest
def selftest() -> int:
    """The mutation battery of the CI job: every mutant must FLIP the verdict of the conformant control.

    Reuses the admission fixtures of `tools/graph/admit_change.py` (scratch git repository + the
    ChangeAdmissionReceipt/v1 fixture set), so the battery exercises the real gate, not a mock."""
    import tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change  # noqa: E402

    root = Path(tempfile.mkdtemp(prefix="ci-gate-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False)[:300]))

    repo, base, head = admit_change.scratch_repo(root)
    F = admit_change.make_fixtures(base, head)
    bundle = root / "bundle"
    cmd_bundle(argparse.Namespace(out=str(bundle), program_ref="0" * 40))
    (repo / ".github").mkdir(exist_ok=True)
    shutil.copytree(bundle, repo / ".github/graph-admission")
    rdir = repo / "receipts/graph"
    rdir.mkdir(parents=True, exist_ok=True)

    def run(receipt: dict | None, *, body: str = "", extra_files: list[str] | None = None,
            tamper: str | None = None, program_ref: str = "0" * 40, doc_only: bool = False) -> dict:
        for p in rdir.glob("*.json"):
            p.unlink()
        if receipt is not None:
            (rdir / "car.json").write_text(json.dumps(receipt, indent=1, sort_keys=True) + "\n")
        bp = root / "body.txt"
        bp.write_text(body)
        saved = None
        tp = repo / ".github/graph-admission/tools/graph/admit_change.py"
        if tamper:
            saved = tp.read_text()
            tp.write_text(saved + f"\n# {tamper}\n")
        b, h = base, head
        if doc_only:
            (repo / "README.md").write_text("# fixture\n\nchanged\n")
            subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.email=f@x", "-c", "user.name=f",
                            "commit", "-q", "-m", "docs"], check=True)
            b, h = head, admit_change.git(repo, "rev-parse", "HEAD").strip()
        out = root / "result.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo), repo_name="Arcanada-one/fixture", tools=str(repo / ".github/graph-admission"),
            program_ref=program_ref, base=b, head=h, pr_body_file=str(bp), receipt_glob=["receipts/graph/*.json"],
            enforcement="off", build_graph=False, workdir=str(root / "work"), out=str(out), summary=None))
        if saved is not None:
            tp.write_text(saved)
        doc = json.loads(out.read_text())
        doc["_rc"] = rc
        return doc

    control = run(F["conformant-admit"]["receipt"])
    check("(d) conformant receipt in the head tree → green, verdict admitted",
          control["_rc"] == 0 and control["verdict"].startswith("admitted") and control["conclusion"] == "success",
          verdict=control["verdict"], rc=control["_rc"], codes=control["reason_codes"])

    body_only = run(None, body="Change description.\n\n```json\n"
                    + json.dumps(F["conformant-admit"]["receipt"], indent=1) + "\n```\n")
    check("(d') the same receipt delivered ONLY as a ```json block in the pull-request body → green",
          body_only["_rc"] == 0 and body_only["verdict"].startswith("admitted")
          and len(body_only["receipt_sources"]["pr_body"]) == 1 and not body_only["receipt_sources"]["tree"],
          verdict=body_only["verdict"], sources=body_only["receipt_sources"])

    mutants = {
        "(a) pull request without any receipt": (run(None), "RECEIPT_MISSING"),
        "(b) receipt bound to another change range": (run(F["violation-RECEIPT_NOT_BOUND_TO_RANGE"]["receipt"]),
                                                     "RECEIPT_NOT_BOUND_TO_RANGE"),
        "(c) receipt with a two-valued verdict": (run(F["violation-RECEIPT_MALFORMED-two-valued"]["receipt"]),
                                                  "RECEIPT_MALFORMED"),
        "(e) bundled gate tool tampered with": (run(F["conformant-admit"]["receipt"], tamper="tampered"),
                                               "BUNDLE_DIGEST_MISMATCH"),
        "(f) caller pins a program_ref the bundle does not carry": (run(F["conformant-admit"]["receipt"],
                                                                       program_ref="9" * 40), "BUNDLE_REF_MISMATCH"),
        "(g) a not_measured entity without an exemption pauses, never passes": (
            run(F["violation-NOT_MEASURED_WITHOUT_EXEMPTION"]["receipt"]), "NOT_MEASURED_WITHOUT_EXEMPTION"),
        "(h) a bypass phrase in the pull-request description, even WITH a conformant receipt": (
            run(F["conformant-admit"]["receipt"], body="please skip-graph-verify for this one"),
            "MANUAL_BYPASS_REFUSED"),
        "(i) the receipt replaced by a checkbox in the pull-request description": (
            run(None, body="- [x] graph-verified\n- [x] tests pass\n"), "RECEIPT_REPLACED_BY_CHECKBOX"),
    }
    for name, (doc, code) in mutants.items():
        flipped = doc["_rc"] != 0 and doc["conclusion"] == "failure" and doc["conclusion"] != control["conclusion"]
        check(f"mutant {name} → red (flips the control) with {code}",
              flipped and code in doc["reason_codes"],
              verdict=doc["verdict"], rc=doc["_rc"], codes=doc["reason_codes"])

    # a committed bundle that the pull request EDITS is the tamper path; a pull request that ADDS it is not
    repo2, base2, head2 = admit_change.scratch_repo(root / "s2")
    shutil.copytree(bundle, repo2 / ".github/graph-admission")
    subprocess.run(["git", "-C", str(repo2), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo2), "-c", "user.email=f@x", "-c", "user.name=f",
                    "commit", "-q", "-m", "install bundle"], check=True)
    added_head = admit_change.git(repo2, "rev-parse", "HEAD").strip()
    r2 = rdir2 = repo2 / "receipts/graph"
    rdir2.mkdir(parents=True, exist_ok=True)
    F2 = admit_change.make_fixtures(base2, added_head)
    (rdir2 / "car.json").write_text(json.dumps(F2["conformant-admit"]["receipt"], indent=1, sort_keys=True) + "\n")
    body2 = root / "body2.txt"
    body2.write_text("")

    def run2(b, h):
        out = root / "result2.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo2), repo_name="Arcanada-one/fixture2", tools=str(repo2 / ".github/graph-admission"),
            program_ref="0" * 40, base=b, head=h, pr_body_file=str(body2), receipt_glob=["receipts/graph/*.json"],
            enforcement="off", build_graph=False, workdir=str(root / "work2"), out=str(out), summary=None))
        doc = json.loads(out.read_text()); doc["_rc"] = rc
        return doc

    installing = run2(base2, added_head)
    check("a pull request that ADDS the vendored bundle is not refused for adding it (the installing PR)",
          "BUNDLE_MODIFIED_BY_PR" not in installing["reason_codes"]
          and any(c["code"] == "BUNDLE_INSTALLED_BY_PR" for c in installing["checks"]),
          codes=installing["reason_codes"], verdict=installing["verdict"])
    # the realistic tamper: the tool AND the manifest rewritten consistently, so the sha256 check passes
    tp2 = repo2 / ".github/graph-admission/tools/graph/admit_change.py"
    tp2.write_text(tp2.read_text() + "\n# edited in the pull request\n")
    mp2 = repo2 / ".github/graph-admission/BUNDLE.json"
    man2 = json.loads(mp2.read_text())
    for f in man2["files"]:
        if f["path"].endswith("admit_change.py"):
            f["sha256"] = sha256_file(tp2)
    mp2.write_text(json.dumps(man2, indent=1, sort_keys=True) + "\n")
    subprocess.run(["git", "-C", str(repo2), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo2), "-c", "user.email=f@x", "-c", "user.name=f",
                    "commit", "-q", "-m", "edit a vendored tool"], check=True)
    edited_head = admit_change.git(repo2, "rev-parse", "HEAD").strip()
    edit_mut = run2(added_head, edited_head)
    check("mutant (j) the pull request rewrites a vendored gate tool AND its BUNDLE.json entry (the sha256 "
          "check passes) → still red, with BUNDLE_MODIFIED_BY_PR",
          edit_mut["_rc"] != 0 and "BUNDLE_MODIFIED_BY_PR" in edit_mut["reason_codes"],
          codes=edit_mut["reason_codes"], verdict=edit_mut["verdict"])

    doc_only = run(None, doc_only=True)
    check("doc-only change (README.md) → green with verdict not_measured, no receipt required",
          doc_only["_rc"] == 0 and doc_only["verdict"] == "not_measured"
          and doc_only["reason_codes"] == ["DOC_ONLY_NOT_MEASURED"],
          verdict=doc_only["verdict"], codes=doc_only["reason_codes"])
    check("doc-only green is stated as not_measured in the check text, never as a pass",
          any("never as a pass" in c["detail"] or "not a pass" in c["detail"] for c in doc_only["checks"]))

    print(f"\nSELFTEST {'PASS' if not red else 'FAIL'}: {len(checks) - red}/{len(checks)} checks, "
          f"{len(mutants) + 1}/{len(mutants) + 1} mutants" if not red else
          f"\nSELFTEST FAIL: {len(checks) - red}/{len(checks)} checks")
    shutil.rmtree(root, ignore_errors=True)
    return 0 if not red else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=False)

    b = sub.add_parser("bundle", help="vendor the gate tools of a pinned program SHA into a caller repository")
    b.add_argument("--out", required=True)
    b.add_argument("--program-ref")
    b.add_argument("--workflow-out", help="also vendor .github/workflows/graph-admission.yml here (local `uses: ./…` calls)")
    b.set_defaults(fn=cmd_bundle)

    r = sub.add_parser("run", help="the pull-request check")
    r.add_argument("--repo", required=True)
    r.add_argument("--repo-name")
    r.add_argument("--tools", required=True, help="the vendored bundle directory")
    r.add_argument("--program-ref")
    r.add_argument("--base", required=True)
    r.add_argument("--head", required=True)
    r.add_argument("--pr-body-file")
    r.add_argument("--receipt-glob", action="append")
    r.add_argument("--enforcement", default="off", choices=["off", "ledger", "muneral"])
    r.add_argument("--build-graph", action="store_true")
    r.add_argument("--workdir", default=os.environ.get("RUNNER_TEMP", "/tmp") + "/graph-admission")
    r.add_argument("--out", default="graph-admission-result.json")
    r.add_argument("--summary")
    r.set_defaults(fn=cmd_run)
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not getattr(a, "fn", None):
        ap.error("a subcommand or --selftest is required")
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())

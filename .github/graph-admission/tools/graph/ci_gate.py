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
    # AUP-GRAPH-006:gate2a — the automated-author path classifies changed paths and decides the global
    # fallback with the SAME code the local gate uses, so the classifier travels with the bundle.
    "tools/graph/impact.py",
    # AUP-GRAPH-006:gate2b — the SSHSIG/Ed25519 verifier. It must travel with the bundle: the gate
    # verifies the bundle's signature before trusting anything in it, and a verifier the caller does
    # not have is a verification that silently does not happen.
    "tools/graph/sshsig.py",
    "tools/graph/ci_gate.py",
    "contracts/graph-verified-change/admission-gate.v1.json",
    "contracts/graph-verified-change/relationship-graph.v1.json",
    "contracts/graph-verified-change/change-admission-receipt.v1.json",
    "contracts/graph-verified-change/verifier-matrix.v1.json",
]
DEFAULT_RECEIPT_GLOBS = ["receipts/graph/**/*.json", "receipts/**/change-admission-*.json"]

# AUP-GRAPH-006:gate2b — the bundle's cryptographic half.
SIGNATURE_NAME = "BUNDLE.json.sig"
PUBKEY_NAME = "SIGNING-KEY.pub"
SIGNING_NAMESPACE = "graph-admission-bundle"
PROGRAM_PUBKEY_PATH = "contracts/graph-verified-change/bundle-signing-key.pub"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sshsig  # noqa: E402  (sibling tool, stdlib-only, reused as a library)


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
    mp = out / "BUNDLE.json"
    mp.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")

    # AUP-GRAPH-006:gate2b — sign BUNDLE.json. It carries every file's sha256, so a detached signature
    # over it binds the whole vendored set. The PRIVATE key never enters a repository (it lives outside
    # git on the signing host); the PUBLIC key travels with the bundle AND is committed in the program
    # repository, so the two copies can be compared by anyone who can read both.
    signed = None
    if getattr(a, "sign_key", None):
        key = Path(a.sign_key)
        sig = out / SIGNATURE_NAME
        r = subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", SIGNING_NAMESPACE,
                            "-O", "hashalg=sha512", str(mp)], capture_output=True, text=True)
        produced = mp.with_suffix(mp.suffix + ".sig")
        if r.returncode != 0 or not produced.exists():
            print(f"SIGNING FAILED: ssh-keygen exited {r.returncode}: {(r.stderr or r.stdout).strip()[:300]}",
                  file=sys.stderr)
            return 4
        if produced != sig:
            shutil.move(str(produced), str(sig))
        pub = key.with_suffix(".pub") if key.suffix != ".pub" else key
        shutil.copyfile(pub, out / PUBKEY_NAME)
        # the same public key is committed in the program repository, so a caller's copy is comparable
        (PROGRAM_ROOT / PROGRAM_PUBKEY_PATH).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pub, PROGRAM_ROOT / PROGRAM_PUBKEY_PATH)
        kt, aa = sshsig.parse_public_key((out / PUBKEY_NAME).read_text())
        fp = sshsig.fingerprint(kt, aa)
        ok, reason, _ = sshsig.verify_detached(mp.read_bytes(), sig.read_text(),
                                               (out / PUBKEY_NAME).read_text(), SIGNING_NAMESPACE)
        if not ok:
            print(f"SIGNING PRODUCED AN UNVERIFIABLE SIGNATURE: {reason}", file=sys.stderr)
            return 4
        signed = fp
    print(f"{out}: {len(files)} files, program_ref {ref[:12]}, bundle_digest {manifest['bundle_digest'][:23]}…"
          + (f", signed by {signed}" if signed else ", UNSIGNED"))
    return 0


def verify_bundle(tools: Path, program_ref: str | None,
                  key_fingerprint: str | None = None) -> tuple[dict | None, list[str], dict]:
    """→ (manifest, problems, signature record). A problem is a typed one-line reason for the check text.

    AUP-GRAPH-006:gate2b. The SIGNATURE is checked BEFORE anything in BUNDLE.json is believed: the
    per-file sha256 map is only as trustworthy as the file that carries it, and a pull request that
    rewrites a tool AND its manifest entry keeps that map perfectly consistent (mutant (j) of gate1 —
    caught there by a diff-shape rule, `BUNDLE_MODIFIED_BY_PR`, never by verification). Here the
    manifest must additionally verify against an Ed25519 key the program repository holds.
    """
    sigrec = {"required": True, "namespace": SIGNING_NAMESPACE, "verified": False,
              "key_fingerprint": None, "pinned_fingerprint": key_fingerprint or None,
              "fingerprint_pinned": bool(key_fingerprint), "reason": None}
    mp = tools / "BUNDLE.json"
    if not mp.exists():
        return None, [f"BUNDLE_MISSING: no {mp.name} under {tools}"], sigrec
    sp, kp = tools / SIGNATURE_NAME, tools / PUBKEY_NAME
    if not sp.exists() or not kp.exists():
        missing = ", ".join(n for n, e in ((SIGNATURE_NAME, sp.exists()), (PUBKEY_NAME, kp.exists())) if not e)
        sigrec["reason"] = f"missing {missing}"
        return None, [f"BUNDLE_SIGNATURE_MISSING: {missing} is absent under {tools} — an unsigned bundle is "
                      f"refused, never trusted on its own hashes (a manifest signs nothing for itself)"], sigrec
    ok, reason, det = sshsig.verify_detached(mp.read_bytes(), sp.read_text(), kp.read_text(), SIGNING_NAMESPACE)
    sigrec.update({"verified": ok, "reason": reason, "key_fingerprint": det.get("public_key_fingerprint"),
                   "hash_algorithm": det.get("hash_algorithm"), "key_type": det.get("key_type")})
    if not ok:
        return None, [f"BUNDLE_SIGNATURE_INVALID: {reason}"], sigrec
    if key_fingerprint:
        if det.get("public_key_fingerprint") != key_fingerprint:
            return None, [f"BUNDLE_SIGNATURE_UNTRUSTED_KEY: the bundle is signed by "
                          f"{det.get('public_key_fingerprint')} but the caller pins {key_fingerprint} — a "
                          f"valid signature by an unpinned key is not a trusted signature"], sigrec
    try:
        man = json.loads(mp.read_text())
    except json.JSONDecodeError as e:
        return None, [f"BUNDLE_MALFORMED: {e}"], sigrec
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
    return man, problems, sigrec


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

    man, problems, sigrec = verify_bundle(tools, a.program_ref, getattr(a, "signing_key_fingerprint", None))
    result["bundle"] = {"path": str(tools.relative_to(repo)) if tools.is_relative_to(repo) else str(tools),
                        "program_ref": (man or {}).get("program_ref"),
                        "bundle_digest": (man or {}).get("bundle_digest"), "problems": problems,
                        "signature": sigrec}
    if problems:
        return fail(problems[0].split(":")[0], "; ".join(problems))
    if sigrec.get("fingerprint_pinned"):
        result["checks"].append({"code": "BUNDLE_SIGNATURE_VERIFIED", "verdict": "verified",
                                 "detail": (f"BUNDLE.json carries a valid Ed25519 SSHSIG detached signature in "
                                            f"namespace {SIGNING_NAMESPACE!r} by {sigrec['key_fingerprint']}, "
                                            f"which is the key this caller pins. Every per-file sha256 below is "
                                            f"therefore signed, not merely self-consistent.")})
    else:
        result["checks"].append({"code": "BUNDLE_SIGNATURE_UNPINNED", "verdict": "not_measured",
                                 "detail": (f"the signature is valid for the key SHIPPED IN THE BUNDLE "
                                            f"({sigrec['key_fingerprint']}), but this caller pins no expected "
                                            f"fingerprint, so what is proven is self-consistency, not provenance: "
                                            f"anyone who can replace both the signature and {PUBKEY_NAME} in the "
                                            f"same change satisfies it. Pass `signing_key_fingerprint` from the "
                                            f"caller's own workflow file to turn this into a provenance claim. "
                                            f"`not_measured` is not a pass (DEC-AUP-0008 I4).")})

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
           "--enforcement", a.enforcement, "--workdir", str(work / "gate2a"),
           "--repo-name", result["repo"]]
    # AUP-GRAPH-006:gate2a — the automated-author path. The event payload is the ONLY source of author
    # identity; the head branch name is attacker-controllable and is never consulted.
    if getattr(a, "event_file", None) and Path(a.event_file).exists():
        cmd += ["--event-file", a.event_file]
        result["automated_author_inputs"] = {
            "event_file": a.event_file,
            "verifier_job": getattr(a, "verifier_job", None) or None,
            "verifier_conclusion": getattr(a, "verifier_conclusion", None) or None,
        }
    for flag, val in (("--verifier-job", getattr(a, "verifier_job", None)),
                      ("--verifier-conclusion", getattr(a, "verifier_conclusion", None)),
                      ("--verifier-output-ref", getattr(a, "verifier_output_ref", None))):
        if val:
            cmd += [flag, val]
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
        # NOTE: `refuse` here is the DRIVER's finding about the two human-facing sources. The gate may
        # still author a receipt itself on the automated-author path (AUP-GRAPH-006:gate2a); when it does,
        # this entry is downgraded below, after the gate has spoken, so a driver-level note can never
        # outvote the gate's own verdict.
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
    result["automated_author"] = gate_doc.get("automated_author")
    result["checks"] += [{"code": c["code"], "verdict": c["verdict"], "detail": c["detail"]} for c in gate_doc["checks"]]
    result["reason_codes"] = sorted(set(result["reason_codes"] + list(gate_doc.get("reason_codes") or [])))

    # the caller repository's own graph, built here from the pinned bundle, cross-checked against the receipt
    if a.build_graph:
        bound = [r for r in gate_doc.get("receipts", []) if r.get("bound")]
        # …including a receipt the gate AUTHORED itself on the automated-author path: it is not one of
        # the driver's two sources, but it is a receipt like any other and is rebuilt against like one.
        pool = list(map(str, receipts))
        au_path = (gate_doc.get("automated_author") or {}).get("receipt_path")
        if au_path:
            pool.append(au_path)
        for rec in bound:
            src = next((json.loads(Path(p).read_text()) for p in pool
                        if Path(p).exists() and Path(p).name == Path(rec["path"]).name), None)
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

    if (gate_doc.get("automated_author") or {}).get("eligible"):
        for c in result["checks"]:
            if c["code"] == "RECEIPT_SOURCES_EMPTY":
                c["verdict"] = "not_measured"
                c["detail"] += (" — the gate then AUTHORED one itself on the automated-author path "
                                f"({(gate_doc['automated_author'].get('author_match') or {}).get('author', {}).get('login')}), "
                                "and that receipt was checked exactly like any other.")
    hard = [c for c in result["checks"] if c["verdict"] == "refuse"]
    gv = gate_doc.get("verdict")
    result["verdict"] = {"admit": "admitted", "paused_safe": "paused", "refuse": "refused"}.get(gv, gv)
    if hard and result["verdict"] == "admitted":
        result["verdict"] = "refused"
    # The gate's receipt rows carry `entity_counts.exempted` and `admission`, never an `exemptions` key:
    # keying on `r["exemptions"]` (gate1) made `admitted_with_exemptions` unreachable in CI. Read the
    # fields the gate actually emits.
    exempt = any((r.get("entity_counts") or {}).get("exempted") or r.get("admission") == "admitted_with_exemptions"
                 for r in gate_doc.get("receipts", []) if r.get("bound"))
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
    cmd_bundle(argparse.Namespace(out=str(bundle), program_ref="0" * 40, workflow_out=None, sign_key=None))
    sign_bundle(bundle)  # gate2b: an unsigned bundle is refused, so every fixture bundle is signed
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
    # gate2b changed what catches this. The tamper keeps the sha256 map consistent but CANNOT keep the
    # signature valid — BUNDLE.json's bytes changed and the attacker has no key — so the cryptographic
    # layer now fires FIRST. The mutant must still flip; the code it flips with is stronger than gate1's.
    check("mutant (j) the pull request rewrites a vendored gate tool AND its BUNDLE.json entry (the sha256 "
          "check passes) → still red, now with BUNDLE_SIGNATURE_INVALID (gate2b) rather than only the "
          "diff-shape rule",
          edit_mut["_rc"] != 0 and "BUNDLE_SIGNATURE_INVALID" in edit_mut["reason_codes"],
          codes=edit_mut["reason_codes"], verdict=edit_mut["verdict"])

    # …and the diff-shape layer must still work on its own, for the one attacker the signature cannot
    # stop: someone who HOLDS the signing key. Re-sign the tampered bundle correctly and the signature
    # is valid; BUNDLE_MODIFIED_BY_PR is then the only thing standing, and it must still stand.
    sign_bundle(repo2 / ".github/graph-admission")
    subprocess.run(["git", "-C", str(repo2), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo2), "-c", "user.email=f@x", "-c", "user.name=f",
                    "commit", "-q", "-m", "re-sign the tampered bundle with the trusted key"], check=True)
    resigned_head = admit_change.git(repo2, "rev-parse", "HEAD").strip()
    resign_mut = run2(added_head, resigned_head)
    check("mutant (j2) the same tamper, correctly RE-SIGNED with the trusted key (the key-holder case, "
          "which no signature can catch) → still red, with BUNDLE_MODIFIED_BY_PR — the two layers are "
          "independent",
          resign_mut["_rc"] != 0 and "BUNDLE_MODIFIED_BY_PR" in resign_mut["reason_codes"]
          and "BUNDLE_SIGNATURE_INVALID" not in resign_mut["reason_codes"],
          codes=resign_mut["reason_codes"], verdict=resign_mut["verdict"])

    doc_only = run(None, doc_only=True)
    check("doc-only change (README.md) → green with verdict not_measured, no receipt required",
          doc_only["_rc"] == 0 and doc_only["verdict"] == "not_measured"
          and doc_only["reason_codes"] == ["DOC_ONLY_NOT_MEASURED"],
          verdict=doc_only["verdict"], codes=doc_only["reason_codes"])
    check("doc-only green is stated as not_measured in the check text, never as a pass",
          any("never as a pass" in c["detail"] or "not a pass" in c["detail"] for c in doc_only["checks"]))

    print(f"\nSELFTEST {'PASS' if not red else 'FAIL'}: {len(checks) - red}/{len(checks)} checks, "
          f"{len(mutants) + 2}/{len(mutants) + 2} mutants" if not red else
          f"\nSELFTEST FAIL: {len(checks) - red}/{len(checks)} checks")
    shutil.rmtree(root, ignore_errors=True)

    print("\n--- AUP-GRAPH-006:gate2a — the automated-author battery ---")
    g2a_checks, g2a_red = selftest_gate2a()
    red += g2a_red
    checks += g2a_checks
    print("\n--- AUP-GRAPH-006:gate2b — the bundle-signature battery ---")
    g2b_checks, g2b_red = selftest_gate2b()
    red += g2b_red
    checks += g2b_checks
    measured = [c for c in checks if c.get("ok") is not None]
    print(f"\nTOTAL {'PASS' if not red else 'FAIL'}: {len(measured) - red}/{len(measured)} checks across "
          f"three batteries ({len(checks) - len(measured)} not_measured)")
    return 0 if not red else 1


def selftest_gate2a() -> tuple[list[dict], int]:
    """AUP-GRAPH-006:gate2a — the automated-author mutation battery.

    Control: a dependabot pull request touching ONLY a lockfile is green with the typed exemption.
    Every mutant must FLIP it. A survivor is a hole, reported as one.
    """
    import tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change  # noqa: E402

    root = Path(tempfile.mkdtemp(prefix="gate2a-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False)[:400]))

    # a repository with a lockfile, a manifest and source — the shape a dependency bump lands in
    repo = root / "repo"
    repo.mkdir(parents=True)
    env = {"GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "fixture",
           "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-05T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-09-05T00:00:00Z", "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "HOME": str(root)}

    def g(*args):
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)}: {r.stderr[:300]}")
        return r.stdout

    g("init", "-q", "-b", "main")
    (repo / "src").mkdir()
    (repo / "src/a.ts").write_text("export const a = 1;\n")
    (repo / "src/b.ts").write_text("import { a } from './a';\nexport const b = a + 1;\n")
    (repo / "package.json").write_text('{\n "name": "fixture",\n "dependencies": {"left-pad": "1.0.0"}\n}\n')
    (repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\npackages:\n  left-pad@1.0.0: {}\n")
    g("add", "-A"); g("commit", "-q", "-m", "base")
    base = g("rev-parse", "HEAD").strip()

    bundle = root / "bundle"
    cmd_bundle(argparse.Namespace(out=str(bundle), program_ref="0" * 40, workflow_out=None, sign_key=None))
    sign_bundle(bundle)
    shutil.copytree(bundle, repo / ".github/graph-admission")
    g("add", "-A"); g("commit", "-q", "-m", "install the gate bundle")
    base = g("rev-parse", "HEAD").strip()

    def commit(files: dict[str, str], msg: str, branch: str) -> str:
        """One branch per mutant, each a single commit on `base`: a mutant must differ from the control
        in exactly the one thing it mutates, and sequential commits would carry the previous one's files
        into the diff (observed: mutant (d) inherited mutant (b)'s src/a.ts and refused for the wrong reason)."""
        g("checkout", "-q", "-B", branch, base)
        for rel, body in files.items():
            fp = repo / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(body)
        g("add", "-A"); g("commit", "-q", "-m", msg)
        return g("rev-parse", "HEAD").strip()

    DEPENDABOT = {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"}
    HUMAN = {"login": "mallory", "id": 12345, "type": "User"}

    def event(user: dict, head_ref: str) -> str:
        p = root / f"event-{user['login']}-{abs(hash(head_ref)) % 10 ** 6}.json"
        p.write_text(json.dumps({"action": "opened", "pull_request": {
            "number": 1, "user": user, "author_association": "NONE",
            "head": {"ref": head_ref}, "base": {"ref": "main"}}}, indent=1))
        return str(p)

    def run(head: str, *, event_file: str | None, conclusion: str | None, job: str = "lint-and-test",
            body: str = "") -> dict:
        bp = root / "body.txt"
        bp.write_text(body)
        out = root / "result.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo), repo_name="Arcanada-one/fixture", tools=str(repo / ".github/graph-admission"),
            program_ref="0" * 40, base=base, head=head, pr_body_file=str(bp),
            receipt_glob=["receipts/graph/*.json"], enforcement="off", build_graph=True,
            workdir=str(root / f"work-{head[:8]}"), out=str(out), summary=None,
            event_file=event_file, verifier_job=job, verifier_conclusion=conclusion,
            verifier_output_ref="https://example.invalid/run/1"))
        doc = json.loads(out.read_text())
        doc["_rc"] = rc
        return doc

    # ---------------------------------------------------------------- control (a)
    lock_head = commit({"pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  left-pad@1.1.0: {}\n",
                        "package.json": '{\n "name": "fixture",\n "dependencies": {"left-pad": "1.1.0"}\n}\n'},
                       "build(deps): bump left-pad from 1.0.0 to 1.1.0", "mut-a")
    control = run(lock_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.1.0"),
                  conclusion="success")
    au = control.get("automated_author") or {}
    check("(a) dependabot pull request touching only dependency manifests → green with the typed exemption",
          control["_rc"] == 0 and control["verdict"] == "admitted_with_exemptions"
          and au.get("eligible") is True and au.get("exemption_code") == "AUTOMATED_DEPENDENCY_UPDATE"
          and "AUTOMATED_AUTHOR_RECEIPT_ISSUED" in control["reason_codes"],
          verdict=control["verdict"], rc=control["_rc"], codes=control["reason_codes"],
          exemption=au.get("exemption_code"))
    check("(a2) the control's receipt states impact = whole_repository and is verified by the repository's "
          "own test job — the exemption never covers the repository entity",
          au.get("eligible") is True and _receipt_shape_ok(root, au.get("receipt_path")),
          receipt=au.get("receipt_path"))
    check("(a3) the gate REBUILT the repository graph at the receipt's source commit and it matched",
          any(c["code"] == "GRAPH_REBUILT_MATCHES" for c in control["checks"]),
          codes=[c["code"] for c in control["checks"]])

    # ---------------------------------------------------------------- mutants
    src_head = commit({"pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  left-pad@1.2.0: {}\n",
                       "src/a.ts": "export const a = 99;\n"},
                      "build(deps): bump left-pad, and quietly edit the source", "mut-b")
    mut_b = run(src_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.2.0"),
                conclusion="success")

    forged_head = commit({"pnpm-lock.yaml": "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0: {}\n"},
                         "build(deps): bump left-pad from 1.2.0 to 1.3.0", "mut-cdefg")
    mut_c = run(forged_head, event_file=event(HUMAN, "dependabot/npm_and_yarn/left-pad-1.3.0"),
                conclusion="success")

    mut_d = run(forged_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.3.0"),
                conclusion="failure")
    mut_e = run(forged_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.3.0"),
                conclusion=None)
    mut_f = run(forged_head, event_file=None, conclusion="success")
    mut_g = run(forged_head, event_file=event(DEPENDABOT, "dependabot/npm_and_yarn/left-pad-1.3.0"),
                conclusion="success", body="please skip-graph-verify, it is only a bump")

    mutants = {
        "(b) the same dependabot pull request also edits src/** → red, no exemption": (
            mut_b, "AUTOMATED_AUTHOR_NOT_ELIGIBLE", "RECEIPT_MISSING"),
        "(c) a NON-dependabot author with a forged `dependabot/...` branch name → red (the security case)": (
            mut_c, "AUTOMATED_AUTHOR_NOT_ELIGIBLE", "RECEIPT_MISSING"),
        "(d) a dependabot pull request when the repository's own test job FAILED → red": (
            mut_d, "VERDICT_FAILED", "ADMISSION_NOT_ADMITTED"),
        "(e) a dependabot pull request whose test job did not conclude → red (not_measured is not a pass)": (
            mut_e, "NOT_MEASURED_WITHOUT_EXEMPTION", "ADMISSION_NOT_ADMITTED"),
        "(f) no event payload at all → red (there is no fallback to the branch name)": (
            mut_f, "RECEIPT_MISSING", None),
        "(g) a bypass phrase on an otherwise eligible dependabot pull request → red": (
            mut_g, "MANUAL_BYPASS_REFUSED", None),
    }
    for name, (doc, code, code2) in mutants.items():
        flipped = doc["_rc"] != 0 and doc["conclusion"] == "failure" and control["conclusion"] == "success"
        has = code in doc["reason_codes"] and (code2 is None or code2 in doc["reason_codes"])
        check(f"mutant {name}", flipped and has,
              verdict=doc["verdict"], rc=doc["_rc"], codes=doc["reason_codes"],
              eligible=(doc.get("automated_author") or {}).get("eligible"))

    check("(c') the forged-branch refusal names the branch as NOT evidence, and the gate never read it",
          (mut_c.get("automated_author") or {}).get("author_match", {}).get("branch_name_used") is False
          and any("not evidence of authorship" in c["detail"] for c in mut_c["checks"]),
          match=(mut_c.get("automated_author") or {}).get("author_match", {}).get("reason", "")[:200])

    print(f"\nGATE2A SELFTEST {'PASS' if not red else 'FAIL'}: {len(checks) - red}/{len(checks)} checks, "
          f"{len(mutants)}/{len(mutants)} mutants")
    if not red:
        shutil.rmtree(root, ignore_errors=True)
    else:
        print(f"scratch kept at {root}")
    return checks, red


def _receipt_shape_ok(root: Path, receipt_path: str | None) -> bool:
    """The control's authored receipt must make exactly the claims the policy says it makes."""
    if not receipt_path or not Path(receipt_path).exists():
        return False
    r = json.loads(Path(receipt_path).read_text())
    gf = r["impact_set"]["global_fallback"]
    verdict_of = {v["entity"]: v["verdict"] for v in r["verdicts"]}
    exempt = {x["entity"] for x in r["exemptions"]}
    repo_ent = next((e for e in verdict_of if e.startswith("repository:")), None)
    auth_ent = next((e for e in verdict_of if e.startswith("receipt_authorship:")), None)
    return bool(
        gf.get("triggered") is True and gf.get("scope") == "whole_repository" and gf.get("total_nodes")
        and r["impact_set"]["scope"] == "whole_repository"
        and repo_ent and verdict_of[repo_ent] == "verified" and repo_ent not in exempt
        and auth_ent and verdict_of[auth_ent] == "not_measured" and auth_ent in exempt
        and r["exemptions"][0]["owner"] and r["exemptions"][0]["expires_at_utc"]
        and r["verifiers"][0]["kind"] == "other"
        and r["admission"]["verdict"] == "admitted_with_exemptions"
        and r["authored_by"]["path"] == "automated_author"
    )


SELFTEST_SEED = bytes(range(32))          # a throwaway fixture key, never a production key
SELFTEST_OTHER_SEED = bytes(range(32, 64))  # "the attacker's own key"


def sign_bundle(bundle: Path, seed: bytes = SELFTEST_SEED, namespace: str = SIGNING_NAMESPACE,
                hash_algorithm: str = "sha512") -> str:
    """Sign a bundle the way `--sign-key` does, but in pure Python.

    The batteries must not depend on an OpenSSH binary: a battery that silently skips when a tool is
    absent reports a pass it never measured. `selftest_gate2b` cross-checks this against the real
    `ssh-keygen` where that binary exists, and records `not_measured` where it does not."""
    mp = bundle / "BUNDLE.json"
    pub = sshsig.ed25519_keypair(seed)[1]
    (bundle / PUBKEY_NAME).write_text(sshsig.public_key_line(pub, "selftest"))
    (bundle / SIGNATURE_NAME).write_text(
        sshsig.make_detached(seed, mp.read_bytes(), namespace, hash_algorithm))
    return sshsig.fingerprint(sshsig.SUPPORTED_KEY_TYPE, pub)


def selftest_gate2b() -> tuple[list[dict], int]:
    """AUP-GRAPH-006:gate2b — the bundle stops being a tripwire and becomes a signature.

    gate1's mutant (j) — rewrite a vendored tool AND its BUNDLE.json entry so the sha256 map stays
    consistent — was caught by `BUNDLE_MODIFIED_BY_PR`, a rule about the SHAPE OF THE DIFF, never by
    verification. That rule cannot see a tamper that is already in the base tree. These fixtures put
    the tamper in the BASE commit, where the diff rule is blind by construction, and measure what the
    signature does about it.
    """
    import tempfile
    root = Path(tempfile.mkdtemp(prefix="gate2b-selftest-"))
    checks, red = [], 0

    def check(name, ok, **kw):
        nonlocal red
        checks.append({"name": name, "ok": bool(ok), **kw})
        if not ok:
            red += 1
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + json.dumps(kw, ensure_ascii=False)[:400]))

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import admit_change  # noqa: E402

    pristine = root / "pristine-bundle"
    cmd_bundle(argparse.Namespace(out=str(pristine), program_ref="0" * 40, workflow_out=None, sign_key=None))
    FP = sign_bundle(pristine)
    OTHER_FP = sshsig.fingerprint(sshsig.SUPPORTED_KEY_TYPE, sshsig.ed25519_keypair(SELFTEST_OTHER_SEED)[1])

    def scenario(name: str, mutate=None, pin: str | None = FP) -> dict:
        """A repository whose BASE COMMIT already carries the bundle (mutated or not), and a pull
        request that touches only src/ — so BUNDLE_MODIFIED_BY_PR can never fire."""
        d = root / name
        repo = d / "repo"
        repo.mkdir(parents=True)
        env = {"GIT_AUTHOR_NAME": "f", "GIT_AUTHOR_EMAIL": "f@x", "GIT_COMMITTER_NAME": "f",
               "GIT_COMMITTER_EMAIL": "f@x", "GIT_AUTHOR_DATE": "2026-09-05T00:00:00Z",
               "GIT_COMMITTER_DATE": "2026-09-05T00:00:00Z",
               "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(d)}

        def g(*a):
            r = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, env=env)
            if r.returncode != 0:
                raise RuntimeError(f"git {' '.join(a)}: {r.stderr[:200]}")
            return r.stdout

        g("init", "-q", "-b", "main")
        (repo / "src").mkdir()
        (repo / "src/a.ts").write_text("export const a = 1;\n")
        (repo / ".github").mkdir()
        tools = repo / ".github/graph-admission"
        shutil.copytree(pristine, tools)
        if mutate:
            mutate(tools)
        g("add", "-A"); g("commit", "-q", "-m", "base, bundle already installed")
        base = g("rev-parse", "HEAD").strip()
        (repo / "src/a.ts").write_text("export const a = 2;\n")
        g("add", "-A"); g("commit", "-q", "-m", "an ordinary change that does not touch the bundle")
        head = g("rev-parse", "HEAD").strip()
        (d / "body.txt").write_text("")
        out = d / "result.json"
        rc = cmd_run(argparse.Namespace(
            repo=str(repo), repo_name="Arcanada-one/fixture", tools=str(tools), program_ref="0" * 40,
            base=base, head=head, pr_body_file=str(d / "body.txt"), receipt_glob=["receipts/graph/*.json"],
            enforcement="off", build_graph=False, workdir=str(d / "work"), out=str(out), summary=None,
            signing_key_fingerprint=pin))
        doc = json.loads(out.read_text())
        doc["_rc"] = rc
        doc["_touched_bundle"] = "BUNDLE_MODIFIED_BY_PR" in doc["reason_codes"]
        return doc

    # ---------------------------------------------------------------- fixture 1: valid signature
    valid = scenario("valid")
    check("valid signature + pinned key: the bundle is trusted (no BUNDLE_* refusal)",
          not any(c["code"].startswith("BUNDLE_") and c["verdict"] == "refuse" for c in valid["checks"])
          and (valid["bundle"]["signature"] or {}).get("verified") is True
          and any(c["code"] == "BUNDLE_SIGNATURE_VERIFIED" for c in valid["checks"]),
          codes=valid["reason_codes"], sig=valid["bundle"]["signature"])
    check("the pull request does NOT touch the bundle, so the gate1 diff-shape rule cannot fire here "
          "— whatever the signature catches below, it catches on its own",
          not valid["_touched_bundle"])

    # ---------------------------------------------------------------- fixture 2: the consistent tamper
    def tamper_consistently(tools: Path):
        tp = tools / "tools/graph/admit_change.py"
        tp.write_text(tp.read_text() + "\n# an attacker's line\n")
        mp = tools / "BUNDLE.json"
        man = json.loads(mp.read_text())
        for f in man["files"]:
            if f["path"].endswith("admit_change.py"):
                f["sha256"] = sha256_file(tp)
        man["bundle_digest"] = "sha256:" + hashlib.sha256(
            json.dumps(man["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        mp.write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")

    tampered = scenario("tampered", tamper_consistently)
    check("a tampered tool WITH a consistent BUNDLE.json, already in the base tree → refused by the "
          "SIGNATURE (gate1 could only catch this when the pull request itself touched the bundle)",
          tampered["_rc"] != 0 and "BUNDLE_SIGNATURE_INVALID" in tampered["reason_codes"]
          and not tampered["_touched_bundle"],
          codes=tampered["reason_codes"], touched=tampered["_touched_bundle"])

    # ---------------------------------------------------------------- fixture 3: no signature
    def remove_signature(tools: Path):
        (tools / SIGNATURE_NAME).unlink()

    unsigned = scenario("unsigned", remove_signature)
    check("a bundle with no signature → refused (an unsigned bundle is never trusted on its own hashes)",
          unsigned["_rc"] != 0 and "BUNDLE_SIGNATURE_MISSING" in unsigned["reason_codes"],
          codes=unsigned["reason_codes"])

    def remove_pubkey(tools: Path):
        (tools / PUBKEY_NAME).unlink()

    nokey = scenario("nokey", remove_pubkey)
    check("a bundle with no public key → refused, not skipped",
          nokey["_rc"] != 0 and "BUNDLE_SIGNATURE_MISSING" in nokey["reason_codes"],
          codes=nokey["reason_codes"])

    # ---------------------------------------------------------------- fixture 4: the attacker re-signs
    def resign_with_own_key(tools: Path):
        tamper_consistently(tools)
        sign_bundle(tools, SELFTEST_OTHER_SEED)

    resigned = scenario("resigned", resign_with_own_key)
    check("a tamper re-signed with the ATTACKER's own key, public key swapped too → refused, because "
          "the caller pins a fingerprint OUTSIDE the bundle",
          resigned["_rc"] != 0 and "BUNDLE_SIGNATURE_UNTRUSTED_KEY" in resigned["reason_codes"],
          codes=resigned["reason_codes"])

    # …and the residual, measured rather than asserted: with NO pinned fingerprint it gets through.
    unpinned = scenario("resigned-unpinned", resign_with_own_key, pin=None)
    check("THE RESIDUAL, measured not claimed: the same attack with NO pinned fingerprint is NOT "
          "refused — and the check text says so as `not_measured`, never as a pass",
          not any(c["code"].startswith("BUNDLE_") and c["verdict"] == "refuse" for c in unpinned["checks"])
          and any(c["code"] == "BUNDLE_SIGNATURE_UNPINNED" and c["verdict"] == "not_measured"
                  for c in unpinned["checks"]),
          codes=unpinned["reason_codes"])

    # ---------------------------------------------------------------- fixture 5: wrong namespace
    def sign_other_namespace(tools: Path):
        sign_bundle(tools, SELFTEST_SEED, namespace="git")

    wrongns = scenario("wrong-namespace", sign_other_namespace)
    check("a signature by the RIGHT key over the right bytes but in another namespace (e.g. a `git` "
          "commit signature reused) → refused",
          wrongns["_rc"] != 0 and "BUNDLE_SIGNATURE_INVALID" in wrongns["reason_codes"],
          codes=wrongns["reason_codes"])

    # ---------------------------------------------------------------- the verifier vs the real ssh-keygen
    kg = shutil.which("ssh-keygen")
    if not kg:
        checks.append({"name": "cross-check against ssh-keygen", "ok": None,
                       "verdict": "not_measured", "reason": "no ssh-keygen on this host"})
        print("not_measured  cross-check against ssh-keygen: the binary is absent on this host")
    else:
        d = root / "xcheck"
        d.mkdir()
        pub = sshsig.ed25519_keypair(SELFTEST_SEED)[1]
        msg = b"cross-check message\n"
        (d / "m").write_bytes(msg)
        (d / "allowed").write_text("signer@fixture " + sshsig.public_key_line(pub, "x"))
        agree = []
        for alg in ("sha512", "sha256"):
            (d / "s.sig").write_text(sshsig.make_detached(SELFTEST_SEED, msg, SIGNING_NAMESPACE, alg))
            r = subprocess.run([kg, "-Y", "verify", "-f", str(d / "allowed"), "-I", "signer@fixture",
                                "-n", SIGNING_NAMESPACE, "-s", str(d / "s.sig")],
                               input=msg, capture_output=True)
            agree.append(r.returncode == 0)
        check("signatures this implementation PRODUCES are accepted by the real `ssh-keygen -Y verify` "
              "(sha512 and sha256)", all(agree), results=agree)
        # …and the other direction: ssh-keygen signs, this implementation verifies
        r = subprocess.run([kg, "-q", "-t", "ed25519", "-N", "", "-C", "x", "-f", str(d / "k")],
                           capture_output=True)
        both = []
        if r.returncode == 0:
            for alg in ("sha512", "sha256"):
                subprocess.run([kg, "-Y", "sign", "-q", "-f", str(d / "k"), "-n", SIGNING_NAMESPACE,
                                "-O", f"hashalg={alg}", str(d / "m")], capture_output=True)
                ok, _, _ = sshsig.verify_detached(msg, (d / "m.sig").read_text(),
                                                  (d / "k.pub").read_text(), SIGNING_NAMESPACE)
                both.append(ok)
                (d / "m.sig").unlink()
            # a one-byte change to the message must break a REAL ssh-keygen signature under this verifier
            subprocess.run([kg, "-Y", "sign", "-q", "-f", str(d / "k"), "-n", SIGNING_NAMESPACE, str(d / "m")],
                           capture_output=True)
            bad, _, _ = sshsig.verify_detached(msg + b"!", (d / "m.sig").read_text(),
                                               (d / "k.pub").read_text(), SIGNING_NAMESPACE)
            check("signatures the real `ssh-keygen -Y sign` produces are accepted by this implementation, "
                  "and a one-byte change to the message breaks them", all(both) and not bad,
                  accepted=both, tampered_rejected=not bad)
        else:
            print("not_measured  ssh-keygen could not generate a key here")

    print(f"\nGATE2B SELFTEST {'PASS' if not red else 'FAIL'}: "
          f"{sum(1 for c in checks if c.get('ok')) }/{len([c for c in checks if c.get('ok') is not None])} "
          f"checks, {'0' if not red else red} failing")
    if not red:
        shutil.rmtree(root, ignore_errors=True)
    else:
        print(f"scratch kept at {root}")
    return checks, red


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=False)

    b = sub.add_parser("bundle", help="vendor the gate tools of a pinned program SHA into a caller repository")
    b.add_argument("--out", required=True)
    b.add_argument("--program-ref")
    b.add_argument("--workflow-out", help="also vendor .github/workflows/graph-admission.yml here (local `uses: ./…` calls)")
    b.add_argument("--sign-key", help="AUP-GRAPH-006:gate2b — Ed25519 private key (ssh-keygen format) to sign "
                                      "BUNDLE.json with. The key must live OUTSIDE any repository; its public "
                                      "half is written into the bundle and into the program repository.")
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
    r.add_argument("--event-file", help="GITHUB_EVENT_PATH — the pull_request event payload; the automated-author "
                                        "path reads the author from it and from nothing else")
    r.add_argument("--verifier-job", help="the repository's own test job, verifier of a whole-repository impact")
    r.add_argument("--verifier-conclusion", help="that job's conclusion; absent/unknown is not_measured, never a pass")
    r.add_argument("--verifier-output-ref", help="URL the verdict can be traced to")
    r.add_argument("--signing-key-fingerprint", help="AUP-GRAPH-006:gate2b — the SHA256:… fingerprint the caller "
                                                     "trusts, set in the caller's OWN workflow file, outside the "
                                                     "bundle. Without it the signature proves self-consistency "
                                                     "only, and the check says so as not_measured.")
    r.set_defaults(fn=cmd_run)
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not getattr(a, "fn", None):
        ap.error("a subcommand or --selftest is required")
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())

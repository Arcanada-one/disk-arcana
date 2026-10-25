"""Revision-bound impact over both sides of a committed change.

Each traversal uses one real graph. Paths never cross revisions. The union selects
verification obligations; it does not manufacture verification results.
"""
from __future__ import annotations

import copy
import contextlib
import contextvars
import hashlib
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import build_graph
import impact
import schema_check
import origin_association

SOURCE_EXTS = impact.CODE_EXTS | {".prisma", ".py", ".rs", ".go", ".java", ".kt", ".cs", ".c", ".cpp", ".h"}

_phase_fd = contextvars.ContextVar("graph_phase_fd", default=None)


@contextlib.contextmanager
def phase_trace_to(path):
    """Optional diagnostics only; create a new private log, never replace evidence.

    Records contain fixed phase names, PID and timings, not argv, environment,
    exception messages or evidence payloads. A requested but unwritable log fails
    explicitly. The log has no role in any verification or admission decision.
    """
    if path is None:
        yield
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    token = _phase_fd.set(fd)
    try:
        yield
    finally:
        _phase_fd.reset(token)
        os.close(fd)


@contextlib.contextmanager
def trace_phase(name):
    """Write BEGIN before work, so a killed process still identifies its phase."""
    fd = _phase_fd.get()
    if fd is None:
        yield
        return
    started = time.monotonic()

    def emit(event, **extra):
        data = (json.dumps({"schema": "GraphPhaseTrace/v1", "pid": os.getpid(),
                            "phase": name, "event": event,
                            "monotonic_seconds": time.monotonic(), **extra}) + "\n").encode()
        while data:
            written = os.write(fd, data)
            if written == 0:
                raise OSError("phase log write made no progress")
            data = data[written:]

    emit("begin")
    try:
        yield
    except BaseException as exc:
        emit("error", elapsed_seconds=time.monotonic() - started,
             exception_type=type(exc).__name__)
        raise
    else:
        emit("end", elapsed_seconds=time.monotonic() - started)


def graph_parity(installed: dict, current: dict) -> dict:
    """Bind two genuine outputs only when their entire semantic documents agree.

    Version/timestamp/digest are producer metadata, not evidence of equivalence.
    Every other manifest field, every node/edge/attribute and every extra field
    remains in the comparison. Neither input nor its digest is rewritten.
    """
    bodies = []
    for doc in (installed, current):
        manifest = doc.get("manifest", {})
        if manifest.get("graph_digest") != schema_check.graph_digest(doc):
            raise impact.Refusal("CALLER_GRAPH_INVALID", "producer graph digest is invalid")
        body = copy.deepcopy(doc)
        for key in ("builder_version", "built_at_utc", "graph_digest"):
            body["manifest"].pop(key, None)
        bodies.append(body)
    if bodies[0] != bodies[1]:
        raise impact.Refusal("CALLER_GRAPH_SEMANTIC_DRIFT", "installed and current graph bodies differ")
    return {"source_commit": current["manifest"]["source_commit"],
            "installed_graph_digest": installed["manifest"]["graph_digest"],
            "current_graph_digest": current["manifest"]["graph_digest"],
            "installed_builder_version": installed["manifest"]["builder_version"],
            "current_builder_version": current["manifest"]["builder_version"],
            "body_sha256": "sha256:" + hashlib.sha256(impact.dump(bodies[0])).hexdigest()}


def _canonical_bundle_key() -> str:
    return (Path(__file__).resolve().parents[2] /
            "contracts/graph-verified-change/bundle-signing-key.pub").read_text()


def caller_graph_pair(repo: impact.Repo, base: str, head: str, bundle_path: str):
    try:
        return _caller_graph_pair(repo, base, head, bundle_path)
    except impact.Refusal:
        raise
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as exc:
        raise impact.Refusal("CALLER_GRAPH_COMPATIBILITY_REFUSED", "trusted paired build could not be completed",
                             {"error_type": type(exc).__name__}) from exc


def _caller_graph_pair(repo: impact.Repo, base: str, head: str, bundle_path: str):
    """Execute only an unchanged, trusted signed BASE bundle in owned quarantine.

    Independently rebuild current graphs at both revisions before returning the
    installed graphs and their exact paired proof. No author executable is used.
    """
    import ci_gate
    import sshsig

    if repo.path != repo.top or bundle_path not in {".github/graph-admission", ".arcana/graph-gate"}:
        raise impact.Refusal("CALLER_BUNDLE_PATH", "compatibility requires a repository-root canonical bundle path")
    base, head = repo.rev(base), repo.rev(head)
    def tree(rev):
        rows = impact.git(["ls-tree", "-r", "-z", rev, "--", bundle_path], repo.top)
        out = {}
        for row in filter(None, rows.split("\0")):
            meta, path = row.split("\t", 1)
            mode, kind, oid = meta.split()
            if mode not in {"100644", "100755"} or kind != "blob":
                raise impact.Refusal("CALLER_BUNDLE_FILE_TYPE", "bundle contains a non-regular Git object")
            out[path] = (mode, oid)
        return out
    files = tree(base)
    if not files or files != tree(head):
        raise impact.Refusal("CALLER_BUNDLE_CHANGED", "BASE and HEAD signed bundle objects must be identical")
    key = _canonical_bundle_key()
    fingerprint = sshsig.fingerprint(*sshsig.parse_public_key(key))
    with tempfile.TemporaryDirectory(prefix="caller-graph-compat-") as directory:
        root = Path(directory)
        for path, (_, oid) in files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(subprocess.run(["git", "cat-file", "blob", oid], cwd=repo.top,
                                              capture_output=True, check=True).stdout)
        tools = root / bundle_path
        ok, _, _ = sshsig.verify_detached((tools / "BUNDLE.json").read_bytes(),
                                         (tools / "BUNDLE.json.sig").read_text(), key,
                                         ci_gate.SIGNING_NAMESPACE)
        if not ok:
            raise impact.Refusal("CALLER_BUNDLE_UNTRUSTED", "BASE manifest lacks the canonical trusted signature")
        signed_manifest = json.loads((tools / "BUNDLE.json").read_text())
        for entry in signed_manifest.get("files", []):
            path = entry.get("path", "")
            if not path or Path(path).is_absolute() or ".." in Path(path).parts:
                raise impact.Refusal("CALLER_BUNDLE_PATH", "signed manifest path escapes quarantine")
        # Signature and all executable files are checked before reading workflow paths
        # or running any code. The second check binds the actual unchanged workflow.
        man, problems, _ = ci_gate.verify_bundle(tools, None, fingerprint)
        if problems:
            raise impact.Refusal("CALLER_BUNDLE_UNTRUSTED", "signed BASE bundle refused", {"problems": problems})
        for entry in man.get("files", []):
            path = entry.get("path", "")
            if Path(path).is_absolute() or ".." in Path(path).parts:
                raise impact.Refusal("CALLER_BUNDLE_PATH", "signed manifest path escapes quarantine")
            if entry.get("verified_by_the_job") is False:
                rows = []
                for rev in (base, head):
                    row = impact.git(["ls-tree", rev, "--", path], repo.top).strip()
                    if not row or row.split()[0] not in {"100644", "100755"}:
                        raise impact.Refusal("CALLER_WORKFLOW_UNBOUND", "signed workflow is not a regular committed file")
                    rows.append(row)
                if rows[0] != rows[1]:
                    raise impact.Refusal("CALLER_WORKFLOW_CHANGED", "signed workflow changed in caller range")
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(subprocess.run(["git", "show", f"{base}:{path}"], cwd=repo.top,
                                                  capture_output=True, check=True).stdout)
        man, problems, signature = ci_gate.verify_bundle(tools, None, fingerprint, repo=root)
        if problems or signature.get("workflow", {}).get("verdict") != "verified":
            raise impact.Refusal("CALLER_BUNDLE_UNTRUSTED", "signed workflow/bundle refused", {"problems": problems})
        env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME"}}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        indices, proofs = [], {}
        for role, rev in (("base", base), ("head", head)):
            output = root / (role + ".json")
            runner = ("import runpy,sys;sys.path.insert(0,sys.argv[1]);"
                      "sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name='__main__')")
            proc = subprocess.run([sys.executable, "-I", "-B", "-c", runner, str(tools / "tools/graph"),
                                   str(tools / "tools/graph/build_graph.py"),
                                   str(repo.top), "--rev", rev, "--built-at", build_graph.FIXED_BUILT_AT,
                                   "--out", str(output)], cwd=root, env=env, capture_output=True, timeout=120)
            if proc.returncode:
                raise impact.Refusal("CALLER_GRAPH_BUILD_FAILED", "trusted installed builder failed",
                                     {"revision": rev, "exit_code": proc.returncode})
            doc = json.loads(output.read_text())
            errors = schema_check.check_graph(doc, schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH))
            if errors:
                raise impact.Refusal("CALLER_GRAPH_INVALID", "installed graph is invalid", {"violations": errors})
            current = index_at(repo, rev)
            proofs[role] = graph_parity(doc, current.doc)
            indices.append(impact.GraphIndex(doc))
    binding = {"schema": "CallerGraphCompatibility/v1", "bundle_path": bundle_path,
               "program_ref": man["program_ref"], "bundle_digest": man["bundle_digest"],
               "trusted_key_fingerprint": fingerprint, "base": base, "head": head, "graphs": proofs}
    source_root = Path(__file__).resolve().parents[2]
    source_files = {path: hashlib.sha256((source_root / path).read_bytes()).hexdigest()
                    for path in ci_gate.BUNDLE_FILES}
    binding["current_producer_files_sha256"] = "sha256:" + hashlib.sha256(impact.dump(source_files)).hexdigest()
    return indices[0], indices[1], binding


def index_at(repo: impact.Repo, revision: str) -> impact.GraphIndex:
    with trace_phase("revision-graph-build"):
        doc = build_graph.build(repo.path, rev=revision, built_at=build_graph.FIXED_BUILT_AT)
    with trace_phase("revision-graph-schema"):
        errors = schema_check.check_graph(doc, schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH))
    if errors:
        raise impact.Refusal("GRAPH_INVALID", "rebuilt revision graph is invalid", {"violations": errors})
    with trace_phase("revision-graph-index"):
        return impact.GraphIndex(doc)


def fallback_units(q: dict) -> set[str]:
    """The entity a triggered global fallback collapses onto, for a live impact query.

    The rule itself lives in `schema_check.fallback_units` — the module that imports nothing of
    ours — so that verify.py, this module and the receipt conformance check cannot hold three
    versions of it. Here it is only fed the query's rows.
    """
    return schema_check.fallback_units([e for section in ("deterministic_core", "inferred_tail")
                                        for e in q["impact_set"][section]])


def selected(q: dict) -> set[str]:
    rows = [e for section in ("deterministic_core", "inferred_tail") for e in q["impact_set"][section]]
    if q["impact_set"].get("global_fallback", {}).get("triggered"):
        return set(q["seeds"]) | fallback_units(q) | schema_check.traversal_entities(rows)
    return set(q["seeds"]) | {e["entity"] for e in rows}


def merge_revisions(versions: list[tuple[str, dict]]) -> dict:
    """Union base/head impact rows per entity (extracted from query() unchanged, plus the lean form).

    Keep an actual path as the display path and all revision paths as obligations. A boundary inferred in either
    revision must retain its canary requirement, so revision paths that DIFFER are always kept in full; only when
    every revision reached the entity by the same path in the same section is the record the list of revisions.
    """
    entries: dict[str, list] = {}
    for role, q in versions:
        for section in ("deterministic_core", "inferred_tail"):
            for entry in q["impact_set"][section]:
                entries.setdefault(entry["entity"], []).append((role, section, entry))
    out = {"deterministic_core": [], "inferred_tail": [], "_entities": entries}
    for entity, paths in sorted(entries.items()):
        role, section, chosen = max(paths, key=lambda p: (p[1] == "inferred_tail", p[2].get("boundary") in {"repo", "service"}))
        entry = copy.deepcopy(chosen)
        if all(s == section and e == chosen for _, s, e in paths):
            # Every revision reached this entity by the SAME path in the SAME section: each revision path would be a
            # verbatim copy of the row. Record which revisions, not N copies — every reader already falls back to the
            # row itself (`e.get("revision_paths", [e])`: verify.collect_entities, mandatory_by_entity, the canary
            # hold), and the gate rebuilds these rows with this same function, so equality is unchanged. Measured:
            # a root .env.example (global fallback, 11 519 rows) gave an 18.85 MB receipt, 10.04 MB of it these copies.
            entry["revisions"] = [r for r, _, _ in paths]
        else:
            entry["revision_paths"] = [{"revision": r, "section": s, **copy.deepcopy(e)} for r, s, e in paths]
        out[section].append(entry)
    return out


def query(base_idx: impact.GraphIndex, head_idx: impact.GraphIndex, files: list[dict], *,
          repo: impact.Repo, base: str, head: str, tree_commit: str, tree_dirty: bool,
          max_depth=impact.DEFAULT_MAX_DEPTH, graph_path=None, head_graph_path=None, edge_types=None) -> dict:
    common = dict(mode="diff", base=base, head=head, tree_commit=tree_commit, tree_dirty=tree_dirty,
                  repo=repo, max_depth=max_depth, edge_types=edge_types)
    before = impact.query(base_idx, copy.deepcopy(files), graph_path=graph_path, **common)
    head_files = [f for f in files if f["status"] not in {"D", "R"}]
    # A deletion-only range still binds and checks the head graph, even with no head seeds.
    head_stale = impact.check_staleness(head_idx, repo, "diff", base, tree_commit, tree_dirty,
                                       set(), set(impact.RULES), head=head, graph_role="head")
    after = impact.query(head_idx, copy.deepcopy(head_files), graph_role="head",
                         graph_path=head_graph_path, **common) if head_files else None
    out = copy.deepcopy(before)
    versions = [("base", before)] + ([("head", after)] if after else [])
    merged = merge_revisions(versions)
    for section in ("deterministic_core", "inferred_tail"):
        out["impact_set"][section] = merged[section]
    entries = merged["_entities"]
    base_files = {f["path"]: f for f in out["change_set"]["files"]}
    for f in (after or {}).get("change_set", {}).get("files", []):
        dest = base_files[f["path"]]
        ids = sorted(set(dest.get("node_ids", [])) | set(f.get("node_ids", [])))
        if ids:
            dest.update(node_ids=ids, node_id=next((i for i in ids if i.startswith("code_unit:")), ids[0]))
            dest.pop("new", None)
            dest.pop("uncovered", None)
    out["seeds"] = sorted(set(before["seeds"]) | set((after or {}).get("seeds", [])))
    out["impact_set"]["total"] = len(entries)
    out["impact_set"]["method"] = "Union of independently revision-bound base/head traversals; " + before["impact_set"]["method"]
    if after and after["impact_set"]["global_fallback"]["triggered"]:
        out["impact_set"]["global_fallback"] = after["impact_set"]["global_fallback"]
    # Never carry a base-only 'new file has no consumers' explanation into a measured head.
    if entries or out["impact_set"]["global_fallback"]["triggered"]:
        out.pop("empty_impact_explanation", None)
        out["events"] = [e for e in out["events"] if e.get("code") != "EMPTY_IMPACT_REQUIRES_EXPLANATION"]
    out["events"] = [{**e, "revision": "base"} for e in out["events"]]
    if after:
        out["events"].extend({**e, "revision": "head"} for e in after["events"]
                             if not (e.get("code") == "EMPTY_IMPACT_REQUIRES_EXPLANATION"
                                     and (entries or out["impact_set"]["global_fallback"]["triggered"])))
    missing = sorted(f["path"] for f in head_files
                     if Path(f["path"]).suffix.lower() in SOURCE_EXTS
                     and not head_idx.path_nodes(f["path"], set(impact.RULES)))
    if missing:
        out["events"].append({"code": "HEAD_CODE_NOT_MEASURED", "files": missing})
    out["head_graph"] = {k: head_idx.manifest[k] for k in ("source_commit", "graph_digest", "builder_version", "built_at_utc")}
    out["head_graph"].update(path=head_graph_path, staleness=head_stale)
    out["stats"].update(seeds=len(out["seeds"]),
                        deterministic_core=len(out["impact_set"]["deterministic_core"]),
                        inferred_tail=len(out["impact_set"]["inferred_tail"]),
                        graph_nodes=len(set(base_idx.nodes) | set(head_idx.nodes)),
                        new_files=missing)
    out["revision_selection"] = {"schema": "RevisionImpactSelection/v1", "base": sorted(selected(before)),
                                 "head": sorted(selected(after)) if after else [], "unmeasured_head_files": missing}
    if "empty_impact_explanation" in out:
        out["empty_impact_explanation"]["graph_metadata"] = {
            "scope": "graph_non_seed_dependents",
            "revisions": {role: empty_revision_metadata(idx, q) for role, idx, q in
                          [("base", base_idx, before)] + ([("head", head_idx, after)] if after else [])}}
    return out


def empty_revision_metadata(idx, q):
    seeds = set(q["seeds"])
    edges = [e for seed in sorted(seeds) for e in idx.rev.get(seed, []) if e["type"] != "deploys_to"]
    return {"source_commit": idx.manifest["source_commit"], "graph_digest": idx.manifest["graph_digest"],
            "extractors": idx.manifest.get("extractors"), "language_coverage": idx.manifest.get("language_coverage"),
            "seeds": sorted(seeds), "changed_node_known_to_graph": bool(seeds),
            "internal_reverse_edges": sum(e["from"] in seeds for e in edges),
            "external_reverse_edges": sum(e["from"] not in seeds for e in edges),
            "files": copy.deepcopy(q["change_set"]["files"]),
            "max_depth": q["impact_set"]["max_depth"], "edge_types": q["impact_set"]["edge_types"]}


def bind_empty_explanation(q, claim):
    """Bind an author's explanation to actual paired graphs; never alter raw events."""
    fields = {"schema", "base", "head", "base_graph_digest", "head_graph_digest", "scope", "reason"}
    reason = claim.get("reason") if isinstance(claim, dict) else None
    if not isinstance(claim, dict) or set(claim) != fields or claim.get("schema") != "EmptyImpactExplanation/v1":
        raise impact.Refusal("EMPTY_IMPACT_EXPLANATION_INVALID", "exact explanation fields are required")
    if not isinstance(reason, str) or len(reason.strip()) < 40 or reason.strip().lower().startswith(("generated", "todo", "placeholder", "not_measured")):
        raise impact.Refusal("EMPTY_IMPACT_EXPLANATION_INVALID", "a substantive author explanation is required")
    cs = q["change_set"]
    if claim["scope"] != "graph_non_seed_dependents" or any(claim[k] != cs[k] for k in ("base", "head")) or claim["base_graph_digest"] != q["graph"]["graph_digest"] or claim["head_graph_digest"] != q.get("head_graph", {}).get("graph_digest"):
        raise impact.Refusal("EMPTY_IMPACT_EXPLANATION_STALE", "explanation does not bind this exact paired measurement")
    imp = q["impact_set"]
    metadata = q.get("empty_impact_explanation", {}).get("graph_metadata", {})
    revisions = metadata.get("revisions", {})
    if cs.get("mode") != "diff" or imp["total"] or imp["global_fallback"]["triggered"] or q.get("revision_selection", {}).get("unmeasured_head_files") or set(revisions) != {"base", "head"} or any(m["external_reverse_edges"] for m in revisions.values()) or not any(e.get("code") == "EMPTY_IMPACT_REQUIRES_EXPLANATION" for e in q["events"]):
        raise impact.Refusal("EMPTY_IMPACT_EXPLANATION_INAPPLICABLE", "only a complete empty non-seed dependent prediction may be explained")
    return {"schema": "BoundEmptyImpactExplanation/v1", "reason": reason.strip(), "graph_metadata": copy.deepcopy(metadata),
            "binding": {"schema": "BoundEmptyImpactExplanation/v1", "input": copy.deepcopy(claim),
                        "input_sha256": "sha256:" + hashlib.sha256(impact.dump(claim)).hexdigest()}}


def blocking_query_events(q):
    bound = q.get("empty_impact_explanation", {}).get("binding")
    return [e for e in q.get("events", []) if not (bound and e.get("code") == "EMPTY_IMPACT_REQUIRES_EXPLANATION")]


def receipt_problems(repo_path: Path, doc: dict, *, origin_binding: dict | None = None) -> list[str]:
    """Rebuild from Git, never from receipt node_ids or declared revision selections.

Legacy receipts stay readable, but cannot omit workflow verifier obligations
or admit head obligations absent at base.
A paired receipt must match both graph digests and the complete dual selection.
"""
    cs = doc.get("change_set") or {}
    if cs.get("mode") != "diff":
        return []
    repo = impact.Repo(repo_path)
    base, head = repo.rev(cs["base"]), repo.rev(cs["head"])
    actual = repo.diff_files(base, head)
    paths = {f.get("path") for f in cs.get("files", [])}
    files = [f for f in actual if f["path"] in paths]
    if not files:
        return []  # ordinary file/range binding checks reject unrelated receipts
    compatibility = doc.get("caller_graph_compatibility")
    if compatibility is not None:
        if not isinstance(compatibility, dict):
            return ["caller graph compatibility is not an object"]
        try:
            before, after, rebuilt = caller_graph_pair(repo, base, head,
                                                       compatibility.get("bundle_path"))
        except (impact.Refusal, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as exc:
            return ["caller graph compatibility refused: " + str(exc)]
        if compatibility != rebuilt:
            return ["caller graph compatibility differs from independently rebuilt trusted BASE proof"]
    else:
        before, after = index_at(repo, base), index_at(repo, head)
    origin_proof = None
    if origin_binding is not None:
        try:
            trees = {"base": impact.git(["rev-parse", base + "^{tree}"], repo.path).strip(),
                     "head": impact.git(["rev-parse", head + "^{tree}"], repo.path).strip()}
            origin_proof = origin_association.validate(
                origin_binding["raw"], origin_binding["signature"], origin_binding["trusted_base_key"],
                origin_binding["receipt_digest"], doc,
                {"graph": before.doc, "head_graph": after.doc}, trees)
            origin_binding["proof"] = origin_proof
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            return ["origin association refused: " + str(exc)]
    selection_config = doc.get("impact_set") or {}
    depth = selection_config.get("max_depth", impact.DEFAULT_MAX_DEPTH)
    edge_types = selection_config.get("edge_types", "all")
    if depth is not None and (isinstance(depth, bool) or not isinstance(depth, int) or depth < 0):
        return ["invalid bound impact depth"]
    if edge_types != "all" and (not isinstance(edge_types, list) or not all(isinstance(t, str) for t in edge_types)):
        return ["invalid bound impact edge types"]
    q = query(before, after, files, repo=repo, base=base, head=head,
              tree_commit=repo.head(), tree_dirty=repo.dirty(), max_depth=depth,
              edge_types=None if edge_types == "all" else set(edge_types))
    selection = q["revision_selection"]
    paired = "revision_selection" in doc or "head_graph" in doc
    new_required = set(selection["head"]) - set(selection["base"])
    workflow_selected = any(
        idx.nodes.get(entity, {}).get("kind") == "workflow_configuration"
        for role, idx in (("base", before), ("head", after))
        for entity in selection[role]
    )
    enforce_mandatory = paired or workflow_selected or q["impact_set"].get("global_fallback", {}).get("triggered", False) or "binding" in (doc.get("empty_impact_explanation") or {})
    if not enforce_mandatory and not new_required and not selection["unmeasured_head_files"]:
        return []
    problems = schema_check.fallback_evidence_problems(doc, fallback_units(q)) if q["impact_set"].get("global_fallback", {}).get("triggered") else []
    explanation = doc.get("empty_impact_explanation") or {}
    if "binding" in explanation:
        try:
            expected_explanation = bind_empty_explanation(q, explanation["binding"].get("input"))
            if expected_explanation != explanation:
                problems.append("empty impact explanation differs from independent paired graph binding")
            if any(e.get("code") != "EMPTY_IMPACT_REQUIRES_EXPLANATION" for e in q["events"]):
                problems.append("empty impact explanation cannot satisfy other query diagnostics")
            if not paired:
                problems.append("empty impact explanation requires both revision graph bindings")
        except (impact.Refusal, AttributeError, TypeError, KeyError):
            problems.append("empty impact explanation binding invalid or inapplicable")
    elif explanation.get("schema") == "BoundEmptyImpactExplanation/v1":
        problems.append("empty impact prediction has no bound author explanation")
    if not paired and (new_required or selection["unmeasured_head_files"]):
        problems.append("head graph binding missing for new head impact obligations")
    if paired:
        for field, idx in (("graph", before), ("head_graph", after)):
            binding = doc.get(field) or {}
            if (binding.get("source_commit") != idx.manifest["source_commit"]
                    or (binding.get("graph_digest") != idx.manifest["graph_digest"] and origin_proof is None)):
                problems.append(field + " revision/digest does not match the rebuilt Git graph")
        if doc.get("revision_selection") != selection:
            problems.append("revision selection differs from independently rebuilt Git impact")
        for section in ("deterministic_core", "inferred_tail"):
            if selection_config.get(section) != q["impact_set"][section]:
                problems.append("revision impact paths differ from independent traversal: " + section)
    expected = set(selection["base"]) | set(selection["head"])
    verdicts = {v.get("entity") for v in doc.get("verdicts", [])}
    excluded, exclusion_problems = structural_exclusions_rederived(repo, doc, base, head, before, after)
    problems.extend(exclusion_problems)
    missing = sorted(expected - verdicts - excluded)
    if missing:
        problems.append("missing selected entity verdicts: " + ", ".join(missing[:12]))
    admitted = (doc.get("admission") or {}).get("verdict") in {"admitted", "admitted_with_exemptions"}
    verification = doc.get("verify") if isinstance(doc.get("verify"), dict) else {}
    required = verification.get("required_by_entity")
    if enforce_mandatory and admitted and required is None:
        problems.append("admitted receipt has no mandatory verifier mapping")
    if required is not None:
        if not isinstance(required, dict) or expected - set(required):
            problems.append("required_by_entity omits independently selected entities")
        else:
            mandatory = mandatory_by_entity(before, after, q)
            if any(not isinstance(required[e], list) or not set(vs) <= set(required[e]) for e, vs in mandatory.items()):
                problems.append("required_by_entity omits mandatory base/head verifier obligations")
    if enforce_mandatory and admitted:
        mandatory = mandatory_by_entity(before, after, q)
        records = {v.get("entity"): v for v in doc.get("verdicts", []) if isinstance(v, dict)}
        verifiers = {v.get("id"): v for v in doc.get("verifiers", []) if isinstance(v, dict)}
        for entity, minimum in mandatory.items():
            record = records.get(entity, {})
            # Existing admission rules still judge failed/not_measured and explicit exemptions.
            if record.get("verdict") != "verified":
                continue
            referenced = [verifiers.get(i, {}) for i in record.get("verifier_ids", [])]
            covered_kinds = {("full_fallback_test" if v.get("scope") == "global_fallback_full_suite" else v.get("kind")) for v in referenced
                             if entity in v.get("entities", []) and row_measured_verified(v, entity)
                             and isinstance(v.get("output_ref"), str) and v["output_ref"].strip()}
            if uncovered_row_kinds(minimum, covered_kinds):
                problems.append("verified entity lacks referenced mandatory output scope: " + entity)
            # The finer check the per-entity record makes possible, and the direction that must stay
            # red: a receipt whose top-level verdict is BETTER than what its own verifier wrote down
            # for that entity is contradicting itself, and that is a different defect from a run
            # that failed somewhere else.
            for v in referenced:
                per = v.get("entity_verdicts")
                if isinstance(per, dict) and per.get(entity) in ("failed", "not_measured"):
                    problems.append(f"receipt claims {entity} verified while its own {v.get('kind')} row "
                                    f"({v.get('id')}) records {per[entity]}")
    if selection["unmeasured_head_files"]:
        problems.append("head code extraction not measured: " + ", ".join(selection["unmeasured_head_files"]))
    return problems


def uncovered_row_kinds(minimum, covered_kinds: set) -> set:
    """The mandatory verifiers whose receipt row KIND is absent from `covered_kinds`.

    `minimum` holds verifier-matrix ids; a receipt row carries a `kind` from the receipt schema's
    `kind_values`. The two vocabularies are not the same: the matrix declares
    `route_config_consistency` with `kind: config_schema`, and the receipt schema has no
    `route_config_consistency` kind at all, so verify.py writes that row as `config_schema`. Comparing
    the ids with the kinds directly made every route introduced by a change `paused_safe
    HEAD_IMPACT_NOT_COVERED` whatever its evidence (A2-337, muneral #182 `route:GET /health/routes`).
    The id is translated through the matrix's own declaration; an id the matrix does not declare keeps
    itself, which is the old comparison.
    """
    declared = _matrix()["verifiers"]
    return {m for m in minimum if (m if m == "full_fallback_test" else
                                  declared.get(m, {}).get("kind", m)) not in covered_kinds}


def _matrix() -> dict:
    return json.loads((Path(__file__).resolve().parents[2] / "contracts/graph-verified-change/verifier-matrix.v1.json").read_text())


def row_measured_verified(v: dict, entity: str) -> bool:
    """Did THIS verifier row measure THIS entity and find it good?

    The process exit code answers a different question — «did the whole run come out clean» — and a
    run covers every entity the verifier was handed. Reading it per entity is what A2-274 measured on
    its own range: one additive `ENUM_VALUE_ADDED` in one contract put `contract_diff` at rc 1, and
    every entity whose only mandatory verifier it was lost `verified` — including entities whose
    contract is byte-identical at base and head. The honest answer exists: the verifier computed a
    verdict per entity and now records it (`entity_verdicts`). A finding elsewhere in the run, additive
    or breaking, demotes nobody it did not touch; a finding on THIS entity still demotes it, because
    the row then says `failed` or `not_measured` here.

    A row without the field — every receipt written before this change, and any verifier that records
    nothing per entity — keeps the process code as its answer. That is the old behaviour, not a
    silent pass: it is the only evidence such a row carries.
    """
    per = v.get("entity_verdicts")
    if isinstance(per, dict) and entity in per:
        return per[entity] == "verified"
    return v.get("exit_code") == 0


def structural_exclusions_rederived(repo: impact.Repo, doc: dict, base: str, head: str,
                                    before: impact.GraphIndex, after: impact.GraphIndex) -> tuple[set[str], list[str]]:
    """Which of the receipt's claimed exclusions survive an independent re-derivation (DEC-AUP-0034).

    The receipt does not get to assert its own coverage. Every condition is checked here from the
    matrix and from Git — the node type carries neither a mandatory nor a selectable verifier, the
    change set does not contain the path, and `git cat-file` at both revisions yields the same bytes
    AND the same digests the receipt printed. A claim that fails any of them buys nothing: the entity
    goes back to owing a verdict, and the discrepancy is named so a reader sees a forged exclusion
    rather than a quietly smaller impact set."""
    claims = doc.get("structural_exclusions")
    if not claims:
        return set(), ([] if claims in (None, []) else ["structural_exclusions is not a list"])
    if not isinstance(claims, list):
        return set(), ["structural_exclusions is not a list"]
    matrix = json.loads((Path(__file__).resolve().parents[2] / "contracts/graph-verified-change/verifier-matrix.v1.json").read_text())
    changed = {f.get("path") for f in (doc.get("change_set") or {}).get("files", [])}
    accepted, problems = set(), []
    for claim in claims:
        if not isinstance(claim, dict) or not isinstance(claim.get("entity"), str):
            problems.append("malformed structural exclusion entry")
            continue
        eid = claim["entity"]
        node = after.nodes.get(eid) or before.nodes.get(eid) or {}
        ntype = node.get("type") or eid.split(":", 1)[0]
        spec = matrix["node_types"].get(ntype)
        path = node.get("path") or claim.get("path")
        if not isinstance(spec, dict) or (spec.get("mandatory") or []) or (spec.get("selectable") or []):
            problems.append(f"structural exclusion claims a node type the matrix does verify: {eid}")
            continue
        if claim.get("rule") == "DEC-AUP-0035":
            ok, why = _superseded_self_rederived(repo, doc, claim, path, base, head)
            if ok:
                accepted.add(eid)
            else:
                problems.append(f"structural exclusion claims supersession it does not have: {eid} ({why})")
            continue
        if path in changed:
            problems.append(f"structural exclusion claims an entity the change set contains: {eid}")
            continue
        digests = claim.get("content_hash") if isinstance(claim.get("content_hash"), dict) else {}
        blobs = {}
        for rev in (base, head):
            r = subprocess.run(["git", "-C", str(repo.top), "cat-file", "blob", f"{rev}:{path}"],
                               capture_output=True)
            if r.returncode != 0:
                break
            blobs[rev] = r.stdout
        if len(blobs) != 2:
            problems.append(f"structural exclusion names a path unreadable at base or head: {eid}")
            continue
        seen = {"base": _sha_bytes(blobs[base]), "head": _sha_bytes(blobs[head])}
        if blobs[base] != blobs[head]:
            problems.append(f"structural exclusion claims byte-identity for a file that changed: {eid}")
            continue
        if {k: digests.get(k) for k in ("base", "head")} != seen:
            problems.append(f"structural exclusion carries a content hash the tree does not confirm: {eid}")
            continue
        accepted.add(eid)
    return accepted, problems


def _superseded_self_rederived(repo: impact.Repo, doc: dict, claim: dict, path, base: str,
                               head: str) -> tuple[bool, str]:
    """DEC-AUP-0035, re-derived from Git rather than believed (the R4 discipline of DEC-AUP-0034).

    The claim is narrow on purpose: THIS receipt, at the path THIS receipt was written to, replacing
    a document that carries THIS receipt's work item. Every one of those three is checked against
    the blobs, so the only thing a claim can ever buy is the `not_measured` that the previous draft
    of the same record would have carried — which is the verdict the matrix gives that node type
    whatever anyone claims."""
    own = doc.get("receipt_path")
    if not isinstance(path, str) or not path:
        return False, "no path"
    if path != own:
        return False, f"path {path!r} is not the receipt's own output path {own!r}"
    wi = doc.get("work_item")
    wi = wi if isinstance(wi, str) else (wi or {}).get("task_id") if isinstance(wi, dict) else None
    if not wi:
        return False, "the receipt declares no work item"
    sup = claim.get("superseded") if isinstance(claim.get("superseded"), dict) else {}
    if sup.get("work_item") != wi or sup.get("receipt_path") != path:
        return False, "the claim's superseded block disagrees with the receipt"
    digests = claim.get("content_hash") if isinstance(claim.get("content_hash"), dict) else {}
    seen_any = False
    for rev, role in ((base, "base"), (head, "head")):
        r = subprocess.run(["git", "-C", str(repo.top), "cat-file", "blob", f"{rev}:{path}"],
                           capture_output=True)
        if r.returncode != 0:
            if digests.get(role) is not None:
                return False, f"a content hash is claimed at {role} where the path does not exist"
            continue
        seen_any = True
        if digests.get(role) != _sha_bytes(r.stdout):
            return False, f"the content hash at {role} is not the one the tree carries"
        try:
            was = json.loads(r.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, f"the document at {role} is not readable JSON, so it supersedes nothing"
        if not (isinstance(was, dict) and str(was.get("schema", "")).endswith("Receipt/v1")):
            return False, f"the document at {role} is not a receipt"
        prev = was.get("work_item")
        prev = prev if isinstance(prev, str) else (prev or {}).get("task_id") if isinstance(prev, dict) else None
        if prev != wi:
            return False, f"the receipt at {role} carries work item {prev!r}, not {wi!r}"
    if not seen_any:
        return False, "the path exists at neither revision"
    return True, ""


def _sha_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def is_test_path(path: str) -> bool:
    """The TypeScript/JavaScript test-file rule build_graph applies (TsFile.is_test), for a repo path."""
    return bool(re.search(r"\.(spec|test)\.[cm]?[jt]sx?$", path) or "/test/" in path or "/__tests__/" in path
                or path.startswith(("test/", "__tests__/")))


def canary_unreachable_test(ntype: str, path: str, inferred_boundary: bool | None) -> bool:
    """A2-353: is this a test code_unit no canary can ever list (and no inferred boundary holds)?

    ONE definition, used by BOTH the producer (verify.py, which discharges `canary` and records it) and the gate
    (mandatory_by_entity below). While verify.py alone knew it, the gate recomputed the matrix minimum without it and
    refused the receipt verify.py issued correctly: HEAD_IMPACT_NOT_COVERED, «required_by_entity omits mandatory
    base/head verifier obligations» (talomnia-site #211, 2026-09-29) — the same split polyglot2 closed for type_check.
    """
    return ntype == "code_unit" and not inferred_boundary and is_test_path(path or "")


def inferred_boundary_by_entity(q: dict) -> dict[str, bool]:
    """The inferred-boundary fact per impacted entity, derived exactly as verify.py derives it: any hop on the chosen
    revision paths with inferred/observed provenance AND a service/repo boundary; the first section that lists the
    entity wins (verify.py uses setdefault in deterministic_core, inferred_tail order); a changed seed has none."""
    out: dict[str, bool] = {}
    for section in ("deterministic_core", "inferred_tail"):
        for e in q["impact_set"][section]:
            if e["entity"] in out:
                continue
            hops = [h for p in e.get("revision_paths", [e]) for h in (p.get("path") or [])]
            out[e["entity"]] = any(h.get("provenance") in ("inferred", "observed") for h in hops) and e.get("boundary") in ("service", "repo")
    return out


def mandatory_by_entity(before: impact.GraphIndex, after: impact.GraphIndex, q: dict) -> dict[str, list[str]]:
    """The matrix minimum, independent of a producer's supplied requirement arrays."""
    matrix = json.loads((Path(__file__).resolve().parents[2] / "contracts/graph-verified-change/verifier-matrix.v1.json").read_text())
    affected = selected(q)
    changed = set(q["seeds"])
    full_test_units = fallback_units(q) if q["impact_set"].get("global_fallback", {}).get("triggered") else set()
    hops = {e: set() for e in affected}
    for section in ("deterministic_core", "inferred_tail"):
        for e in q["impact_set"][section]:
            # A global fallback narrows selected() to the seeds plus the repository's own unit(s),
            # while impact.py still lists the whole graph in deterministic_core as the readable
            # blast radius. Rows outside the selection have no hops entry and are not entities to
            # be verified - they ARE the radius. Skipping them keeps this function agreeing with
            # selected() instead of raising KeyError on the first one (measured: muneral #108).
            if e["entity"] not in hops:
                continue
            for path in e.get("revision_paths", [e]):
                hops[e["entity"]].update(h["edge_type"] for h in path.get("path", []))
    boundary = inferred_boundary_by_entity(q)
    result = {}
    for eid in affected:
        node = after.nodes.get(eid) or before.nodes[eid]
        kinds = hops[eid]
        for idx in (before, after):
            kinds.update(e["type"] for e in idx.fwd.get(eid, []) if e["to"] in affected or eid in changed)
            kinds.update(e["type"] for e in idx.rev.get(eid, []) if e["from"] in affected)
        required = set(matrix["node_types"].get(node["type"], {}).get("mandatory", []))
        required.update(matrix.get("node_kinds", {}).get(node.get("kind"), {}).get("mandatory", []))
        for kind in kinds:
            required.update(matrix["edge_types"].get(kind, {}).get("mandatory", []))
        required = {v for v in required if node["type"] in matrix["verifiers"][v]["applies_to_nodes"]}
        # AUP-GRAPH-009 polyglot2, second site. This function recomputes the matrix minimum
        # independently of verify.py, so the discharge has to exist in BOTH or the gate refuses a
        # receipt the producer issued correctly: measured on scrutator, verify.py dropped the
        # obligation and this one did not, giving `required_by_entity omits mandatory base/head
        # verifier obligations`. `type_check` applies to code_unit, deployable_unit and route; a node
        # that is not TypeScript can never discharge it, whichever of the three it is.
        if node["type"] in ("code_unit", "route") and Path(node.get("path", "")).suffix not in impact.CODE_EXTS:
            required.discard("type_check")
        if node["type"] == "deployable_unit" and not _deployable_has_ts(node.get("path", ""), before, after):
            required.discard("type_check")
        # The A2-353 discharge, the SAME function verify.py calls (see canary_unreachable_test).
        if "canary" in required and canary_unreachable_test(node["type"], node.get("path", ""), boundary.get(eid, False)):
            required.discard("canary")
        if eid in full_test_units:
            required.add("full_fallback_test")  # separate full-suite row, never targeted spec coverage
        result[eid] = sorted(required)
    return result


def _deployable_has_ts(dep_path: str, before: impact.GraphIndex, after: impact.GraphIndex) -> bool:
    """Does this deployable contain TypeScript, as the graph sees it?

    verify.py reads the tree; here only the two graph indexes are in hand, so membership is decided
    by the nodes that live under the deployable's path. Vendored copies are excluded for the same
    reason as there — a caller does not type-check somebody else's shipped code, and
    `.github/graph-admission/**` is a vendored copy of this very tool.
    """
    prefix = "" if dep_path.rstrip("/") in ("", ".") else dep_path.rstrip("/") + "/"
    for idx in (before, after):
        for n in idx.nodes.values():
            p = n.get("path") or ""
            if not p.startswith(prefix):
                continue
            rel = p[len(prefix):]
            if rel.startswith(".github/graph-admission/") or "node_modules/" in rel or rel.startswith("vendor/"):
                continue
            if Path(rel).suffix in impact.CODE_EXTS:
                return True
    return False

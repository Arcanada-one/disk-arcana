#!/usr/bin/env python3
"""AUP-GRAPH-001 `schema0` — validator for RelationshipGraph/v1 and ChangeAdmissionReceipt/v1 documents.

The rules are the `rules` tables of `contracts/graph-verified-change/relationship-graph.v1.json` and
`change-admission-receipt.v1.json`; this file is their executable form. Classification is deterministic:
a document is `conformant` (0 violations) or `violation` (≥ 1 code). `not_measured` never appears here —
the validator either reads the document or refuses with `UNREADABLE`.

`--selftest` runs the fixture battery under `contracts/graph-verified-change/fixtures/` (file name =
expected label: `conformant-*` / `violation-<CODE>-*`), the mutation battery (every rule disabled in turn
must turn ≥ 1 violation fixture green, otherwise the rule is untested and the selftest FAILS) and a
negative control of the selftest itself (a wrong expectation is reported red).

stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTRACT_DIR = ROOT / "contracts" / "graph-verified-change"
GRAPH_SCHEMA_PATH = CONTRACT_DIR / "relationship-graph.v1.json"
RECEIPT_SCHEMA_PATH = CONTRACT_DIR / "change-admission-receipt.v1.json"
FIXTURES_DIR = CONTRACT_DIR / "fixtures"
VERSION = "1.0.0"

SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?Z$")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def repo_relative(ref: str) -> bool:
    """Is this a path a checkout of the repository can resolve? (DEC-AUP-0037 R1)

    Rejects the absolute path (`/home/dev/aup/arc2/runs/A2-233/...` is how #112's evidence left the
    repository), the URL, the home-relative path and anything with a `..` component. Deliberately
    textual: this validator never touches a filesystem, so it may not resolve, stat or normalise.
    """
    if not ref or not ref.strip():
        return False
    ref = ref.strip()
    if ref.startswith(("/", "~", "\\")) or re.match(r"^[A-Za-z]+://", ref) or re.match(r"^[A-Za-z]:[\\/]", ref):
        return False
    return ".." not in PurePosixPath(ref.replace("\\", "/")).parts


def load_schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def graph_digest(doc: dict) -> str:
    """sha256 over canonical {nodes, edges, manifest minus graph_digest minus built_at_utc}."""
    man = {k: v for k, v in (doc.get("manifest") or {}).items() if k not in ("graph_digest", "built_at_utc")}
    return sha256_text(canonical({"nodes": doc.get("nodes"), "edges": doc.get("edges"), "manifest": man}))


def parse_iso(s):
    if not isinstance(s, str) or not ISO_RE.match(s):
        return None
    try:
        return datetime.strptime(s[:19] + "Z" if len(s) >= 19 else s + ":00Z", "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        try:
            return datetime.strptime(s, "%Y-%m-%dT%H:%MZ")
        except ValueError:
            return None


# ------------------------------------------------------------------- global-fallback selection
# One implementation of one rule, in the module that imports nothing of ours, so that every site
# which has to know it can import it: impact_pair.selected(), impact_pair.mandatory_by_entity(),
# verify.py collect_entities(), verify.py --selftest, and check_receipt() below. Six sites; the
# rule has already diverged twice across them (muneral #108, then A2-232), and each divergence was
# a silence, not an error.
def _deployable_dir(entity: str) -> str:
    d = entity.split(":", 1)[1].strip("/")
    return "" if d in ("", ".") else d + "/"


def traversal_entities(rows) -> set[str]:
    """Normal paths remain obligations even when synthetic fallback rows coexist."""
    return {e["entity"] for e in rows if isinstance(e, dict) and "entity" in e
            if any(p.get("path") and not all(h.get("via") == "global-fallback" for h in p["path"])
                   for p in e.get("revision_paths", [e]))}


def fallback_evidence_problems(doc: dict, units: set[str]) -> list[str]:
    """A targeted spec row cannot discharge the repository-wide fallback measurement."""
    if (doc.get("admission") or {}).get("verdict") not in {"admitted", "admitted_with_exemptions"}:
        return []
    records = {v.get("entity"): v for v in doc.get("verdicts", [])}
    rows = {v.get("id"): v for v in doc.get("verifiers", [])}
    problems = []
    for eid in sorted(units):
        referenced = [rows.get(i, {}) for i in records.get(eid, {}).get("verifier_ids", [])]
        if not any(v.get("scope") == "global_fallback_full_suite" and v.get("kind") == "targeted_test"
                   and eid in v.get("entities", []) and v.get("exit_code") == 0
                   and v.get("entity_verdicts", {}).get(eid) == "verified" and v.get("output_ref")
                   for v in referenced):
            problems.append("missing measured full fallback test evidence: " + eid)
    return problems


def fallback_units(rows) -> set[str]:
    """The entities a triggered global fallback collapses onto, from impact-set rows.

    A fallback (lockfile / root manifest / global config) makes the impact the WHOLE REPOSITORY as
    ONE entity - the Bazel/Nx rule of DEC-AUP-0008 - verified by the repository's own build. The
    rows impact.py lists ARE the blast radius, not N separate measurements; demanding a verdict per
    row is what paused a receipt over 464 nodes it had itself collapsed into one (muneral #108).

    But the ONE entity has to EXIST, and until A2-235 it did not: the selection was the change's
    seeds, and a manifest has none. `deployable_unit` is that entity, and it sits right there among
    the rows. One rule:

        every deployable unit in the radius, plus every code unit no deployable unit contains.

    The second half is not a second tier, it is the same sentence: a code unit inside a deployable
    is covered when that deployable is built, and a code unit inside none is covered by nothing, so
    it answers for itself. In a repository with no manifest at all (no package.json / Cargo.toml /
    pyproject.toml) the graph holds no deployable and EVERY code unit is uncovered — which is why
    that case needs no special branch.

    A fallback that reaches neither (documents, receipts, work items only) weighs nothing. The
    caller must NAME that rather than return a quiet `paused_safe` over an empty verdict list
    (A2-232: talomnia-backend, core=14, verdicts=0, verifiers=0, admission paused_safe).
    """
    by_type: dict[str, set[str]] = {}
    for e in rows:
        if not isinstance(e, dict) or not isinstance(e.get("entity"), str):
            continue
        by_type.setdefault(e.get("node_type") or e["entity"].split(":", 1)[0], set()).add(e["entity"])
    units = by_type.get("deployable_unit", set())
    dirs = sorted(_deployable_dir(u) for u in units)
    uncovered = {c for c in by_type.get("code_unit", set())
                 if not any(c.split(":", 1)[1].startswith(d) for d in dirs)}
    return units | uncovered


# --------------------------------------------------------------------------- rule registry
class Ctx:
    def __init__(self, doc, schema, disabled):
        self.doc, self.schema, self.disabled, self.findings = doc, schema, disabled, []

    def add(self, code, detail=""):
        if code not in self.disabled:
            self.findings.append({"code": code, "detail": detail})


# ----------------------------------------------------------------------------------- graph
def check_graph(doc: dict, schema: dict, disabled=frozenset()) -> list[dict]:
    c = Ctx(doc, schema, disabled)
    if doc.get("schema") != schema["document_schema_name"]:
        c.add("GRAPH_SCHEMA_MISMATCH", f"schema={doc.get('schema')!r}")
    man = doc.get("manifest")
    if not isinstance(man, dict):
        man = {}
        c.add("MANIFEST_MISSING_FIELD", "manifest absent")
    for f in schema["manifest"]["required"]:
        if f not in man:
            c.add("MANIFEST_MISSING_FIELD", f)
    if "source_commit" in man and not (isinstance(man["source_commit"], str) and COMMIT_RE.match(man["source_commit"])):
        c.add("SOURCE_COMMIT_INVALID", str(man.get("source_commit"))[:60])
    if "built_at_utc" in man and parse_iso(man["built_at_utc"]) is None:
        c.add("BUILT_AT_INVALID", str(man.get("built_at_utc"))[:60])
    if man.get("dirty") is True:
        c.add("GRAPH_DIRTY", "manifest.dirty = true")
    node_types = schema["node_types"]
    edge_types = schema["edge_types"]
    prov_values = set(schema["provenance"]["values"])
    nodes = doc.get("nodes") if isinstance(doc.get("nodes"), list) else []
    edges = doc.get("edges") if isinstance(doc.get("edges"), list) else []
    ids: dict[str, str] = {}
    for n in nodes:
        if not isinstance(n, dict):
            c.add("NODE_TYPE_UNKNOWN", "node is not an object"); continue
        nid, nt = n.get("id"), n.get("type")
        if nt not in node_types:
            c.add("NODE_TYPE_UNKNOWN", f"{nid}: {nt}")
        if not (isinstance(nid, str) and isinstance(nt, str) and nid.startswith(nt + ":")):
            c.add("NODE_ID_FORM", str(nid))
        if not (isinstance(n.get("content_hash"), str) and SHA_RE.match(n["content_hash"])):
            c.add("NODE_WITHOUT_HASH", str(nid))
        if isinstance(nid, str):
            if nid in ids:
                c.add("DUPLICATE_NODE_ID", nid)
            ids[nid] = nt
    for e in edges:
        if not isinstance(e, dict):
            c.add("EDGE_TYPE_UNKNOWN", "edge is not an object"); continue
        et, fr, to = e.get("type"), e.get("from"), e.get("to")
        label = f"{fr} -{et}-> {to}"
        if et not in edge_types:
            c.add("EDGE_TYPE_UNKNOWN", label)
        if "provenance" not in e:
            c.add("EDGE_WITHOUT_PROVENANCE", label)
        elif e["provenance"] not in prov_values:
            c.add("EDGE_PROVENANCE_INVALID", f"{label}: {e['provenance']!r}")
        else:
            p = e["provenance"]
            if p == "inferred" and not e.get("inferred_by"):
                c.add("INFERRED_WITHOUT_METHOD", label)
            if p == "observed" and parse_iso(e.get("observed_at_utc")) is None:
                c.add("OBSERVED_WITHOUT_TIME", label)
            if p != "inferred" and (e.get("inferred_by") or e.get("via") == "llm"):
                c.add("LLM_EDGE_NOT_INFERRED", f"{label}: provenance={p} inferred_by={e.get('inferred_by')!r}")
        for end in (fr, to):
            if end not in ids:
                c.add("EDGE_ENDPOINT_UNKNOWN", f"{label}: {end}")
        if et in edge_types and fr in ids and to in ids:
            spec = edge_types[et]
            if ids[fr] not in spec["from"] or ids[to] not in spec["to"]:
                c.add("EDGE_ENDPOINT_TYPE_MISMATCH", f"{label}: {ids[fr]} -> {ids[to]}")
    if isinstance(man.get("graph_digest"), str) and man["graph_digest"] != graph_digest(doc):
        c.add("GRAPH_DIGEST_MISMATCH", f"declared {man['graph_digest'][:23]}… recomputed {graph_digest(doc)[:23]}…")
    return c.findings


# --------------------------------------------------------------------------------- receipt
DOC_KINDS = {"doc", "receipt"}


SELECTED_NOTE_RE = re.compile(r"selected: (\[[^\]]*\]|none)")


def _version(v) -> tuple:
    try:
        return tuple(int(x) for x in str(v).split(".")[:3])
    except ValueError:
        return ()


def check_verifier_selection(c: Ctx, doc: dict, F: dict) -> None:
    """A2-413 — the selection as a checked record. See fields.verifier_selection.rule.

    Absence is a finding only where the producer is one that writes the field: receipts from earlier
    producers are dated records whose silence is itself measured (A2-411 § 2) and is never backfilled.
    """
    spec = F["verifier_selection"]
    prod = doc.get("producer") if isinstance(doc.get("producer"), dict) else {}
    need = spec["required_from_producer"]
    knows = prod.get("tool") == need["tool"] and _version(prod.get("version")) >= _version(need["min_version"])
    if "verifier_selection" not in doc:
        if knows:
            c.add("VERIFIER_SELECTION_MISSING", f"{prod.get('tool')} {prod.get('version')} writes verifier_selection; this receipt has none")
        return
    vs = doc["verifier_selection"]
    bad = []
    if not isinstance(vs, dict) or any(k not in vs for k in spec["required"]):
        c.add("VERIFIER_SELECTION_INVALID", f"missing {[k for k in spec['required'] if not isinstance(vs, dict) or k not in vs]}")
        return
    req, app, na = vs["requested"], vs["applied"], vs["not_applied"]
    if vs["schema"] != spec["schema"]:
        bad.append(f"schema {vs['schema']!r}")
    if not (isinstance(req, list) and all(isinstance(x, str) for x in req) and len(set(req)) == len(req)):
        bad.append("requested is not a list of distinct strings"); req = []
    unknown = [x for x in req if x not in spec["selectable_values"]]
    if unknown:
        bad.append(f"requested names non-selectable {unknown}")
    if not (isinstance(app, dict) and all(isinstance(v, list) and v and all(isinstance(e, str) for e in v) for v in app.values())):
        bad.append("applied is not verifier → non-empty entity list"); app = {}
    if not (isinstance(na, list) and all(isinstance(x, dict) and isinstance(x.get("entities"), list) for x in na)):
        bad.append("not_applied is not a list of rows with entities"); na = []
    for v in app:
        if v not in req:
            bad.append(f"applied {v!r} was not requested")
    for x in na:
        if x.get("verifier") not in req:
            bad.append(f"not_applied {x.get('verifier')!r} was not requested")
        if x.get("reason") not in spec["not_applied_reasons"]:
            bad.append(f"not_applied reason {x.get('reason')!r}")
        elif (x["reason"] == "NO_ENTITY_OF_APPLICABLE_TYPE") != (not x["entities"]):
            bad.append(f"not_applied {x.get('verifier')!r}: entities must be empty exactly for NO_ENTITY_OF_APPLICABLE_TYPE")
    accounted = set(app) | {x.get("verifier") for x in na}
    for v in req:
        if v not in accounted:
            bad.append(f"requested {v!r} is accounted for nowhere")
    # Against the per-entity required sets the producer also records: a record of what applied that
    # disagrees with what was demanded is a record of nothing.
    vd = doc.get("verify") if isinstance(doc.get("verify"), dict) else {}
    rbe = vd.get("required_by_entity")
    if isinstance(rbe, dict):
        for v in spec["selectable_values"]:
            demanded = {e for e, r in rbe.items() if isinstance(r, list) and v in r}
            listed = set(app.get(v, []))
            if demanded != listed:
                bad.append(f"applied[{v}] lists {len(listed)} entities, required_by_entity demands {len(demanded)}")
    if bad:
        c.add("VERIFIER_SELECTION_INVALID", "; ".join(bad)[:400])
    # The prose line stays until this field is the only record; while both exist they must agree.
    notes = doc.get("notes") if isinstance(doc.get("notes"), list) else []
    for n in notes:
        m = SELECTED_NOTE_RE.search(n) if isinstance(n, str) else None
        if not m:
            continue
        said = [] if m.group(1) == "none" else re.findall(r"'([^']*)'", m.group(1))
        if sorted(said) != sorted(req):
            c.add("VERIFIER_SELECTION_CONTRADICTS_NOTES", f"notes say {sorted(said)}, verifier_selection.requested {sorted(req)}")


def check_receipt(doc: dict, schema: dict, disabled=frozenset()) -> list[dict]:
    c = Ctx(doc, schema, disabled)
    F = schema["fields"]
    if doc.get("schema") != schema["document_schema_name"]:
        c.add("RECEIPT_SCHEMA_MISMATCH", f"schema={doc.get('schema')!r}")
    for f in F["required"]:
        if f not in doc:
            c.add("RECEIPT_MISSING_FIELD", f)

    def sub(name):
        v = doc.get(name)
        return v if isinstance(v, dict) else {}

    for name in ("producer", "repo", "graph", "tree", "staleness"):
        for f in F[name]["required"]:
            if f not in sub(name):
                c.add("RECEIPT_MISSING_FIELD", f"{name}.{f}")
    graph, tree, stale, cs = sub("graph"), sub("tree"), sub("staleness"), sub("change_set")
    if not (isinstance(graph.get("source_commit"), str) and COMMIT_RE.match(graph["source_commit"])):
        c.add("RECEIPT_WITHOUT_GRAPH_COMMIT", str(graph.get("source_commit"))[:60])
    if not (isinstance(graph.get("graph_digest"), str) and SHA_RE.match(graph["graph_digest"])):
        c.add("RECEIPT_WITHOUT_GRAPH_DIGEST", str(graph.get("graph_digest"))[:60])
    # change set
    mode = cs.get("mode")
    files = cs.get("files") if isinstance(cs.get("files"), list) else []
    if "mode" not in cs or "files" not in cs:
        c.add("RECEIPT_MISSING_FIELD", "change_set.mode/files")
    if mode not in F["change_set"]["mode_values"]:
        c.add("CHANGE_SET_FILE_INVALID", f"mode={mode!r}")
    if mode == "diff":
        for f in ("base", "head"):
            if f not in cs:
                c.add("RECEIPT_MISSING_FIELD", f"change_set.{f}")
    if not files:
        c.add("CHANGE_SET_EMPTY", "")
    fspec = F["change_set"]["file"]
    changed_nodes = []
    non_doc_change = False
    for f in files:
        if not isinstance(f, dict) or any(k not in f for k in fspec["required"]) \
                or f.get("status") not in fspec["status_values"] or f.get("kind") not in fspec["kind_values"]:
            c.add("CHANGE_SET_FILE_INVALID", canonical(f)[:120]); continue
        if f["kind"] not in DOC_KINDS:
            non_doc_change = True
        if f.get("node_id"):
            changed_nodes.append(f["node_id"])
    recorded_entities = {v.get("entity") for v in (doc.get("verdicts") or []) if isinstance(v, dict)}
    # structural exclusions (DEC-AUP-0034): affected entities that owe this change no verdict because
    # the verifier matrix gives their node type no verifier at all and their bytes did not change. Here
    # only the DOCUMENT is judged — shape, and the two self-consistency facts the receipt itself carries
    # (an entity is never both excluded and given a verdict, and a changed entity is never excluded).
    # Whether the exclusion is TRUE of the tree is re-derived from Git by impact_pair.receipt_problems,
    # which is the gate's independent check; this validator has no repository in hand.
    excluded = set()
    for x in (doc.get("structural_exclusions") if isinstance(doc.get("structural_exclusions"), list) else []):
        if not isinstance(x, dict) or not isinstance(x.get("entity"), str) or not x["entity"]:
            c.add("STRUCTURAL_EXCLUSION_INVALID", "entry without an entity"); continue
        ch = x.get("content_hash") if isinstance(x.get("content_hash"), dict) else {}
        missing = [f for f in ("node_type", "reason") if not x.get(f)]
        if missing:
            c.add("STRUCTURAL_EXCLUSION_INVALID", f"{x['entity']}: missing {', '.join(missing)}"); continue
        # The entity a receipt cannot verify is the PREVIOUS VERSION OF ITSELF (DEC-AUP-0035). That
        # one IS in the change set and its bytes DO differ — the two facts DEC-AUP-0034 relies on
        # are inverted here, so it is admitted on entirely different evidence: the excluded path is
        # the path this document was written to, and the receipt standing there declares the same
        # work item. Everything the document can check about that is checked here; whether it is
        # TRUE of the tree is re-derived from Git by impact_pair.receipt_problems.
        if x.get("rule") == "DEC-AUP-0035":
            sup = x.get("superseded") if isinstance(x.get("superseded"), dict) else {}
            wi = doc.get("work_item")
            wi = wi if isinstance(wi, str) else (wi or {}).get("task_id") if isinstance(wi, dict) else None
            path = x.get("path")
            bad = None
            if not (isinstance(path, str) and path and x["entity"] == "receipt:" + path):
                bad = "entity and path must be the same receipt file"
            elif path != doc.get("receipt_path"):
                bad = (f"path {path!r} is not this receipt's own output path "
                       f"{doc.get('receipt_path')!r} — only the document it replaces is superseded")
            elif not wi or sup.get("work_item") != wi:
                bad = (f"superseded.work_item {sup.get('work_item')!r} is not this receipt's work item "
                       f"{wi!r}")
            elif sup.get("receipt_path") != path:
                bad = "superseded.receipt_path disagrees with path"
            elif not (ch.get("head") is None or (isinstance(ch.get("head"), str)
                                                 and re.fullmatch(r"sha256:[0-9a-f]{64}", ch["head"]))) \
                    or not (ch.get("base") is None or (isinstance(ch.get("base"), str)
                                                       and re.fullmatch(r"sha256:[0-9a-f]{64}", ch["base"]))):
                bad = "content_hash values must each be sha256:<64 hex> or null (absent at that revision)"
            elif ch.get("base") is None and ch.get("head") is None:
                bad = "content_hash names no revision at which the superseded receipt exists"
            elif x["entity"] in recorded_entities:
                bad = "excluded AND given a verdict"
            if bad:
                c.add("STRUCTURAL_EXCLUSION_INVALID", f"{x['entity']}: {bad}"); continue
            excluded.add(x["entity"]); continue
        if not (isinstance(ch.get("base"), str) and ch.get("base") == ch.get("head")
                and re.fullmatch(r"sha256:[0-9a-f]{64}", ch["base"])):
            c.add("STRUCTURAL_EXCLUSION_INVALID",
                  f"{x['entity']}: content_hash must be one equal sha256:<64 hex> at base and head"); continue
        if x["entity"] in recorded_entities:
            c.add("STRUCTURAL_EXCLUSION_INVALID", f"{x['entity']}: excluded AND given a verdict"); continue
        if x["entity"] in changed_nodes:
            c.add("STRUCTURAL_EXCLUSION_INVALID", f"{x['entity']}: the change set contains it"); continue
        excluded.add(x["entity"])
    # staleness
    sv = stale.get("verdict")
    if sv == "not_checked":
        c.add("STALENESS_NOT_CHECKED", "")
    elif sv != "fresh":
        c.add("RECEIPT_ON_STALE_GRAPH", f"staleness.verdict={sv!r}")
    else:
        ref_commit = cs.get("base") if mode == "diff" else tree.get("commit")
        if graph.get("source_commit") and ref_commit and graph["source_commit"] != ref_commit:
            c.add("RECEIPT_ON_STALE_GRAPH", f"graph {str(graph['source_commit'])[:12]} ≠ {'base' if mode == 'diff' else 'tree'} {str(ref_commit)[:12]}")
        if mode == "diff" and tree.get("dirty") is True:
            c.add("RECEIPT_ON_STALE_GRAPH", "dirty tree in diff mode")
        if stale.get("mismatched_nodes"):
            c.add("RECEIPT_ON_STALE_GRAPH", f"{len(stale['mismatched_nodes'])} mismatched nodes")
    # Optional paired revision evidence is strict whenever present.
    if "head_graph" in doc or "revision_selection" in doc:
        hg, rs = sub("head_graph"), sub("revision_selection")
        hs = hg.get("staleness") if isinstance(hg.get("staleness"), dict) else {}
        if mode != "diff" or hg.get("source_commit") != cs.get("head") or not SHA_RE.fullmatch(str(hg.get("graph_digest", ""))) or hs.get("verdict") != "fresh":
            c.add("HEAD_GRAPH_BINDING_INVALID", "head revision/digest/freshness does not match the committed change")
        valid = rs.get("schema") == "RevisionImpactSelection/v1" and all(isinstance(rs.get(k), list) and all(isinstance(x, str) for x in rs[k]) for k in ("base", "head", "unmeasured_head_files"))
        if not valid:
            c.add("REVISION_SELECTION_INCOMPLETE", "missing typed base/head selections")
        else:
            selected = set(rs["base"]) | set(rs["head"])
            # A structurally excluded entity is covered, not missing (DEC-AUP-0034). `excluded` holds
            # only entries that already survived validation above, so a forged exclusion buys nothing
            # here either: it was dropped from the set AND reported as STRUCTURAL_EXCLUSION_INVALID.
            recorded = recorded_entities | excluded
            vd = doc.get("verify") if isinstance(doc.get("verify"), dict) else {}
            required = vd.get("required_by_entity")
            if selected - recorded or (required is not None and (not isinstance(required, dict) or selected - set(required))):
                c.add("REVISION_SELECTION_INCOMPLETE", "selected entity lacks verdict or required verifier selection")
            if rs["unmeasured_head_files"] and (doc.get("admission") or {}).get("verdict") in {"admitted", "admitted_with_exemptions"}:
                c.add("REVISION_SELECTION_INCOMPLETE", "unmeasured head code cannot be admitted")
    check_verifier_selection(c, doc, F)
    # impact set
    imp = sub("impact_set")
    for f in F["impact_set"]["required"]:
        if f not in imp:
            c.add("RECEIPT_MISSING_FIELD", f"impact_set.{f}")
    core = imp.get("deterministic_core") if isinstance(imp.get("deterministic_core"), list) else []
    tail = imp.get("inferred_tail") if isinstance(imp.get("inferred_tail"), list) else []
    gf = imp.get("global_fallback") if isinstance(imp.get("global_fallback"), dict) else {}
    if gf.get("triggered") is True and not gf.get("reason"):
        c.add("GLOBAL_FALLBACK_WITHOUT_REASON", "")
    # A triggered global fallback (lockfile / global config) makes the impact the WHOLE
    # REPOSITORY as ONE entity - the Bazel/Nx rule of DEC-AUP-0008 - verified by the
    # repository's own test job. impact.py still lists every node so a reader can see the
    # blast radius, and the receipt keeps that listing; but those rows ARE the radius, not
    # N separate measurements. Demanding a verdict per row is the same disagreement that
    # `selected()`, `mandatory_by_entity()` and `collect_entities()` were each taught to
    # avoid; this is its fourth site. Measured on muneral #108: 458 rows against 8
    # verdicts, ENTITY_WITHOUT_VERDICT, receipt refused. The archived receipts show what
    # the unfixed rule cost - deps-floors carries 149 exemptions, one per row, each with
    # an expiry, where the fixed rule demands two.
    #
    # Only the VERDICT DEMAND narrows. Every per-row check below - provenance, placement,
    # boundary - still runs on all rows: those measure the quality of the radius listing
    # itself, they do not ask for a verdict, and silently switching them off while fixing
    # something else would be the worse defect.
    fallback_selection = None
    if gf.get("triggered") is True:
        # The demand is the seeds plus the repository's own unit(s) — `fallback_units` above. It
        # used to fall back to "what the receipt actually judged" whenever `impact_set.seeds` was
        # absent, which impact.py never emits: a receipt with ZERO verdicts therefore demanded
        # zero, and passed as conformant. That is the receipt grading its own homework, and it is
        # the same silence A2-232 measured in the producer (talomnia-backend: core=14, verdicts=0).
        # Derive the demand from the rows instead — they are in the receipt, independent of it.
        seeds = imp.get("seeds")
        fallback_selection = fallback_units(core + tail) | traversal_entities(core + tail)
        # Historical receipts remain readable under their producer's format; live admission
        # always re-derives the full-suite obligation from Git in impact_pair.receipt_problems.
        producer = doc.get("producer") or {}
        modern = producer.get("tool") == "tools/graph/verify.py" and _version(producer.get("version")) >= (1, 3, 0)
        scoped = any(v.get("scope") == "global_fallback_full_suite" for v in doc.get("verifiers", []))
        if modern or scoped:
            for problem in fallback_evidence_problems(doc, fallback_units(core + tail)):
                c.add("FULL_FALLBACK_TEST_NOT_MEASURED", problem)
        if isinstance(seeds, list):
            fallback_selection |= {s for s in seeds if isinstance(s, str)}
        fallback_selection |= {n for f in ((doc.get("change_set") or {}).get("files") or [])
                               if isinstance(f, dict)
                               for n in (f.get("node_ids") or ([f["node_id"]] if f.get("node_id") else []))
                               if isinstance(n, str)}
    entities = []
    boundary_inferred = []
    for section, entries in (("deterministic_core", core), ("inferred_tail", tail)):
        for e in entries:
            if not isinstance(e, dict) or "entity" not in e:
                c.add("IMPACT_ENTRY_WITHOUT_PROVENANCE", f"{section}: entry without entity"); continue
            if fallback_selection is None or e["entity"] in fallback_selection:
                entities.append(e["entity"])
            path = e.get("path") if isinstance(e.get("path"), list) else []
            if not path:
                c.add("IMPACT_ENTRY_WITHOUT_PROVENANCE", f"{e['entity']}: empty path"); continue
            provs = []
            for hop in path:
                if not isinstance(hop, dict) or "provenance" not in hop or hop["provenance"] not in ("deterministic", "inferred", "observed"):
                    c.add("IMPACT_ENTRY_WITHOUT_PROVENANCE", f"{e['entity']}: hop without provenance"); provs.append(None)
                else:
                    provs.append(hop["provenance"])
            non_det = any(p in ("inferred", "observed") for p in provs)
            if section == "deterministic_core" and non_det:
                c.add("IMPACT_ENTRY_MISPLACED", f"{e['entity']} has an inferred/observed hop but sits in deterministic_core")
            if section == "inferred_tail" and provs and all(p == "deterministic" for p in provs):
                c.add("IMPACT_ENTRY_MISPLACED", f"{e['entity']} is fully deterministic but sits in inferred_tail")
            if non_det and e.get("boundary") in ("service", "repo"):
                boundary_inferred.append(e["entity"])
    if not core and not tail and gf.get("triggered") is not True and non_doc_change:
        exp = doc.get("empty_impact_explanation")
        if not (isinstance(exp, dict) and exp.get("reason") and isinstance(exp.get("graph_metadata"), dict) and exp["graph_metadata"]):
            c.add("EMPTY_IMPACT_WITHOUT_EXPLANATION", "non-doc change, empty impact set, no explanation with graph_metadata")
    exp = doc.get("empty_impact_explanation")
    if isinstance(exp, dict) and ("binding" in exp or exp.get("schema") == "BoundEmptyImpactExplanation/v1"):
        binding = exp.get("binding")
        claim = binding.get("input") if isinstance(binding, dict) else None
        keys = {"schema", "base", "head", "base_graph_digest", "head_graph_digest", "scope", "reason"}
        valid = isinstance(binding, dict) and set(binding) == {"schema", "input", "input_sha256"} and binding.get("schema") == "BoundEmptyImpactExplanation/v1" and isinstance(claim, dict) and set(claim) == keys
        if valid:
            encoded = (json.dumps(claim, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
            valid = (exp.get("schema") == "BoundEmptyImpactExplanation/v1" and claim["schema"] == "EmptyImpactExplanation/v1" and claim["scope"] == "graph_non_seed_dependents"
                     and binding["input_sha256"] == "sha256:" + hashlib.sha256(encoded).hexdigest()
                     and isinstance(claim["reason"], str) and len(claim["reason"].strip()) >= 40
                     and exp.get("reason") == claim["reason"].strip()
                     and all(claim[k] == (doc.get("change_set") or {}).get(k) for k in ("base", "head"))
                     and claim["base_graph_digest"] == (doc.get("graph") or {}).get("graph_digest")
                     and claim["head_graph_digest"] == (doc.get("head_graph") or {}).get("graph_digest")
                     and isinstance(exp.get("graph_metadata"), dict)
                     and exp["graph_metadata"].get("scope") == "graph_non_seed_dependents"
                     and isinstance(exp["graph_metadata"].get("revisions"), dict)
                     and set(exp["graph_metadata"].get("revisions", {})) == {"base", "head"}
                     and not core and not tail and gf.get("triggered") is not True)
        if not valid:
            c.add("EMPTY_IMPACT_WITHOUT_EXPLANATION", "invalid exact paired author explanation binding")
    # verifiers
    vers = doc.get("verifiers") if isinstance(doc.get("verifiers"), list) else []
    vspec = F["verifier"]
    ver_ids = set()
    canary_entities = set()
    canary_rows = []
    probe_ids = set()
    for v in vers:
        if not isinstance(v, dict):
            c.add("VERIFIER_WITHOUT_OUTPUT_REF", "verifier is not an object"); continue
        if v.get("id"):
            ver_ids.add(v["id"])
        if v.get("kind") not in vspec["kind_values"]:
            c.add("VERIFIER_KIND_UNKNOWN", f"{v.get('id')}: {v.get('kind')!r}")
        if not v.get("output_ref") or "exit_code" not in v:
            c.add("VERIFIER_WITHOUT_OUTPUT_REF", str(v.get("id")))
        for f in vspec["required"]:
            if f not in v and f not in ("output_ref", "exit_code"):
                c.add("RECEIPT_MISSING_FIELD", f"verifier {v.get('id')}: {f}")
        if v.get("kind") in {"canary", "shell_behavior"}:
            canary_entities.update(v.get("entities") or [])
            canary_rows.append(v)
        if v.get("kind") == "endpoint_probe":
            probe_ids.add(v.get("id"))
    # observed probes (DEC-AUP-0039) — the section is the MEASUREMENT, the verifier row is the CLAIM.
    #
    # An endpoint probe observes a running contour, so its evidence cannot be re-derived from the tree at
    # head. A2-251 measured what that costs while the section was unnamed: fifteen probe results written
    # into an `observed` key, a receipt all of whose observations were `failed` still `conformant`, and
    # `kind: endpoint_probe` itself a VERIFIER_KIND_UNKNOWN violation. Tolerated is not read.
    #
    # `probe_supports` maps an endpoint_probe verifier id to the worst thing observed under it. The
    # binding is one-directional on purpose: a row names its verifier, so a probe cannot quietly attach
    # itself to a claim, and a verifier row with no rows under it supports nothing.
    observed_rows = doc.get("observed")
    probe_observations: dict[str, list[str]] = {vid: [] for vid in probe_ids if isinstance(vid, str)}
    if observed_rows is not None:
        ospec = F.get("observed") or {}
        if not isinstance(observed_rows, list):
            c.add("OBSERVED_ENTRY_INVALID", f"observed is {type(observed_rows).__name__}, not a list")
            observed_rows = []
        seen_probes = set()
        for o in observed_rows:
            if not isinstance(o, dict):
                c.add("OBSERVED_ENTRY_INVALID", "row is not an object"); continue
            label = str(o.get("probe"))[:60]
            missing = [f for f in ospec.get("required", []) if not o.get(f)]
            if missing:
                c.add("OBSERVED_ENTRY_INVALID", f"{label}: missing {', '.join(missing)}"); continue
            if o["verdict"] not in ospec.get("verdict_values", []):
                c.add("OBSERVED_ENTRY_INVALID", f"{label}: verdict={o['verdict']!r} is not tri-valued"); continue
            if o["probe"] in seen_probes:
                c.add("OBSERVED_ENTRY_INVALID", f"{label}: duplicate probe id"); continue
            seen_probes.add(o["probe"])
            if o["verdict"] != "verified" and not o.get("detail"):
                c.add("OBSERVED_ENTRY_INVALID",
                      f"{label}: verdict {o['verdict']} without a detail saying what was seen instead")
                continue
            if o["verifier_id"] not in probe_observations:
                c.add("OBSERVED_ENTRY_INVALID",
                      f"{label}: verifier_id {o['verifier_id']!r} is not a verifier of kind endpoint_probe "
                      f"in this receipt")
                continue
            probe_observations[o["verifier_id"]].append(o["verdict"])

    # exemptions
    exs = doc.get("exemptions") if isinstance(doc.get("exemptions"), list) else []
    captured = parse_iso(doc.get("captured_at_utc"))
    valid_exempt = set()
    for x in exs:
        if not isinstance(x, dict):
            c.add("EXEMPTION_WITHOUT_OWNER", "exemption is not an object"); continue
        ok = True
        if not x.get("owner"):
            c.add("EXEMPTION_WITHOUT_OWNER", str(x.get("entity"))); ok = False
        exp_t = parse_iso(x.get("expires_at_utc"))
        if exp_t is None:
            c.add("EXEMPTION_WITHOUT_EXPIRY", str(x.get("entity"))); ok = False
        elif captured and exp_t <= captured:
            c.add("EXEMPTION_EXPIRED", f"{x.get('entity')}: {x.get('expires_at_utc')} ≤ {doc.get('captured_at_utc')}"); ok = False
        for f in ("entity", "reason"):
            if not x.get(f):
                c.add("RECEIPT_MISSING_FIELD", f"exemption.{f}"); ok = False
        if ok:
            valid_exempt.add(x["entity"])
    # verdicts
    vds = doc.get("verdicts") if isinstance(doc.get("verdicts"), list) else []
    verdict_of = {}
    for v in vds:
        if not isinstance(v, dict) or "entity" not in v:
            c.add("VERDICT_NOT_TRIVALUED", "verdict without entity"); continue
        val = v.get("verdict")
        if val not in F["verdict"]["verdict_values"]:
            c.add("VERDICT_NOT_TRIVALUED", f"{v['entity']}: {val!r}"); continue
        verdict_of[v["entity"]] = val
        if val == "verified":
            vids = v.get("verifier_ids") or []
            if not vids or any(i not in ver_ids for i in vids):
                c.add("VERIFIED_WITHOUT_VERIFIER", v["entity"])
        if val == "not_measured" and not v.get("reason"):
            c.add("NOT_MEASURED_WITHOUT_REASON", v["entity"])
    # A probe claim is CASHED the same way a canary claim is (DEC-AUP-0037): a `verified` verdict cites
    # the row. Only then does the receipt owe an observation — a probe row nobody rests on claims nothing,
    # and an honest `not_measured` verdict must stay conformant or the rule would punish the receipt that
    # refused to overstate itself. There is no boundary half here: unlike a canary, an endpoint probe is
    # never what silently discharges some other rule.
    for v in vds:
        if not isinstance(v, dict) or v.get("verdict") != "verified":
            continue
        for vid in (v.get("verifier_ids") or []):
            if vid not in probe_observations:
                continue
            seen = probe_observations[vid]
            if not seen:
                c.add("ENDPOINT_PROBE_WITHOUT_OBSERVATION",
                      f"{v.get('entity')} rests on {vid}, which records no observation")
            elif any(x != "verified" for x in seen):
                bad = sorted({x for x in seen if x != "verified"})
                c.add("PROBE_CLAIM_CONTRADICTS_OBSERVATION",
                      f"{v.get('entity')} is verified on {vid}, whose observations include "
                      f"{', '.join(bad)} ({len(seen)} probe(s) recorded)")
    for ent in entities + changed_nodes:
        if ent not in verdict_of and ent not in excluded:
            c.add("ENTITY_WITHOUT_VERDICT", ent)
    # admission
    adm = sub("admission")
    for f in F["admission"]["required"]:
        if f not in adm:
            c.add("RECEIPT_MISSING_FIELD", f"admission.{f}")
    av = adm.get("verdict")
    # an inferred/observed edge across a service boundary never alone waives the canary: a claim of `verified`
    # or an admission needs a canary listing the entity or a valid exemption; an honest not_measured + paused_safe/refused is conformant
    #
    # A2-270: the condition is named ONCE, because the same predicate decides below whether a canary
    # row's listing is load-bearing. A boundary entity that owes no canary here cannot be the reason
    # some canary row is being spent there.
    def owes_canary(ent: str) -> bool:
        return ent not in valid_exempt and (verdict_of.get(ent) == "verified"
                                            or av in ("admitted", "admitted_with_exemptions"))

    for ent in boundary_inferred:
        if ent not in canary_entities and owes_canary(ent):
            c.add("INFERRED_BOUNDARY_WITHOUT_CANARY", f"{ent}: verdict={verdict_of.get(ent)} admission={av}")
    # DEC-AUP-0037 R1 — a canary claim the gate cannot open is testimony, not measurement.
    #
    # This validator holds only the document, so it checks the one thing a document can carry: that
    # the claim POINTS INTO the repository. Whether the pointed-at bytes exist and say what the row
    # says is admit_change.canary_coverage's half, which has the repo (R2).
    #
    # The rule fires only where a claim is CASHED — a `verified` verdict citing the row, or the row
    # being what keeps INFERRED_BOUNDARY_WITHOUT_CANARY quiet for a boundary entity. A canary row
    # that discharges nothing claims nothing, and an honest not_measured must stay conformant or the
    # rule would punish the very receipt that refused to overstate itself.
    #
    # A2-270: `quieted` is the entities whose INFERRED_BOUNDARY_WITHOUT_CANARY finding the row's
    # listing is ACTUALLY suppressing — the same predicate the rule above applies, not membership of
    # the list alone. Reading the bare list made every `verify.py` receipt of a code change a
    # violation: `v-canary` writes every boundary entity into its row even when it consumed zero
    # canary documents (`0 canary result(s); 0 verified / 0 failed / 86 not_measured`), so a row that
    # measured nothing, that no verdict rests on and whose entities are all exempted or honestly
    # `not_measured`, was called cashed and refused for its `output_ref`. Measured on muneral#163
    # (A2-267): as `verify.py` wrote it the receipt is a violation naming three EXEMPTED entities as
    # "resting on" the row, and it was made conformant only by hand-editing `entities` to `[]` — an
    # edit that erases the record of which entities the canary verifier ran over. DEC-AUP-0037 R2 is
    # the side that was wrong here: the entities a canary COVERS are the ones its document lists;
    # the row's `entities` is the scope the verifier ran over ("what actually ran", the receipt
    # contract's own words for `verifiers`), and scope is not a claim of coverage.
    cashed_ids = {vid for rec in vds if isinstance(rec, dict) and rec.get("verdict") == "verified"
                  for vid in (rec.get("verifier_ids") or []) if isinstance(vid, str)}
    quieted = {e for e in boundary_inferred if e in canary_entities and owes_canary(e)}
    for v in canary_rows:
        ents = set(v.get("entities") or [])
        resting = sorted({e for e, verdict in verdict_of.items()
                          if verdict == "verified" and v.get("id") in
                          {i for rec in vds if isinstance(rec, dict) and rec.get("entity") == e
                           for i in (rec.get("verifier_ids") or [])}} | (ents & quieted))
        if v.get("id") not in cashed_ids and not (ents & quieted):
            continue
        ref = v.get("output_ref")
        if not isinstance(ref, str) or not repo_relative(ref):
            c.add("CANARY_CLAIM_WITHOUT_COMMITTED_EVIDENCE",
                  f"{v.get('id')}: output_ref={ref!r} is not a path inside the repository; "
                  f"{len(resting)} entity(ies) rest on it: " + ", ".join(resting[:6]))
    if av is not None and av not in F["admission"]["verdict_values"]:
        c.add("ADMISSION_VERDICT_INVALID", str(av))
    non_verified = [e for e, v in verdict_of.items() if v != "verified"]
    if av == "admitted" and (non_verified or (gf.get("triggered") is True and not verdict_of)):
        c.add("ADMISSION_CONTRADICTS_VERDICTS", f"admitted with {len(non_verified)} non-verified entities")
    if av == "admitted_with_exemptions" and any(e not in valid_exempt for e in non_verified):
        c.add("ADMISSION_CONTRADICTS_VERDICTS", "admitted_with_exemptions but a non-verified entity has no valid exemption")
    return c.findings


# -------------------------------------------------------------------------------- dispatch
def classify(doc, gschema=None, rschema=None, disabled=frozenset()) -> dict:
    gschema = gschema or load_schema(GRAPH_SCHEMA_PATH)
    rschema = rschema or load_schema(RECEIPT_SCHEMA_PATH)
    if not isinstance(doc, dict):
        return {"verdict": "violation", "kind": "unknown", "findings": [{"code": "UNREADABLE", "detail": "document is not an object"}]}
    s = doc.get("schema")
    if s == rschema["document_schema_name"] or (isinstance(s, str) and s.startswith("ChangeAdmissionReceipt")) or "impact_set" in doc:
        findings, kind = check_receipt(doc, rschema, disabled), "receipt"
    else:
        findings, kind = check_graph(doc, gschema, disabled), "graph"
    codes = sorted({f["code"] for f in findings})
    return {"verdict": "conformant" if not findings else "violation", "kind": kind, "codes": codes, "findings": findings}


def classify_file(path: Path, **kw) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"file": str(path), "verdict": "violation", "kind": "unknown", "codes": ["UNREADABLE"], "findings": [{"code": "UNREADABLE", "detail": str(e)[:200]}]}
    r = classify(doc, **kw)
    r["file"] = str(path)
    return r


ALL_GRAPH_RULES = ("GRAPH_SCHEMA_MISMATCH", "MANIFEST_MISSING_FIELD", "SOURCE_COMMIT_INVALID", "BUILT_AT_INVALID", "NODE_TYPE_UNKNOWN",
                   "NODE_WITHOUT_HASH", "NODE_ID_FORM", "DUPLICATE_NODE_ID", "EDGE_TYPE_UNKNOWN", "EDGE_WITHOUT_PROVENANCE",
                   "EDGE_PROVENANCE_INVALID", "INFERRED_WITHOUT_METHOD", "OBSERVED_WITHOUT_TIME", "LLM_EDGE_NOT_INFERRED",
                   "EDGE_ENDPOINT_UNKNOWN", "EDGE_ENDPOINT_TYPE_MISMATCH", "GRAPH_DIGEST_MISMATCH", "GRAPH_DIRTY")
ALL_RECEIPT_RULES = ("RECEIPT_SCHEMA_MISMATCH", "RECEIPT_MISSING_FIELD", "RECEIPT_WITHOUT_GRAPH_COMMIT", "RECEIPT_WITHOUT_GRAPH_DIGEST",
                     "RECEIPT_ON_STALE_GRAPH", "STALENESS_NOT_CHECKED", "CHANGE_SET_EMPTY", "CHANGE_SET_FILE_INVALID",
                     "EMPTY_IMPACT_WITHOUT_EXPLANATION", "IMPACT_ENTRY_WITHOUT_PROVENANCE", "IMPACT_ENTRY_MISPLACED",
                     "GLOBAL_FALLBACK_WITHOUT_REASON", "INFERRED_BOUNDARY_WITHOUT_CANARY", "VERIFIER_WITHOUT_OUTPUT_REF",
                     "VERIFIER_KIND_UNKNOWN", "ENTITY_WITHOUT_VERDICT", "VERDICT_NOT_TRIVALUED", "VERIFIED_WITHOUT_VERIFIER",
                     "NOT_MEASURED_WITHOUT_REASON", "EXEMPTION_WITHOUT_OWNER", "EXEMPTION_WITHOUT_EXPIRY", "EXEMPTION_EXPIRED",
                     "ADMISSION_CONTRADICTS_VERDICTS", "ADMISSION_VERDICT_INVALID", "HEAD_GRAPH_BINDING_INVALID", "REVISION_SELECTION_INCOMPLETE",
                     "STRUCTURAL_EXCLUSION_INVALID", "CANARY_CLAIM_WITHOUT_COMMITTED_EVIDENCE",
                     "OBSERVED_ENTRY_INVALID", "ENDPOINT_PROBE_WITHOUT_OBSERVATION", "PROBE_CLAIM_CONTRADICTS_OBSERVATION",
                     "VERIFIER_SELECTION_INVALID", "VERIFIER_SELECTION_MISSING", "VERIFIER_SELECTION_CONTRADICTS_NOTES")


# -------------------------------------------------------------------------------- selftest
def expected_label(name: str):
    if name.startswith("conformant-"):
        return "conformant", None
    m = re.match(r"^violation-(\d+-)?([A-Z_]+)", name)
    if m:
        return "violation", m.group(2)
    return None, None


def run_battery(fixtures: list[Path], disabled=frozenset()) -> dict:
    gs, rs = load_schema(GRAPH_SCHEMA_PATH), load_schema(RECEIPT_SCHEMA_PATH)
    rows, fn, fp = [], 0, 0
    for p in sorted(fixtures):
        label, code = expected_label(p.name)
        r = classify_file(p, gschema=gs, rschema=rs, disabled=disabled)
        if label == "conformant":
            ok = r["verdict"] == "conformant"
            if not ok:
                fp += 1
        else:
            ok = r["verdict"] == "violation" and code in r["codes"]
            if not ok:
                fn += 1
        rows.append({"fixture": p.name, "expected": label, "expected_code": code, "verdict": r["verdict"], "codes": r["codes"], "ok": ok})
    return {"rows": rows, "false_negatives": fn, "false_positives": fp, "n": len(rows)}


def selftest(receipt_out: Path | None) -> int:
    fixtures = sorted(FIXTURES_DIR.glob("*.json"))
    res = {"schema": "ReadinessReceipt/v1", "portion_id": "AUP-GRAPH-001:schema0", "tool": "tools/graph/schema_check.py", "tool_version": VERSION,
           "captured_at_utc": now_iso(), "checks": []}
    failed = []

    def assert_(name, cond, **kw):
        res["checks"].append({"name": name, "ok": bool(cond), **kw})
        if not cond:
            failed.append(name)
        print(("PASS " if cond else "FAIL ") + name + (f"  {kw}" if kw and not cond else ""))

    # 1 the schemas load and their rule tables match the registry here
    gs, rs = load_schema(GRAPH_SCHEMA_PATH), load_schema(RECEIPT_SCHEMA_PATH)
    assert_("graph schema rule table == validator registry", set(gs["rules"]) == set(ALL_GRAPH_RULES), missing=sorted(set(gs["rules"]) ^ set(ALL_GRAPH_RULES)))
    assert_("receipt schema rule table == validator registry", set(rs["rules"]) == set(ALL_RECEIPT_RULES), missing=sorted(set(rs["rules"]) ^ set(ALL_RECEIPT_RULES)))
    # 2 fixture battery
    assert_("fixture count ≥ 20", len(fixtures) >= 20, n=len(fixtures))
    labels = [expected_label(p.name) for p in fixtures]
    assert_("every fixture is labelled conformant / violation-<CODE>", all(l[0] for l in labels))
    b = run_battery(fixtures)
    res["fixture_battery"] = b
    assert_("fixture battery: 0 false negatives", b["false_negatives"] == 0, rows=[r for r in b["rows"] if not r["ok"]])
    assert_("fixture battery: 0 false positives", b["false_positives"] == 0, rows=[r for r in b["rows"] if not r["ok"]])
    for must in ("EDGE_WITHOUT_PROVENANCE", "RECEIPT_ON_STALE_GRAPH", "EMPTY_IMPACT_WITHOUT_EXPLANATION", "INFERRED_BOUNDARY_WITHOUT_CANARY", "VERDICT_NOT_TRIVALUED", "RECEIPT_WITHOUT_GRAPH_COMMIT"):
        assert_(f"mandated fixture present: {must}", any(l[1] == must for l in labels))
    kinds = {}
    for p in fixtures:
        r = classify_file(p, gschema=gs, rschema=rs)
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    assert_("fixtures cover both graphs and receipts", kinds.get("graph", 0) >= 5 and kinds.get("receipt", 0) >= 5, kinds=kinds)
    # 3 mutation battery: disable each rule → ≥ 1 violation fixture goes green
    exercised = {c for (l, c) in labels if l == "violation"}
    mutants = []
    survived = []
    for rule in ALL_GRAPH_RULES + ALL_RECEIPT_RULES:
        if rule not in exercised:
            mutants.append({"rule": rule, "status": "NOT_EXERCISED"})
            continue
        mb = run_battery(fixtures, disabled=frozenset({rule}))
        greened = [r["fixture"] for r in mb["rows"] if r["expected"] == "violation" and r["expected_code"] == rule and r["verdict"] == "conformant"]
        detected = [r["fixture"] for r in mb["rows"] if not r["ok"]]
        mutants.append({"rule": rule, "status": "killed" if detected else "SURVIVED", "fixtures_gone_green": greened, "detected_by": detected})
        if not detected:
            survived.append(rule)
    res["mutation_battery"] = {"mutants": mutants, "survived": survived, "not_exercised": [m["rule"] for m in mutants if m["status"] == "NOT_EXERCISED"]}
    assert_("mutation battery: every exercised rule is detected by ≥ 1 fixture", not survived, survived=survived)
    assert_("mutation battery: every rule of both tables is exercised by a fixture", not res["mutation_battery"]["not_exercised"], not_exercised=res["mutation_battery"]["not_exercised"])
    # 4 determinism: classify twice → identical
    r1 = [classify_file(p, gschema=gs, rschema=rs) for p in fixtures]
    r2 = [classify_file(p, gschema=gs, rschema=rs) for p in fixtures]
    assert_("classification is deterministic (two runs identical)", canonical(r1) == canonical(r2))
    # 5 digest: rebuilding the digest of a conformant graph reproduces the declared one
    cg = [p for p in fixtures if p.name.startswith("conformant-") and classify_file(p, gschema=gs, rschema=rs)["kind"] == "graph"]
    okd = all(json.loads(p.read_text())["manifest"]["graph_digest"] == graph_digest(json.loads(p.read_text())) for p in cg)
    assert_("graph_digest of every conformant graph fixture reproduces", okd and cg, n=len(cg))
    # 6 negative control of the selftest: a wrong expectation is reported red
    if cg:
        tmp = Path(__file__).resolve().parents[2] / "receipts" / "graph" / ".selftest-negctl-violation-EDGE_WITHOUT_PROVENANCE.json"
        try:
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(cg[0].read_text(encoding="utf-8"), encoding="utf-8")
            nb = run_battery([tmp])
            assert_("selftest negative control: a conformant graph labelled as a violation is reported (red)", nb["false_negatives"] == 1)
        finally:
            if tmp.exists():
                tmp.unlink()
    res["verdict"] = "PASS" if not failed else "FAIL"
    res["failed"] = failed
    res["contract_files"] = {str(p.relative_to(ROOT)): sha256_text(p.read_text(encoding="utf-8")) for p in (GRAPH_SCHEMA_PATH, RECEIPT_SCHEMA_PATH, CONTRACT_DIR / "relationship-graph.v1.md") if p.exists()}
    res["ratification"] = {"architecture_owner": "PENDING", "kc2_research_method_owner": "PENDING", "independent_blind_review": "NOT_RUN — the fixture labels are in the file names; a blind reviewer runs `schema_check.py` on renamed copies and compares (not_measured here, never pass)"}
    res["arcanada2_component_improved"] = "program of record contracts/ + receipts/ discipline (DEC-AUP-0008); pilot consumer Muneral (Arcanada-one/muneral) — the existing NestJS/Prisma service is described, not rewritten"
    res["host"] = {"name": "arcana-devs", "python": sys.version.split()[0]}
    res["fixtures"] = {p.name: sha256_text(p.read_text(encoding="utf-8")) for p in fixtures}
    if receipt_out:
        receipt_out.parent.mkdir(parents=True, exist_ok=True)
        receipt_out.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"receipt: {receipt_out}")
    print(f"SELFTEST {res['verdict']}: {len(res['checks']) - len(failed)}/{len(res['checks'])} checks, {b['n']} fixtures, mutants killed {sum(1 for m in mutants if m['status'] == 'killed')}/{len([m for m in mutants if m['status'] != 'NOT_EXERCISED'])}")
    return 0 if not failed else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", help="graph or receipt JSON files to classify")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--receipt", type=Path, help="with --selftest: write the ReadinessReceipt/v1 here")
    ap.add_argument("--json", action="store_true", help="print one JSON object per file")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest(a.receipt)
    if not a.files:
        ap.error("give files or --selftest")
    rc = 0
    for f in a.files:
        r = classify_file(Path(f))
        if a.json:
            print(canonical(r))
        else:
            print(f"{r['verdict'].upper():10} {r['kind']:8} {f}" + (f"  {', '.join(r['codes'])}" if r["codes"] else ""))
        if r["verdict"] != "conformant":
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())

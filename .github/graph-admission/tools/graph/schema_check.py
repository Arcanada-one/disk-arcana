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
from pathlib import Path

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
    entities = []
    boundary_inferred = []
    for section, entries in (("deterministic_core", core), ("inferred_tail", tail)):
        for e in entries:
            if not isinstance(e, dict) or "entity" not in e:
                c.add("IMPACT_ENTRY_WITHOUT_PROVENANCE", f"{section}: entry without entity"); continue
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
    # verifiers
    vers = doc.get("verifiers") if isinstance(doc.get("verifiers"), list) else []
    vspec = F["verifier"]
    ver_ids = set()
    canary_entities = set()
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
        if v.get("kind") == "canary":
            canary_entities.update(v.get("entities") or [])
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
    for ent in entities + changed_nodes:
        if ent not in verdict_of:
            c.add("ENTITY_WITHOUT_VERDICT", ent)
    # admission
    adm = sub("admission")
    for f in F["admission"]["required"]:
        if f not in adm:
            c.add("RECEIPT_MISSING_FIELD", f"admission.{f}")
    av = adm.get("verdict")
    # an inferred/observed edge across a service boundary never alone waives the canary: a claim of `verified`
    # or an admission needs a canary listing the entity or a valid exemption; an honest not_measured + paused_safe/refused is conformant
    for ent in boundary_inferred:
        if ent not in canary_entities and ent not in valid_exempt and (verdict_of.get(ent) == "verified" or av in ("admitted", "admitted_with_exemptions")):
            c.add("INFERRED_BOUNDARY_WITHOUT_CANARY", f"{ent}: verdict={verdict_of.get(ent)} admission={av}")
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
                     "ADMISSION_CONTRADICTS_VERDICTS", "ADMISSION_VERDICT_INVALID")


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

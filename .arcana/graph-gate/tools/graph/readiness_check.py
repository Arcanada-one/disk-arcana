#!/usr/bin/env python3
"""A2-289 — validator for `ReadinessReceipt/v1` documents.

The rules are the `rules` table of `contracts/readiness-receipt-v1.schema.json`; this file is their
executable form, in the shape `schema_check.py` already established: a document is `conformant`
(0 violations) or `violation` (≥ 1 code), and `not_measured` never appears as a document verdict —
the validator either reads the document or refuses with `UNREADABLE`.

WHY IT EXISTS. A2-278 could not measure the A2-P4 negative control «remove `contractDigest` from the
receipt → admission refuses», because nothing refused: there was no schema for `ReadinessReceipt/v1`
anywhere in the program, and Muneral's evidence route records a claim about any digest by design. The
receipt was a label. Measured over the 303 documents that carried it, exactly one field — `schema` —
was common to all of them.

So the required core is thin and the rule that matters is CONDITIONAL: a receipt that asserts it
verified a contract binding must say WHICH contract. That is decidable from the bytes alone. The
A2-278 negative receipt still claims `contract.verified_against_live_endpoint: true` with its
`contractDigest` cut out — it says it checked a contract and will not say which, and no network,
no Muneral and no credential are needed to call that what it is.

`--selftest` runs the fixture battery under `contracts/readiness-receipt-fixtures/` (file name =
expected label: `conformant-*` / `violation-<CODE>-*`), the mutation battery (every rule disabled in
turn must turn ≥ 1 violation fixture green, otherwise the rule is untested and the selftest FAILS)
and a negative control of the selftest itself (a wrong expectation is reported red).

stdlib only — it travels inside the CI gate bundle, where there is no network and no dependency.
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
SCHEMA_PATH = ROOT / "contracts" / "readiness-receipt-v1.schema.json"
FIXTURES_DIR = ROOT / "contracts" / "readiness-receipt-fixtures"
VERSION = "1.0.0"

SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# ISO-8601 UTC, EXTENDED (2026-09-24T18:30:35.941Z) and BASIC (20260924T183035Z). The basic form is
# not a typo to be caught: 13 receipts in the corpus use it, it is the same standard, and a rule that
# calls a valid instant invalid teaches authors to distrust the validator.
ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?|\d{8}T\d{6})(\.\d+)?Z$")

ALL_RULES = (
    "READINESS_SCHEMA_MISMATCH",
    "READINESS_WITHOUT_TIMESTAMP",
    "READINESS_TIMESTAMP_INVALID",
    "READINESS_WITHOUT_PRODUCER",
    "READINESS_CONTRACT_BINDING_WITHOUT_DIGEST",
    "READINESS_CONTRACT_DIGEST_FORM",
    "READINESS_CONTRACT_DIGEST_MISMATCH",
    "READINESS_CLAIM_WITHOUT_VERDICT",
    "READINESS_VERDICT_NOT_TRIVALUED",
    "READINESS_NOT_MEASURED_WITHOUT_REASON",
    "UNREADABLE",
)

# Two-valued tokens. A JSON boolean is the other half of this rule and is matched by type, not here.
TWO_VALUED = {"yes", "no"}

# The one rule no fixture FILE can carry: it fires only when the caller supplies the work item's own
# digest, so there is nothing to put in a file. It is exercised by its own pair of selftest
# assertions instead — fires under a wrong expectation, silent under the right one — and named here
# so that "every rule is exercised by a fixture" stays an assertion rather than becoming a lie.
ARG_DRIVEN_RULES = frozenset({"READINESS_CONTRACT_DIGEST_MISMATCH"})


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_schema(path: Path | None = None) -> dict:
    return json.loads((path or SCHEMA_PATH).read_text(encoding="utf-8"))


def parse_iso(s) -> bool:
    return isinstance(s, str) and bool(ISO_RE.match(s))


class Ctx:
    def __init__(self, doc, schema, disabled):
        self.doc, self.schema, self.disabled = doc, schema, disabled
        self.findings: list[dict] = []
        self.notes: list[str] = []

    def add(self, code, detail=""):
        if code not in self.disabled:
            self.findings.append({"code": code, "detail": detail})


def contract_digest_of(doc: dict, F: dict):
    """The digest the receipt declares, wherever it declares it: top level or inside `contract`."""
    for k in F["contract_digest_any_of"]:
        if k in doc:
            return k, doc[k]
    c = doc.get("contract")
    if isinstance(c, dict):
        for k in F["contract_digest_any_of"]:
            if k in c:
                return f"contract.{k}", c[k]
    return None, None


def asserts_contract_binding(doc: dict, F: dict) -> str | None:
    """Does this receipt CLAIM it verified a binding to a contract?

    Deliberately narrow, and measured rather than guessed: of the 12 documents in the corpus that
    carry a `contract` key, 5 are ARAS run receipts describing the contract a run executed under
    (`digest_preimage`, `verified_against_live_endpoint`) and the rest describe a contract FILE
    (`path`, `sha256`, `rules`) and claim no binding at all. Only the first kind owes a digest.
    """
    c = doc.get("contract")
    if not isinstance(c, dict):
        return None
    for marker in ("digest_preimage", "verified_against_live_endpoint"):
        if marker in c:
            return marker
    return None


def normalise_verdict(v, tables: dict) -> str | None:
    """pass / fail / not_measured, or None when the token is simply not in the tables.

    None is NOT a violation. A domain vocabulary this validator has never heard of is unmapped, not
    two-valued; saying otherwise would make every receipt with a richer vocabulary red for being
    more precise than the tables.
    """
    if isinstance(v, bool):
        return "pass" if v else "fail"
    if not isinstance(v, str):
        return None
    t = v.strip().lower()
    for bucket, tokens in tables.items():
        if t in tokens:
            return bucket
    return None


def check(doc, schema=None, disabled=frozenset(), expect_contract_digest: str | None = None) -> dict:
    schema = schema or load_schema()
    if not isinstance(doc, dict):
        # `disabled` is honoured here too, and not as a formality: the mutation battery kills a rule
        # by disabling it, and a refusal that ignores `disabled` is a rule no mutant can reach — it
        # would be reported killed while being, in fact, untested.
        if "UNREADABLE" in disabled:
            return {"verdict": "conformant", "codes": [], "notes": [], "findings": []}
        return {"verdict": "violation", "codes": ["UNREADABLE"], "notes": [],
                "findings": [{"code": "UNREADABLE", "detail": "document is not a JSON object"}]}
    F = schema["fields"]
    c = Ctx(doc, schema, disabled)

    if doc.get("schema") != schema["document_schema_name"]:
        c.add("READINESS_SCHEMA_MISMATCH", f"schema={doc.get('schema')!r}")

    stamps = [k for k in F["timestamp_any_of"] if k in doc]
    if not stamps:
        c.add("READINESS_WITHOUT_TIMESTAMP", f"none of {', '.join(F['timestamp_any_of'])}")
    for k in stamps:
        if not parse_iso(doc[k]):
            c.add("READINESS_TIMESTAMP_INVALID", f"{k}={str(doc[k])[:60]!r}")

    if not any(k in doc for k in F["producer_any_of"]):
        c.add("READINESS_WITHOUT_PRODUCER", f"none of {', '.join(F['producer_any_of'])}")

    # ---- the A2-P4 conditional rule
    marker = asserts_contract_binding(doc, F)
    where, digest = contract_digest_of(doc, F)
    if marker and where is None:
        c.add("READINESS_CONTRACT_BINDING_WITHOUT_DIGEST",
              f"`contract.{marker}` asserts a verified contract binding, and none of "
              f"{', '.join(F['contract_digest_any_of'])} names the contract it was bound to")
    if where is not None and not (isinstance(digest, str) and SHA_RE.match(digest)):
        c.add("READINESS_CONTRACT_DIGEST_FORM", f"{where}={str(digest)[:80]!r}")
    if expect_contract_digest:
        if where is None:
            c.add("READINESS_CONTRACT_DIGEST_MISMATCH",
                  f"the work item names {expect_contract_digest[:23]}… and the receipt names no contract at all")
        elif digest != expect_contract_digest:
            c.add("READINESS_CONTRACT_DIGEST_MISMATCH",
                  f"work item {expect_contract_digest[:23]}… vs receipt {str(digest)[:23]}…")

    # ---- claims
    tables = F["claims"]["verdict_trivalued"]
    reasons = F["claims"]["reason_any_of"]
    claims = doc.get("claims")
    if isinstance(claims, list):
        for i, it in enumerate(claims):
            if not isinstance(it, dict):
                continue
            label = str(it.get("id") or it.get("claim") or i)[:60]
            if "verdict" not in it:
                c.add("READINESS_CLAIM_WITHOUT_VERDICT", f"claims[{i}] {label}")
                continue
            v = it["verdict"]
            if isinstance(v, bool) or (isinstance(v, str) and v.strip().lower() in TWO_VALUED):
                c.add("READINESS_VERDICT_NOT_TRIVALUED",
                      f"claims[{i}] {label}: verdict={v!r} is two-valued; `not_measured` cannot be said with it")
                continue
            bucket = normalise_verdict(v, tables)
            if bucket is None:
                c.notes.append(f"claims[{i}] {label}: verdict {str(v)[:40]!r} is not in the tri-valued "
                               f"tables — unmapped, not a violation")
            elif bucket == "not_measured" and not any(k in it for k in reasons):
                c.add("READINESS_NOT_MEASURED_WITHOUT_REASON",
                      f"claims[{i}] {label}: none of {', '.join(reasons)}")

    codes = sorted({f["code"] for f in c.findings})
    return {"verdict": "conformant" if not c.findings else "violation",
            "codes": codes, "findings": c.findings, "notes": c.notes}


def check_file(path: Path, **kw) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"file": str(path), "verdict": "violation", "codes": ["UNREADABLE"], "notes": [],
                "findings": [{"code": "UNREADABLE", "detail": str(e)[:200]}]}
    r = check(doc, **kw)
    r["file"] = str(path)
    return r


def is_readiness_receipt(doc) -> bool:
    return isinstance(doc, dict) and doc.get("schema") == "ReadinessReceipt/v1"


# ------------------------------------------------------------------------- pull-request body
FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.S)


def receipts_from_body(body: str) -> list[dict]:
    """Every fenced ```json block in a pull-request body that IS a ReadinessReceipt/v1.

    The same extraction `ci_gate.receipts_from_body` does for ChangeAdmissionReceipt/v1 — the gate
    already receives the body (`--pr-body-file`), it simply threw these blocks away.
    """
    out = []
    for m in FENCE_RE.finditer(body or ""):
        try:
            doc = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        if is_readiness_receipt(doc):
            out.append(doc)
    return out


# -------------------------------------------------------------------------------- selftest
def expected_label(name: str):
    if name.startswith("conformant-"):
        return "conformant", None
    m = re.match(r"^violation-(\d+-)?([A-Z_]+)", name)
    if m:
        return "violation", m.group(2)
    return None, None


def run_battery(fixtures: list[Path], disabled=frozenset(), schema=None) -> dict:
    schema = schema or load_schema()
    rows, fn, fp = [], 0, 0
    for p in sorted(fixtures):
        label, code = expected_label(p.name)
        r = check_file(p, schema=schema, disabled=disabled)
        if label == "conformant":
            ok = r["verdict"] == "conformant"
            if not ok:
                fp += 1
        else:
            ok = r["verdict"] == "violation" and code in r["codes"]
            if not ok:
                fn += 1
        rows.append({"fixture": p.name, "expected": label, "expected_code": code,
                     "verdict": r["verdict"], "codes": r["codes"], "ok": ok})
    return {"rows": rows, "false_negatives": fn, "false_positives": fp, "n": len(rows)}


def selftest(receipt_out: Path | None) -> int:
    schema = load_schema()
    fixtures = sorted(FIXTURES_DIR.glob("*.json"))
    res = {"schema": "ReadinessReceipt/v1", "portion_id": "A2-289",
           "tool": "tools/graph/readiness_check.py", "tool_version": VERSION,
           "captured_at_utc": now_iso(), "checks": []}
    failed = []

    def assert_(name, cond, **kw):
        res["checks"].append({"name": name, "ok": bool(cond), **kw})
        if not cond:
            failed.append(name)
        print(("PASS " if cond else "FAIL ") + name + (f"  {kw}" if kw and not cond else ""))

    assert_("schema rule table == validator registry", set(schema["rules"]) == set(ALL_RULES),
            symmetric_difference=sorted(set(schema["rules"]) ^ set(ALL_RULES)))
    assert_("fixture count ≥ 12", len(fixtures) >= 12, n=len(fixtures))
    labels = [expected_label(p.name) for p in fixtures]
    assert_("every fixture is labelled conformant / violation-<CODE>", all(l[0] for l in labels))
    b = run_battery(fixtures, schema=schema)
    res["fixture_battery"] = b
    assert_("fixture battery: 0 false negatives", b["false_negatives"] == 0,
            rows=[r for r in b["rows"] if not r["ok"]])
    assert_("fixture battery: 0 false positives", b["false_positives"] == 0,
            rows=[r for r in b["rows"] if not r["ok"]])
    assert_("the A2-P4 negative control is a fixture",
            any(l[1] == "READINESS_CONTRACT_BINDING_WITHOUT_DIGEST" for l in labels))
    assert_("a real ARAS run receipt is a conformant fixture (positive control)",
            any(p.name.startswith("conformant-aras-run") for p in fixtures))

    # mutation battery: disable each rule in turn → ≥ 1 violation fixture must go green
    exercised = {c for (l, c) in labels if l == "violation"} | ARG_DRIVEN_RULES
    mutants, survived = [], []
    for rule in ALL_RULES:
        if rule in ARG_DRIVEN_RULES:
            mutants.append({"rule": rule, "status": "exercised_by_argument",
                            "detected_by": ["selftest assertion pair (wrong expectation / right expectation)"]})
            continue
        if rule not in exercised:
            mutants.append({"rule": rule, "status": "NOT_EXERCISED"})
            continue
        mb = run_battery(fixtures, disabled=frozenset({rule}), schema=schema)
        greened = [r["fixture"] for r in mb["rows"]
                   if r["expected"] == "violation" and r["expected_code"] == rule and r["verdict"] == "conformant"]
        detected = [r["fixture"] for r in mb["rows"] if not r["ok"]]
        mutants.append({"rule": rule, "status": "killed" if detected else "SURVIVED",
                        "fixtures_gone_green": greened, "detected_by": detected})
        if not detected:
            survived.append(rule)
    res["mutation_battery"] = {"mutants": mutants, "survived": survived,
                               "not_exercised": [m["rule"] for m in mutants if m["status"] == "NOT_EXERCISED"]}
    assert_("mutation battery: every exercised rule is detected by ≥ 1 fixture", not survived, survived=survived)
    assert_("mutation battery: every rule of the table is exercised by a fixture",
            not res["mutation_battery"]["not_exercised"],
            not_exercised=res["mutation_battery"]["not_exercised"])

    # the one rule no fixture file can carry: it needs an argument
    conf = [p for p in fixtures if p.name.startswith("conformant-")]
    mm = [check_file(p, schema=schema, expect_contract_digest="sha256:" + "0" * 64) for p in conf]
    assert_("READINESS_CONTRACT_DIGEST_MISMATCH fires on every conformant fixture under a wrong expectation",
            all("READINESS_CONTRACT_DIGEST_MISMATCH" in r["codes"] for r in mm))
    aras = [p for p in conf if p.name.startswith("conformant-aras-run")]
    if aras:
        d = json.loads(aras[0].read_text())["contractDigest"]
        r_ok = check_file(aras[0], schema=schema, expect_contract_digest=d)
        assert_("…and does NOT fire when the expectation matches (control of the control)",
                r_ok["verdict"] == "conformant", codes=r_ok["codes"])

    r1 = [check_file(p, schema=schema) for p in fixtures]
    r2 = [check_file(p, schema=schema) for p in fixtures]
    assert_("classification is deterministic (two runs identical)", canonical(r1) == canonical(r2))

    # negative control of the selftest itself: a wrong expectation must be reported red
    if conf:
        tmp = FIXTURES_DIR / ".selftest-negctl-violation-READINESS_WITHOUT_PRODUCER.json"
        try:
            tmp.write_text(conf[0].read_text(encoding="utf-8"), encoding="utf-8")
            nb = run_battery([tmp], schema=schema)
            assert_("selftest negative control: a conformant receipt labelled as a violation is reported (red)",
                    nb["false_negatives"] == 1)
        finally:
            if tmp.exists():
                tmp.unlink()

    res["verdict"] = "PASS" if not failed else "FAIL"
    res["failed"] = failed
    res["contract_files"] = {str(SCHEMA_PATH.relative_to(ROOT)): sha256_text(SCHEMA_PATH.read_text(encoding="utf-8"))}
    res["fixtures"] = {p.name: sha256_text(p.read_text(encoding="utf-8")) for p in fixtures}
    res["host"] = {"name": "arcana-devs", "python": sys.version.split()[0]}
    if receipt_out:
        receipt_out.parent.mkdir(parents=True, exist_ok=True)
        receipt_out.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"receipt: {receipt_out}")
    killed = sum(1 for m in mutants if m["status"] == "killed")
    print(f"SELFTEST {res['verdict']}: {len(res['checks']) - len(failed)}/{len(res['checks'])} checks, "
          f"{b['n']} fixtures, mutants killed {killed}/{len([m for m in mutants if m['status'] != 'NOT_EXERCISED'])}")
    return 0 if not failed else 1


def cmd_corpus(a) -> int:
    """Classify every ReadinessReceipt/v1 under the given roots. A measurement, not a gate."""
    schema = load_schema()
    rows, n = [], 0
    for root in a.corpus:
        for p in sorted(Path(root).rglob("*.json")):
            if ".git/" in str(p):
                continue
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not is_readiness_receipt(doc):
                continue
            n += 1
            r = check(doc, schema=schema)
            if r["verdict"] != "conformant":
                rows.append({"file": str(p), "codes": r["codes"]})
    print(f"corpus: {n} ReadinessReceipt/v1 documents, {n - len(rows)} conformant, {len(rows)} with violations")
    by_code: dict[str, int] = {}
    for r in rows:
        for c in r["codes"]:
            by_code[c] = by_code.get(c, 0) + 1
    for c, k in sorted(by_code.items(), key=lambda kv: -kv[1]):
        print(f"  {k:4d}  {c}")
    if a.json:
        print(json.dumps({"scanned": n, "violations": rows, "by_code": by_code}, indent=1))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", help="ReadinessReceipt/v1 JSON files to classify")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--receipt", type=Path, help="with --selftest: write the ReadinessReceipt/v1 here")
    ap.add_argument("--corpus", action="append", help="classify every ReadinessReceipt/v1 under this root")
    ap.add_argument("--pr-body-file", help="classify every ReadinessReceipt/v1 fenced in a pull-request body")
    ap.add_argument("--expect-contract-digest", help="the contract digest the WORK ITEM carries — the gate "
                                                     "supplies it; without it the binding is not_measured, never a pass")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest(a.receipt)
    if a.corpus:
        return cmd_corpus(a)
    schema = load_schema()
    results = []
    if a.pr_body_file:
        body = Path(a.pr_body_file).read_text(errors="replace")
        for i, doc in enumerate(receipts_from_body(body)):
            r = check(doc, schema=schema, expect_contract_digest=a.expect_contract_digest)
            r["file"] = f"<pr-body block {i}>"
            results.append(r)
        if not results:
            print("no ReadinessReceipt/v1 block in the pull-request body")
    for f in a.files:
        results.append(check_file(Path(f), schema=schema, expect_contract_digest=a.expect_contract_digest))
    if not results and not a.pr_body_file:
        ap.error("give files, --pr-body-file, --corpus or --selftest")
    rc = 0
    for r in results:
        if a.json:
            print(canonical(r))
        else:
            print(f"{r['verdict'].upper():11} {r['file']}" + (f"  {', '.join(r['codes'])}" if r["codes"] else ""))
            for note in r.get("notes") or []:
                print(f"            note: {note}")
        if r["verdict"] != "conformant":
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())

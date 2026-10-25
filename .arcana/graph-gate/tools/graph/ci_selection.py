#!/usr/bin/env python3
"""Derive a CI task-selection input from the canonical paired Git graph.

This executes no verifier and issues no admission or cached test verdict. The
receiving runner must map every selected entity/obligation to an actual lane;
an unmapped obligation must select its complete suite or refuse, never disappear.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import impact
import impact_pair


def selection(repo_path, base, head):
    out = {"schema": "GraphCISelection/v1", "base": base, "head": head,
           "mode": "full", "reason": "exact clean Git inputs required",
           "entities": [], "mandatory_by_entity": {}, "impact": None,
           "measurement": "selection only; no verifier executed or result reused",
           "admission": "not_issued", "unmapped_obligation_policy": "full_or_refuse"}
    try:
        if not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{40}", v)
                   and v != "0" * 40 for v in (base, head)):
            raise ValueError("both exact nonzero Git commit IDs are required")
        repo = impact.Repo(Path(repo_path))
        if repo.head() != head or repo.dirty():
            raise ValueError("actual checkout must equal requested head and be clean")
        before, after = impact_pair.index_at(repo, base), impact_pair.index_at(repo, head)
        q = impact_pair.query(before, after, repo.diff_files(base, head), repo=repo,
                              base=base, head=head, tree_commit=head, tree_dirty=False,
                              max_depth=None, edge_types=None)
        required = impact_pair.mandatory_by_entity(before, after, q)
        entities = []
        for eid in sorted(set(q["revision_selection"]["base"]) | set(q["revision_selection"]["head"])):
            node = after.nodes.get(eid) or before.nodes[eid]
            entities.append({"id": eid, "type": node["type"], "path": node.get("path"),
                             "revisions": [r for r in ("base", "head")
                                           if eid in q["revision_selection"][r]]})
        out.update(impact=q, entities=entities, mandatory_by_entity=required,
                   matrix_sha256=hashlib.sha256((Path(__file__).resolve().parents[2] /
                       "contracts/graph-verified-change/verifier-matrix.v1.json").read_bytes()).hexdigest())
        regular = True
        for f in q["change_set"]["files"]:
            # Extension-based graph kinds do not authorize an executable-mode
            # or symlink replacement to become a document-only CI exclusion.
            for revision in (base, head):
                tree = impact.git(["ls-tree", revision, "--", repo.prefix + f["path"]], repo.top)
                if tree and not tree.startswith("100644 blob "):
                    regular = False
        if q["events"] or q["revision_selection"]["unmeasured_head_files"]:
            out["reason"] = "canonical graph diagnostics require complete fallback or refusal"
        elif not regular:
            out["reason"] = "non-regular or executable-mode changed input requires full fallback"
        elif q["impact_set"]["global_fallback"]["triggered"]:
            out["reason"] = q["impact_set"]["global_fallback"]["reason"]
        else:
            out.update(mode="affected", reason="complete base/head graph traversal and mandatory matrix")
            # This is a graph-derived classification, not a path glob or a green
            # empty-impact receipt. Schema/contract/security lanes still apply.
            out["records_only"] = (all(f["kind"] in impact.DOC_KINDS
                                      for f in q["change_set"]["files"])
                                   and all(e["type"] in {"document", "receipt", "work_item"}
                                           for e in entities))
    except (impact.Refusal, ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        out["reason"] = str(exc)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    Path(a.out).write_text(json.dumps(selection(a.repo, a.base, a.head), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

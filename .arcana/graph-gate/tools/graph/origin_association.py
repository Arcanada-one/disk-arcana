"""Authenticate an origin association without rewriting either measured graph.

This changes no verification result: callers still rederive all selections and
mandatory obligations from current Git. The issuer binds exact raw receipt bytes,
both Git trees and full historical graphs to one current repository identity.
"""
import copy
import json
import re

import schema_check
import sshsig

NAMESPACE = "graph-origin-association"


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("origin association has duplicate JSON keys")
        out[key] = value
    return out


def _same_json(left, right):
    """Compare JSON values without Python bool/int or int/float coercion."""
    def canonical(value):
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    return canonical(left) == canonical(right)


def validate(raw: bytes, signature: str, trusted_base_key: str, receipt_digest: str,
             receipt: dict, current: dict, trees: dict) -> dict:
    """Return an auditable equality proof; refuse any unbound or semantic drift."""
    ok, reason, _ = sshsig.verify_detached(raw, signature, trusted_base_key, NAMESPACE)
    if not ok:
        raise ValueError("origin association signature refused: " + reason)
    claim = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    fields = {"schema", "receipt_digest", "target_source_repo", "git_trees", "original_graphs"}
    if not isinstance(claim, dict) or set(claim) != fields or claim["schema"] != "GraphOriginAssociation/v1":
        raise ValueError("origin association schema/fields invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_digest or "") or claim["receipt_digest"] != receipt_digest:
        raise ValueError("origin association raw receipt digest mismatch")
    if not _same_json(claim["git_trees"], trees) or set(trees) != {"base", "head"}:
        raise ValueError("origin association Git tree mismatch")
    target = claim["target_source_repo"]
    if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", target):
        raise ValueError("origin association target repository invalid")
    old = claim["original_graphs"]
    if not isinstance(old, dict) or set(old) != {"graph", "head_graph"} or set(current) != set(old):
        raise ValueError("origin association requires both complete graphs")
    proof = {}
    for role in ("graph", "head_graph"):
        measured, rebuilt = old[role], current[role]
        for graph in (measured, rebuilt):
            if not isinstance(graph, dict) or not isinstance(graph.get("manifest"), dict):
                raise ValueError("origin association graph malformed")
            if graph["manifest"].get("graph_digest") != schema_check.graph_digest(graph):
                raise ValueError("origin association graph digest invalid")
        binding = receipt.get(role) or {}
        if any(not _same_json(measured["manifest"].get(k), binding.get(k))
               for k in ("source_commit", "graph_digest", "builder_version")):
            raise ValueError("origin association historical graph not bound to receipt")
        if measured["manifest"].get("source_repo") != (receipt.get("repo") or {}).get("name"):
            raise ValueError("origin association measured repository mismatch")
        if rebuilt["manifest"].get("source_repo") != target:
            raise ValueError("origin association current repository mismatch")
        bodies = []
        for graph in (measured, rebuilt):
            body = copy.deepcopy(graph)
            # These remain recorded above/below; no input object or digest is relabelled.
            for key in ("source_repo", "graph_digest", "built_at_utc"):
                body["manifest"].pop(key, None)
            bodies.append(body)
        if not _same_json(bodies[0], bodies[1]):
            raise ValueError("origin association graph body/provenance drift: " + role)
        proof[role] = {"measured_graph_digest": measured["manifest"]["graph_digest"],
                       "current_graph_digest": rebuilt["manifest"]["graph_digest"],
                       "source_commit": rebuilt["manifest"]["source_commit"]}
    return {"schema": "ValidatedGraphOriginAssociation/v1", "receipt_digest": receipt_digest,
            "target_source_repo": target, "git_trees": trees, "graphs": proof}

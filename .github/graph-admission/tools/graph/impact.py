#!/usr/bin/env python3
"""AUP-GRAPH-003 `impact0` — impact query over a RelationshipGraph/v1: change set → affected entities with provenance,
refusals on freshness, global fallback, and the EMPTY_IMPACT_REQUIRES_EXPLANATION event (DEC-AUP-0008).

    impact.py --graph <graph.json> --repo <repo> (--diff <base>..<head> | --worktree | --files p[:S] ...)
              [--max-depth N] [--edge-types t1,t2] [--json] [--out <ImpactQuery.json>] [--emit-receipt <CAR.json>]
    impact.py --selftest [--receipt <ReadinessReceipt.json>] [--pilot <repo> --pilot-graph <graph.json>
              --replay-commits N --replay-out <dir>]

Semantics (the graph SELECTS verification, it never replaces it — consilium 2026-09-05, DEC-AUP-0008):
  seeds        every node whose `path` is a changed file (the code_unit AND the contracts / routes / data models
               declared in it); `<dir>/package.json` or `<dir>/tsconfig*.json` of a deployable seeds the deployable
               and opens its containment (scoped fallback: every unit shipped inside it is affected)
  traversal    reverse edges into an affected node (its dependents: importers, callers, consumers, tests, receipts,
               documents, work items) + forward "declared-by" hops (provides_route, implements_contract, maps_model
               to a node declared in the same file, deploys_to) — an entity whose content is derived from an
               affected unit is affected too. deploys_to is never expanded backwards except from a seeded deployable.
  provenance   best path per entity = fewest inferred/observed hops, then shortest; entities whose best path is
               fully deterministic form `deterministic_core`, every other one `inferred_tail` (never merged)
  refusals     STALE_GRAPH (manifest.dirty, source_commit ≠ HEAD in --worktree / ≠ base in --diff, dirty tree in
               --diff, a tracked node whose content hash no longer matches the tree), UNKNOWN_NODE (a modified or
               deleted code file the graph has no node for), GRAPH_INVALID (schema violations), EMPTY_CHANGE_SET
  fallback     lockfile / root package.json / root tsconfig / nx / turbo / pnpm-workspace / env schema changed ⇒
               every node is affected (global_fallback.triggered + reason)
  event        EMPTY_IMPACT_REQUIRES_EXPLANATION — non-doc change with an empty impact set: exit 3, a generated
               explanation draft with graph_metadata (leaf unit / new file / uncovered language); never an approval

Exit codes: 0 impact computed · 2 refusal · 3 impact computed but EMPTY_IMPACT_REQUIRES_EXPLANATION raised.
Output `ImpactQuery/v1`: its graph / tree / staleness / change_set / impact_set blocks are exactly the
ChangeAdmissionReceipt/v1 blocks (GRAPH-006 copies them); `--emit-receipt` writes a receipt skeleton with every
verdict = not_measured and admission = paused_safe (verifiers are GRAPH-005's job).
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import schema_check  # noqa: E402
import build_graph  # noqa: E402

VERSION = "1.0.0"
TOOL = "tools/graph/impact.py"
QUERY_SCHEMA = "ImpactQuery/v1"
FIXTURE_DIR = ROOT / "contracts" / "graph-verified-change" / "fixtures"
TS_MINI = FIXTURE_DIR / "ts-mini"
IMPACT_EXPECTED_PATH = TS_MINI / "IMPACT_EXPECTED.json"
DEFAULT_MAX_DEPTH = 3

# rules that the mutation battery disables one at a time (every one must be caught by ≥ 1 selftest expectation)
RULES = ["staleness", "dirty_graph", "hash_check", "unknown_node", "global_fallback", "scoped_fallback",
         "forward_declaration", "provenance_split", "empty_impact_event", "depth_limit", "edge_filter",
         "seed_declared_nodes", "reverse_traversal"]

LOCKFILES = {"pnpm-lock.yaml", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json", "Cargo.lock", "poetry.lock",
             "uv.lock", "bun.lockb", "bun.lock"}
GLOBAL_ROOT_FILES = {"package.json", "nx.json", "turbo.json", "pnpm-workspace.yaml", "lerna.json", ".npmrc", ".nvmrc",
                     ".env.example", ".env.schema", ".env.template", "env.schema.json"}
GLOBAL_ROOT_PREFIXES = ("tsconfig",)  # tsconfig.json, tsconfig.base.json … at the root
CODE_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"}
DOC_EXTS = {".md", ".mdx", ".rst", ".txt", ".adoc"}
CONFIG_EXTS = {".json", ".yml", ".yaml", ".toml", ".ini", ".env", ".cfg", ".conf", ".properties"}
DOC_KINDS = {"doc", "receipt"}
FALLBACK_KINDS = {"lockfile", "global_config"}
TEST_RE = re.compile(r"(^|/)(test|tests|__tests__|e2e|spec)(/|$)|\.(spec|test)\.[cm]?[jt]sx?$")
FORWARD_TYPES = {"provides_route", "implements_contract", "maps_model", "deploys_to"}
BOUNDARY_RANK = {"intra_unit": 0, "service": 1, "repo": 2}
FILE_HASH_TYPES = {"code_unit", "document", "receipt", "deployable_unit"}  # content_hash = whole file bytes (schema)
DEPLOYABLE_MANIFEST_NAMES = ("package.json", "Cargo.toml", "pyproject.toml", "setup.py", "setup.cfg")  # AUP-GRAPH-009: deployable_unit
# manifests are no longer always npm — try every builder's manifest name, first one present in the tree wins
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


# ----------------------------------------------------------------------------------------------- helpers
def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class _HashBytes(bytes):
    """Selftest sentinel: bytes whose sha256 is declared rather than computed (fixture hashes are synthetic)."""
    def __new__(cls, h: str):
        o = super().__new__(cls, b"")
        o.declared = h
        return o


def sha_bytes(b: bytes) -> str:
    if isinstance(b, _HashBytes):
        return b.declared
    return "sha256:" + hashlib.sha256(b).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(args: list[str], cwd: Path, check=True) -> str:
    return subprocess.run(["git", *args], cwd=str(cwd), check=check, capture_output=True, text=True).stdout


def dump(obj) -> bytes:
    return (json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def strip_volatile(obj):
    """Copy without wall-clock fields, for determinism comparisons."""
    if isinstance(obj, dict):
        return {k: strip_volatile(v) for k, v in obj.items() if k not in ("captured_at_utc", "checked_at_utc", "duration_s")}
    if isinstance(obj, list):
        return [strip_volatile(v) for v in obj]
    return obj


class Refusal(Exception):
    def __init__(self, code: str, reason: str, details=None):
        super().__init__(f"{code}: {reason}")
        self.code, self.reason, self.details = code, reason, details or {}


# ----------------------------------------------------------------------------------------------- repo access
class Repo:
    """Minimal read-only git access (the pilot clone is never written)."""

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.top = Path(git(["rev-parse", "--show-toplevel"], self.path).strip())
        rel = self.path.relative_to(self.top).as_posix() if self.path != self.top else ""
        self.prefix = rel + "/" if rel else ""
        self.name = build_graph.source_repo_name(self.top)

    def rev(self, r: str) -> str:
        return git(["rev-parse", f"{r}^{{commit}}"], self.top).strip()

    def head(self) -> str:
        return self.rev("HEAD")

    def dirty(self) -> bool:
        return bool(git(["status", "--porcelain", "--", "."], self.path).strip())

    def _rel(self, p: str) -> str | None:
        if self.prefix and not p.startswith(self.prefix):
            return None
        return p[len(self.prefix):]

    def diff_files(self, base: str, head: str) -> list[dict]:
        out = git(["diff", "--name-status", "-z", "--find-renames", base, head, "--", "."], self.path)
        parts = [x for x in out.split("\0")]
        files, i = [], 0
        while i < len(parts) and parts[i]:
            st = parts[i]
            if st[0] in ("R", "C"):
                old, new = parts[i + 1], parts[i + 2]
                i += 3
                ro, rn = self._rel(old), self._rel(new)
                if st[0] == "R":
                    if ro is not None:
                        files.append({"path": ro, "status": "R", "renamed_to": rn})
                    if rn is not None:
                        files.append({"path": rn, "status": "A", "renamed_from": ro})
                elif rn is not None:
                    files.append({"path": rn, "status": "A"})
                continue
            p = parts[i + 1]
            i += 2
            rp = self._rel(p)
            if rp is None:
                continue
            files.append({"path": rp, "status": {"A": "A", "M": "M", "D": "D", "T": "M", "U": "M"}.get(st[0], "M")})
        return sorted(files, key=lambda f: f["path"])

    def worktree_files(self) -> list[dict]:
        out = git(["status", "--porcelain", "-z", "--untracked-files=all", "--", "."], self.path)
        parts = out.split("\0")
        files, i = [], 0
        while i < len(parts) and parts[i]:
            code, p = parts[i][:2], parts[i][3:]
            i += 1
            if code[0] == "R" or code[1] == "R":
                old = parts[i]
                i += 1
                ro, rn = self._rel(old), self._rel(p)
                if ro is not None:
                    files.append({"path": ro, "status": "R", "renamed_to": rn})
                if rn is not None:
                    files.append({"path": rn, "status": "A", "renamed_from": ro})
                continue
            rp = self._rel(p)
            if rp is None:
                continue
            if "D" in code:
                st = "D"
            elif code == "??" or "A" in code:
                st = "A"
            else:
                st = "M"
            files.append({"path": rp, "status": st})
        return sorted(files, key=lambda f: f["path"])

    def read_worktree(self, rel: str) -> bytes | None:
        p = self.path / rel
        return p.read_bytes() if p.is_file() else None

    def read_at(self, rev: str, rels: list[str]) -> dict[str, bytes | None]:
        spec = "".join(f"{rev}:{self.prefix}{r}\n" for r in rels).encode()
        out = subprocess.run(["git", "cat-file", "--batch"], cwd=str(self.top), input=spec, check=True,
                             capture_output=True).stdout
        res, pos = {}, 0
        for r in rels:
            nl = out.index(b"\n", pos)
            header = out[pos:nl].decode()
            pos = nl + 1
            if header.endswith(" missing"):
                res[r] = None
                continue
            size = int(header.split()[2])
            res[r] = out[pos:pos + size]
            pos += size + 1
        return res


# ----------------------------------------------------------------------------------------------- graph index
class GraphIndex:
    def __init__(self, doc: dict):
        self.doc = doc
        self.manifest = doc["manifest"]
        self.nodes: dict[str, dict] = {n["id"]: n for n in doc["nodes"]}
        self.rev: dict[str, list[dict]] = {}
        self.fwd: dict[str, list[dict]] = {}
        self.by_path: dict[str, list[str]] = {}
        self.deployables: dict[str, str] = {}
        for e in doc["edges"]:
            self.rev.setdefault(e["to"], []).append(e)
            self.fwd.setdefault(e["from"], []).append(e)
        edge_key = lambda e: (e["type"], e["from"], e["to"], e["provenance"])  # noqa: E731
        for k in self.rev:
            self.rev[k].sort(key=edge_key)
        for k in self.fwd:
            self.fwd[k].sort(key=edge_key)
        for n in doc["nodes"]:
            p = n.get("path")
            if p:
                self.by_path.setdefault(p, []).append(n["id"])
                if n["type"] == "deployable_unit":
                    self.deployables[p.rstrip("/")] = n["id"]
        for k in self.by_path:
            self.by_path[k].sort()
        self.hints = {t: v.get("mandatory_verifier_hint", "") for t, v in
                      schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH)["edge_types"].items()}

    def path_nodes(self, path: str, rules: set[str]) -> list[str]:
        ids = self.by_path.get(path, [])
        if "seed_declared_nodes" not in rules:
            ids = [i for i in ids if not (i.startswith("contract:") or i.startswith("route:") or i.startswith("data_model:"))]
        return ids


def load_graph(path: Path, rules: set[str]) -> GraphIndex:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    gschema = schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH)
    findings = schema_check.check_graph(doc, gschema, disabled=frozenset({"GRAPH_DIRTY"}))
    if findings:
        codes = sorted({f["code"] for f in findings})
        raise Refusal("GRAPH_INVALID", f"graph fails RelationshipGraph/v1: {', '.join(codes)}",
                      {"codes": codes, "n": len(findings)})
    if doc["manifest"].get("dirty") is True and "dirty_graph" in rules:
        raise Refusal("STALE_GRAPH", "graph was built on a dirty working tree (manifest.dirty = true); rebuild from git objects",
                      {"manifest_dirty": True})
    return GraphIndex(doc)


# ----------------------------------------------------------------------------------------------- change set
def classify_file(path: str, idx: GraphIndex | None) -> str:
    base = os.path.basename(path)
    ext = os.path.splitext(base)[1].lower()
    is_root = "/" not in path
    if base in LOCKFILES:
        return "lockfile"
    if is_root and (base in GLOBAL_ROOT_FILES or base.startswith(GLOBAL_ROOT_PREFIXES) and ext == ".json"):
        return "global_config"
    if path.startswith("receipts/") and ext == ".json":
        return "receipt"
    if ext == ".prisma" or re.search(r"(^|/)prisma/migrations/.*\.sql$", path):
        return "data_model"
    if TEST_RE.search(path) and (ext in CODE_EXTS or ext == ".json"):
        return "test"
    if idx is not None:
        types = {idx.nodes[i]["type"] for i in idx.by_path.get(path, [])}
        if "contract" in types:
            return "contract"
        if "route" in types:
            return "route"
    if ext in DOC_EXTS or path.startswith("docs/") or "/docs/" in path:
        return "doc"
    if ext in CODE_EXTS:
        return "code"
    if ext in CONFIG_EXTS or base.startswith(".env") or base == "Dockerfile" or path.startswith(".github/"):
        return "config"
    return "other"


def parse_file_args(specs: list[str]) -> list[dict]:
    files = []
    for s in specs:
        p, _, st = s.partition(":")
        files.append({"path": p, "status": (st or "M").upper()})
    return sorted(files, key=lambda f: f["path"])


# ----------------------------------------------------------------------------------------------- staleness
def check_staleness(idx: GraphIndex, repo: Repo | None, mode: str, base: str | None, tree_commit: str,
                    tree_dirty: bool, changed_paths: set[str], rules: set[str], reader=None) -> dict:
    """Returns the staleness block; raises Refusal(STALE_GRAPH). `reader(path) -> bytes|None` overrides the tree
    read (fixtures)."""
    m = idx.manifest
    ref = base if mode == "diff" else tree_commit
    method = ["manifest.dirty must be false",
              f"manifest.source_commit == {'change_set.base' if mode == 'diff' else 'HEAD of the tree'}"]
    if mode == "diff":
        method.append("working tree must be clean (a receipt in diff mode describes committed history only)")
    if "staleness" in rules:
        if m.get("source_commit") != ref:
            raise Refusal("STALE_GRAPH", f"graph source_commit {m.get('source_commit', '?')[:12]} ≠ "
                                         f"{'base' if mode == 'diff' else 'HEAD'} {ref[:12]}; rebuild the graph at that commit",
                          {"graph_source_commit": m.get("source_commit"), "expected": ref})
        if mode == "diff" and tree_dirty:
            raise Refusal("STALE_GRAPH", "working tree is dirty in --diff mode; commit or stash before issuing a receipt",
                          {"tree_dirty": True})
    mismatched, checked = [], 0
    if "hash_check" in rules and (repo is not None or reader is not None):
        method.append("content_hash of every whole-file node (code_unit, document, receipt; deployable_unit via its "
                      "package.json) must equal the sha256 of the file bytes "
                      + ("at base (git objects)" if mode == "diff" else "in the working tree, changed files excluded")
                      + "; contract/route/data_model hashes are extractor-owned (declaration text) and not recomputed")
        def read_one(path: str) -> bytes | None:
            if reader is not None:
                return reader(path)
            if mode == "diff":
                return repo.read_at(base, [path]).get(path)
            return repo.read_worktree(path)

        def deployable_manifest(p: str) -> str:
            for name in DEPLOYABLE_MANIFEST_NAMES:
                cand = p.rstrip("/") + "/" + name
                if read_one(cand) is not None:
                    return cand
            return p.rstrip("/") + "/" + DEPLOYABLE_MANIFEST_NAMES[0]  # none present: report honestly as a mismatch below

        wanted: dict[str, list[str]] = {}
        for nid, n in idx.nodes.items():
            p = n.get("path")
            if not p or n["type"] not in FILE_HASH_TYPES:
                continue
            if n["type"] == "deployable_unit":
                p = deployable_manifest(p)
            if mode != "diff" and p in changed_paths:
                continue
            wanted.setdefault(p, []).append(nid)
        paths = sorted(wanted)
        if reader is not None:
            blobs = {p: reader(p) for p in paths}
        elif mode == "diff":
            blobs = repo.read_at(base, paths)
        else:
            blobs = {p: repo.read_worktree(p) for p in paths}
        for p in paths:
            b = blobs.get(p)
            h = sha_bytes(b) if b is not None else None
            for nid in wanted[p]:
                checked += 1
                if idx.nodes[nid]["content_hash"] != h:
                    mismatched.append({"node": nid, "graph_hash": idx.nodes[nid]["content_hash"], "tree_hash": h})
        if mismatched:
            raise Refusal("STALE_GRAPH", f"{len(mismatched)} node(s) no longer match the tree (first: {mismatched[0]['node']})",
                          {"mismatched_nodes": mismatched[:50], "checked_nodes": checked})
    return {"method": "; ".join(method), "verdict": "fresh", "mismatched_nodes": [],
            "checked_nodes": checked, "checked_at_utc": now_iso()}


# ----------------------------------------------------------------------------------------------- traversal
def max_boundary(a: str, b: str | None) -> str:
    b = b or "intra_unit"
    return a if BOUNDARY_RANK.get(a, 0) >= BOUNDARY_RANK.get(b, 0) else b


def hop_of(e: dict) -> dict:
    h = {"from": e["from"], "to": e["to"], "edge_type": e["type"], "provenance": e["provenance"]}
    for k in ("inferred_by", "observed_at_utc", "via", "boundary"):
        if k in e:
            h[k] = e[k]
    return h


def neighbours(idx: GraphIndex, node: str, edge_types: set[str] | None, rules: set[str], open_containment: set[str]):
    """Yield (edge, next_node) pairs: reverse edges (dependents) + forward declared-by hops."""
    if "reverse_traversal" in rules:
        for e in idx.rev.get(node, []):
            if edge_types is not None and e["type"] not in edge_types:
                continue
            if e["type"] == "deploys_to" and node not in open_containment:
                continue  # a deployable's whole containment is only opened by a seeded manifest (scoped fallback)
            yield e, e["from"]
    if "forward_declaration" in rules:
        src = idx.nodes[node]
        for e in idx.fwd.get(node, []):
            if e["type"] not in FORWARD_TYPES or (edge_types is not None and e["type"] not in edge_types):
                continue
            tgt = idx.nodes.get(e["to"])
            if tgt is None:
                continue
            if e["type"] in ("provides_route", "deploys_to"):
                yield e, e["to"]          # a route is declared by its provider; a unit ships inside its deployable
            elif src["type"] == "code_unit" and (tgt.get("path") == src.get("path") or (
                    not tgt.get("path") and (e["type"] == "implements_contract" or str(src.get("path", "")).endswith(".prisma")))):
                yield e, e["to"]          # contract / data model declared in the changed file (route→contract is not a declaration)


def traverse(idx: GraphIndex, seeds: set[str], max_depth: int | None, edge_types: set[str] | None, rules: set[str],
             open_containment: set[str]) -> list[dict]:
    if "depth_limit" not in rules:
        max_depth = None
    best: dict[str, tuple] = {}
    heap: list[tuple] = []
    for s in sorted(seeds):
        best[s] = (0, 0, [], "intra_unit")
        heapq.heappush(heap, (0, 0, s))
    while heap:
        nd, dep, node = heapq.heappop(heap)
        if best[node][0] != nd or best[node][1] != dep:
            continue
        if max_depth is not None and dep >= max_depth:
            continue
        for e, nxt in neighbours(idx, node, edge_types, rules, open_containment):
            if nxt in seeds or nxt == node:
                continue
            det = e["provenance"] == "deterministic" or "provenance_split" not in rules
            key = (nd + (0 if det else 1), dep + 1)
            if nxt not in best or key < best[nxt][:2]:
                best[nxt] = (key[0], key[1], best[node][2] + [hop_of(e)], max_boundary(best[node][3], e.get("boundary")))
                heapq.heappush(heap, (key[0], key[1], nxt))
    entries = []
    for nid in sorted(best):
        if nid in seeds:
            continue
        nd, dep, path, boundary = best[nid]
        entries.append({"entity": nid, "node_type": idx.nodes[nid]["type"], "depth": dep, "boundary": boundary,
                        "path": path, "verifier_hint": idx.hints.get(path[-1]["edge_type"], "")})
    return entries


# ----------------------------------------------------------------------------------------------- query
def query(idx: GraphIndex, files: list[dict], *, mode: str, base: str | None = None, head: str | None = None,
          tree_commit: str, tree_dirty: bool, repo: Repo | None = None, reader=None, max_depth: int | None = DEFAULT_MAX_DEPTH,
          edge_types: set[str] | None = None, rules: set[str] | None = None, graph_path: str | None = None) -> dict:
    rules = set(RULES) if rules is None else set(rules)
    if "edge_filter" not in rules:
        edge_types = None
    m = idx.manifest
    out = {"schema": QUERY_SCHEMA, "tool": TOOL, "version": VERSION, "captured_at_utc": now_iso(),
           "decision_ref": "DEC-AUP-0008",
           "repo": {"name": m.get("source_repo"), "path": str(repo.path) if repo else None},
           "graph": {"path": graph_path, "source_commit": m.get("source_commit"), "graph_digest": m.get("graph_digest"),
                     "builder_version": m.get("builder_version"), "built_at_utc": m.get("built_at_utc"),
                     "node_count": m.get("node_count"), "edge_count": m.get("edge_count")},
           "tree": {"commit": tree_commit, "dirty": bool(tree_dirty)},
           "refusal": None, "events": []}
    if not files:
        raise Refusal("EMPTY_CHANGE_SET", "no changed files (nothing to admit)", {})
    for f in files:
        f["kind"] = classify_file(f["path"], idx)
    changed_paths = {f["path"] for f in files}
    out["staleness"] = check_staleness(idx, repo, mode, base, tree_commit, tree_dirty, changed_paths, rules, reader)
    cs = {"mode": mode, "files": []}
    if mode == "diff":
        cs["base"], cs["head"] = base, head
    seeds: set[str] = set()
    open_containment: set[str] = set()
    unknown, uncovered, new_files = [], [], []
    fallback_files = []
    for f in files:
        entry = {"path": f["path"], "status": f["status"], "kind": f["kind"]}
        for k in ("renamed_to", "renamed_from"):
            if k in f:
                entry[k] = f[k]
        ids = idx.path_nodes(f["path"], rules)
        base_name = os.path.basename(f["path"])
        d = os.path.dirname(f["path"])
        dep_id = idx.deployables.get(d) or (f"deployable_unit:{d}" if f"deployable_unit:{d}" in idx.nodes else None)
        if d and dep_id and (base_name == "package.json" or base_name.startswith("tsconfig")) and "scoped_fallback" in rules:
            ids = sorted(set(ids) | {dep_id})
            open_containment.add(dep_id)
            entry["scoped_fallback"] = f"{f['path']} changed ⇒ every unit shipped inside {dep_id} is affected"
        if f["kind"] in FALLBACK_KINDS:
            fallback_files.append(f["path"])
        if ids:
            entry["node_id"] = next((i for i in ids if i.startswith("code_unit:")), ids[0])
            entry["node_ids"] = ids
            seeds.update(ids)
        elif f["status"] == "A":
            entry["new"] = True
            new_files.append(f["path"])
        elif f["kind"] in FALLBACK_KINDS:
            pass
        elif os.path.splitext(f["path"])[1].lower() in CODE_EXTS | {".prisma"}:
            unknown.append(f["path"])
        else:
            entry["uncovered"] = True
            uncovered.append(f["path"])
        cs["files"].append(entry)
    out["change_set"] = cs
    if unknown and "unknown_node" in rules:
        raise Refusal("UNKNOWN_NODE", f"{len(unknown)} modified/deleted code file(s) have no node in the graph: "
                                      f"{', '.join(unknown[:5])}{' …' if len(unknown) > 5 else ''}; the graph does not cover "
                                      f"what is being changed — rebuild it or fix the extractor", {"files": unknown})
    out["seeds"] = sorted(seeds)
    imp = {"method": f"reverse traversal (dependents) + forward declared-by hops (provides_route, implements_contract, "
                     f"maps_model of the same file, deploys_to); best path = fewest inferred/observed hops, then shortest; "
                     f"max_depth {max_depth if max_depth is not None else 'unlimited'}",
           "max_depth": max_depth, "edge_types": sorted(edge_types) if edge_types else "all",
           "global_fallback": {"triggered": False}, "deterministic_core": [], "inferred_tail": [], "total": 0}
    if fallback_files and "global_fallback" in rules:
        trig = fallback_files[0]
        imp["global_fallback"] = {"triggered": True, "files": fallback_files,
                                  "reason": f"{', '.join(fallback_files)} changed ⇒ every node affected (lockfile / global "
                                            f"config / env schema: safe fallback, Bazel/Nx practice)"}
        imp["method"] = "global fallback: every node of the graph is affected (depth 0, synthetic containment hop); " + imp["method"]
        for nid in sorted(idx.nodes):
            if nid in seeds:
                continue
            imp["deterministic_core"].append({"entity": nid, "node_type": idx.nodes[nid]["type"], "depth": 0,
                                              "boundary": "intra_unit",
                                              "path": [{"from": f"code_unit:{trig}", "to": nid, "edge_type": "deploys_to",
                                                        "provenance": "deterministic", "via": "global-fallback"}],
                                              "verifier_hint": idx.hints.get("deploys_to", "")})
    else:
        for e in traverse(idx, seeds, max_depth, edge_types, rules, open_containment):
            non_det = any(h["provenance"] != "deterministic" for h in e["path"])
            (imp["inferred_tail"] if non_det else imp["deterministic_core"]).append(e)
    imp["total"] = len(imp["deterministic_core"]) + len(imp["inferred_tail"])
    out["impact_set"] = imp
    out["stats"] = {"seeds": len(seeds), "deterministic_core": len(imp["deterministic_core"]),
                    "inferred_tail": len(imp["inferred_tail"]),
                    "by_depth": _count(e["depth"] for e in imp["deterministic_core"] + imp["inferred_tail"]),
                    "by_node_type": _count(e["node_type"] for e in imp["deterministic_core"] + imp["inferred_tail"]),
                    "service_boundary_entries": sum(1 for e in imp["inferred_tail"] if e["boundary"] in ("service", "repo")),
                    "uncovered_files": uncovered, "new_files": new_files, "graph_nodes": len(idx.nodes)}
    non_doc = [f for f in cs["files"] if f["kind"] not in DOC_KINDS]
    if imp["total"] == 0 and not imp["global_fallback"]["triggered"] and non_doc and "empty_impact_event" in rules:
        per_file = []
        for f in non_doc:
            if f.get("new"):
                why = "new file (status A): no consumer can exist in the graph before it is committed"
            elif f.get("uncovered"):
                why = "uncovered file kind: the builder yields no node for it (see manifest.language_coverage)"
            elif f.get("node_ids"):
                rev = sum(len([e for e in idx.rev.get(i, []) if e["type"] != "deploys_to"]) for i in f["node_ids"])
                why = f"leaf unit: {rev} reverse edge(s) other than containment" if rev == 0 else \
                    f"{rev} reverse edge(s) exist but were filtered by depth/edge-type"
            else:
                why = "no node and not a code file"
            per_file.append({"path": f["path"], "kind": f["kind"], "why": why})
        out["empty_impact_explanation"] = {
            "reason": "GENERATED by impact.py — a draft the receipt author must confirm or replace: "
                      + "; ".join(f"{p['path']}: {p['why']}" for p in per_file),
            "graph_metadata": {"extractors": m.get("extractors"), "language_coverage": m.get("language_coverage"),
                               "changed_node_known_to_graph": any(f.get("node_ids") for f in non_doc),
                               "reverse_edges_of_changed_nodes": sum(len(idx.rev.get(s, [])) for s in seeds),
                               "max_depth": max_depth, "edge_types": imp["edge_types"], "per_file": per_file}}
        out["events"].append({"code": "EMPTY_IMPACT_REQUIRES_EXPLANATION",
                              "text": "non-documentation change with an empty impact set: a prediction that must be explained "
                                      "in the receipt (empty_impact_explanation), never an approval"})
    return out


def _count(it) -> dict:
    c: dict = {}
    for x in it:
        c[str(x)] = c.get(str(x), 0) + 1
    return dict(sorted(c.items()))


def refusal_doc(idx: GraphIndex | None, r: Refusal, *, mode: str, tree_commit: str | None, tree_dirty: bool | None,
                repo: Repo | None, graph_path: str | None, files: list[dict] | None) -> dict:
    m = idx.manifest if idx else {}
    return {"schema": QUERY_SCHEMA, "tool": TOOL, "version": VERSION, "captured_at_utc": now_iso(),
            "decision_ref": "DEC-AUP-0008",
            "repo": {"name": m.get("source_repo"), "path": str(repo.path) if repo else None},
            "graph": {"path": graph_path, "source_commit": m.get("source_commit"), "graph_digest": m.get("graph_digest"),
                      "builder_version": m.get("builder_version"), "built_at_utc": m.get("built_at_utc")},
            "tree": {"commit": tree_commit, "dirty": tree_dirty},
            "staleness": {"method": "see refusal", "verdict": "stale" if r.code == "STALE_GRAPH" else "not_checked"},
            "change_set": {"mode": mode, "files": files or []},
            "refusal": {"code": r.code, "reason": r.reason, "details": r.details},
            "events": [], "impact_set": None}


# ----------------------------------------------------------------------------------------------- receipt skeleton
def receipt_skeleton(q: dict, work_item: str | None = None) -> dict:
    """ChangeAdmissionReceipt/v1 pre-filled from an ImpactQuery: every verdict not_measured, admission paused_safe."""
    if q.get("refusal"):
        raise Refusal(q["refusal"]["code"], "no receipt can be issued on a refused query: " + q["refusal"]["reason"])
    imp = q["impact_set"]
    entities = [e["entity"] for e in imp["deterministic_core"] + imp["inferred_tail"]]
    changed = [f["node_id"] for f in q["change_set"]["files"] if f.get("node_id")]
    seen, verdicts = set(), []
    for ent in entities + changed:
        if ent in seen:
            continue
        seen.add(ent)
        verdicts.append({"entity": ent, "verdict": "not_measured",
                         "reason": "impact0 selected the entity; no verifier has run yet (GRAPH-005/006)"})
    rec = {"schema": "ChangeAdmissionReceipt/v1", "receipt_id": f"car-impact-{q['captured_at_utc'].replace('-', '').replace(':', '')}",
           "captured_at_utc": q["captured_at_utc"], "host": os.uname().nodename,
           "producer": {"tool": TOOL, "version": VERSION}, "decision_ref": "DEC-AUP-0008",
           "repo": q["repo"], "graph": {k: q["graph"][k] for k in ("path", "source_commit", "graph_digest", "builder_version", "built_at_utc")},
           "tree": q["tree"], "staleness": {k: v for k, v in q["staleness"].items() if k != "checked_nodes"},
           "change_set": {k: v for k, v in q["change_set"].items()},
           "impact_set": {k: v for k, v in imp.items() if k != "files"},
           "verifiers": [], "verdicts": verdicts, "exemptions": [],
           "admission": {"verdict": "paused_safe",
                         "rule": "the graph selects verification, it never replaces it; every affected entity carries a "
                                 "tri-valued verdict; not_measured blocks unqualified admission"}}
    if "empty_impact_explanation" in q:
        rec["empty_impact_explanation"] = q["empty_impact_explanation"]
    if work_item:
        rec["work_item"] = work_item
    return rec


# ----------------------------------------------------------------------------------------------- CLI query
def run_query(a) -> tuple[dict, int]:
    rules = set(RULES) - {x.strip() for x in (a.disable or "").split(",") if x.strip()}
    edge_types = {x.strip() for x in a.edge_types.split(",") if x.strip()} if a.edge_types and a.edge_types != "all" else None
    repo = Repo(a.repo)
    idx = None
    mode = "diff" if a.diff else "worktree"
    tree_commit, tree_dirty, files, base, head = None, None, [], None, None
    try:
        tree_commit, tree_dirty = repo.head(), repo.dirty()
        if a.diff:
            b, _, h = a.diff.partition("..")
            base, head = repo.rev(b), repo.rev(h or "HEAD")
            files = repo.diff_files(base, head)
        elif a.files:
            files = parse_file_args(a.files)
        else:
            files = repo.worktree_files()
        idx = load_graph(a.graph, rules)
        q = query(idx, files, mode=mode, base=base, head=head, tree_commit=tree_commit, tree_dirty=tree_dirty, repo=repo,
                  max_depth=None if a.max_depth is not None and a.max_depth < 0 else (a.max_depth if a.max_depth is not None else DEFAULT_MAX_DEPTH),
                  edge_types=edge_types, rules=rules, graph_path=str(a.graph))
        return q, (3 if q["events"] else 0)
    except Refusal as r:
        return refusal_doc(idx, r, mode=mode, tree_commit=tree_commit, tree_dirty=tree_dirty, repo=repo,
                           graph_path=str(a.graph), files=files), 2


def human(q: dict) -> str:
    lines = []
    g = q["graph"]
    lines.append(f"graph {g.get('source_commit', '?')[:12]} digest {str(g.get('graph_digest'))[:19]}… built {g.get('built_at_utc')} "
                 f"| tree {str(q['tree'].get('commit'))[:12]}{' DIRTY' if q['tree'].get('dirty') else ''} | mode {q['change_set']['mode']}")
    if q.get("refusal"):
        r = q["refusal"]
        lines.append(f"REFUSED {r['code']}: {r['reason']}")
        return "\n".join(lines)
    lines.append(f"staleness: {q['staleness']['verdict']} ({q['staleness'].get('checked_nodes', 0)} node hashes checked)")
    for f in q["change_set"]["files"]:
        flag = " NEW" if f.get("new") else (" UNCOVERED" if f.get("uncovered") else "")
        lines.append(f"  {f['status']} {f['kind']:<13} {f['path']}{flag}" + (f"  [{f['scoped_fallback']}]" if f.get("scoped_fallback") else ""))
    imp = q["impact_set"]
    if imp["global_fallback"]["triggered"]:
        lines.append(f"GLOBAL FALLBACK: {imp['global_fallback']['reason']} — {imp['total']} entities")
    lines.append(f"impact: {len(imp['deterministic_core'])} deterministic_core + {len(imp['inferred_tail'])} inferred_tail "
                 f"(max_depth {imp['max_depth']}, edge_types {imp['edge_types']})")
    for section in ("deterministic_core", "inferred_tail"):
        for e in imp[section]:
            chain = " ← ".join(f"{h['edge_type']}{'*' if h['provenance'] != 'deterministic' else ''}" for h in e["path"])
            lines.append(f"  d{e['depth']} {section[:4]} {e['boundary']:<10} {e['entity']}  [{chain}]  → {e['verifier_hint']}")
    for ev in q["events"]:
        lines.append(f"EVENT {ev['code']}: {ev['text']}")
    if "empty_impact_explanation" in q:
        lines.append("explanation draft: " + q["empty_impact_explanation"]["reason"])
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------------- selftest
def _fixture_graph(name: str) -> GraphIndex:
    return GraphIndex(json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8")))


def _receipt_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _entity_view(q: dict) -> dict:
    imp = q["impact_set"]
    view = {}
    for section in ("deterministic_core", "inferred_tail"):
        for e in imp[section]:
            view[e["entity"]] = {"section": section, "depth": e["depth"], "boundary": e.get("boundary")}
    return view


def _check_receipt_conformant(q: dict) -> tuple[bool, list[str]]:
    rec = receipt_skeleton(q)
    rschema = schema_check.load_schema(schema_check.RECEIPT_SCHEMA_PATH)
    findings = schema_check.check_receipt(rec, rschema)
    codes = sorted({f["code"] for f in findings})
    return not codes, codes


def fixture_battery(rules: set[str]) -> list[dict]:
    """Every expectation of the selftest as (name, ok, detail); reused by the mutation battery with rules disabled."""
    checks: list[dict] = []

    def add(name, ok, **kw):
        checks.append({"name": name, "ok": bool(ok), **kw})

    g01 = _fixture_graph("conformant-01-graph-full-stack-all-edge-types.json")
    SRC = g01.manifest["source_commit"]
    OTHER = "2222222222222222222222222222222222222222"

    # --- GRAPH-001 receipt fixtures: the expected impact set is contained with matching section and depth
    for name in ("conformant-08-receipt-worktree-admitted.json", "conformant-09-receipt-diff-mode-graph-at-base.json",
                 "conformant-10-receipt-not-measured-with-owned-exemption.json", "conformant-11-receipt-failed-verdict-refused.json",
                 "conformant-12-receipt-not-measured-paused-safe.json", "conformant-16-receipt-with-fitness-rules-verifier.json"):
        rf = _receipt_fixture(name)
        cs = rf["change_set"]
        files = [{"path": f["path"], "status": f["status"]} for f in cs["files"]]
        try:
            q = query(g01, files, mode=cs["mode"], base=cs.get("base"), head=cs.get("head"),
                      tree_commit=rf["tree"]["commit"], tree_dirty=rf["tree"]["dirty"], max_depth=rf["impact_set"]["max_depth"], rules=rules)
        except Refusal as r:
            add(f"{name}: query answers (no refusal)", False, refusal=r.code)
            continue
        view = _entity_view(q)
        missing, misplaced = [], []
        for section in ("deterministic_core", "inferred_tail"):
            for e in rf["impact_set"][section]:
                v = view.get(e["entity"])
                if v is None:
                    missing.append(e["entity"])
                elif v["section"] != section or v["depth"] != e["depth"]:
                    misplaced.append({"entity": e["entity"], "expected": (section, e["depth"]), "got": (v["section"], v["depth"])})
        extra = sorted(set(view) - {e["entity"] for s in ("deterministic_core", "inferred_tail") for e in rf["impact_set"][s]})
        add(f"{name}: every expected entity present in the expected section at the expected depth", not missing and not misplaced,
            missing=missing, misplaced=misplaced, extra_full_closure=extra)
        ok, codes = _check_receipt_conformant(q)
        add(f"{name}: computed impact set is receipt-ready (ChangeAdmissionReceipt/v1 skeleton conformant)", ok, codes=codes)

    # --- 13 doc-only: empty impact, no event
    rf = _receipt_fixture("conformant-13-receipt-doc-only-change-empty-impact.json")
    q = query(g01, [{"path": "apps/api/docs/tasks.md", "status": "M"}], mode="worktree", tree_commit=SRC, tree_dirty=True,
              max_depth=3, rules=rules)
    add("13 doc-only change: empty impact set and NO EMPTY_IMPACT event (documentation is exempt)",
        q["impact_set"]["total"] == 0 and not q["events"], events=q["events"])
    # --- 14 new leaf file: empty impact + event + generated explanation with graph_metadata
    q = query(g01, [{"path": "apps/api/src/tasks/leaf-helper.ts", "status": "A"}], mode="worktree", tree_commit=SRC,
              tree_dirty=True, max_depth=3, rules=rules)
    ev = [e["code"] for e in q["events"]]
    exp = q.get("empty_impact_explanation") or {}
    add("14 new leaf code file: empty impact set raises EMPTY_IMPACT_REQUIRES_EXPLANATION with a graph_metadata draft",
        ev == ["EMPTY_IMPACT_REQUIRES_EXPLANATION"] and exp.get("graph_metadata", {}).get("changed_node_known_to_graph") is False
        and exp["graph_metadata"].get("extractors") == g01.manifest["extractors"], events=ev)
    ok, codes = _check_receipt_conformant(q)
    add("14: the skeleton receipt with the generated explanation is conformant (no EMPTY_IMPACT_WITHOUT_EXPLANATION)", ok, codes=codes)
    # --- 15 lockfile: global fallback = every node
    q = query(g01, [{"path": "pnpm-lock.yaml", "status": "M"}], mode="worktree", tree_commit=SRC, tree_dirty=True, max_depth=3, rules=rules)
    rf = _receipt_fixture("conformant-15-receipt-lockfile-global-fallback.json")
    ents = set(_entity_view(q))
    add("15 lockfile change: global_fallback triggered with reason and the impact set is every node of the graph",
        q["impact_set"]["global_fallback"].get("triggered") is True and bool(q["impact_set"]["global_fallback"].get("reason"))
        and ents == set(g01.nodes) and {e["entity"] for e in rf["impact_set"]["deterministic_core"]} <= ents, n=len(ents))
    ok, codes = _check_receipt_conformant(q)
    add("15: fallback receipt skeleton conformant", ok, codes=codes)
    # root package.json / tsconfig / turbo.json / .env.example also trigger the fallback; a nested package.json does not
    trig = []
    for p in ("package.json", "tsconfig.base.json", "turbo.json", ".env.example", "pnpm-workspace.yaml"):
        q = query(g01, [{"path": p, "status": "M"}], mode="worktree", tree_commit=SRC, tree_dirty=True, rules=rules)
        trig.append(q["impact_set"]["global_fallback"].get("triggered") is True)
    q = query(g01, [{"path": "apps/api/package.json", "status": "M"}], mode="worktree", tree_commit=SRC, tree_dirty=True, rules=rules)
    add("global fallback on root package.json / tsconfig.base.json / turbo.json / .env.example / pnpm-workspace.yaml, not on a nested package.json",
        all(trig) and q["impact_set"]["global_fallback"].get("triggered") is False, triggered=trig)
    # scoped fallback: apps/api/package.json seeds the deployable and opens its containment
    ents = _entity_view(q)
    api_units = sorted(e["from"] for e in g01.rev.get("deployable_unit:apps/api", []) if e["type"] == "deploys_to")
    web = ents.get("code_unit:apps/web/lib/api/tasks.ts")
    add("scoped fallback: apps/api/package.json ⇒ deployable seeded, every unit shipped in apps/api affected (deterministic, depth 1); apps/web only beyond",
        "deployable_unit:apps/api" in q["seeds"]
        and all(ents.get(u, {}).get("section") == "deterministic_core" and ents[u]["depth"] == 1 for u in api_units)
        and (web is None or web["depth"] > 1), seeds=q["seeds"], n=len(ents), api_units=len(api_units))

    # --- refusals
    def refuses(code, **kw):
        try:
            query(g01, kw.pop("files"), rules=rules, **kw)
            return False, None
        except Refusal as r:
            return r.code == code, r.code

    ok, got = refuses("STALE_GRAPH", files=[{"path": "apps/api/src/tasks/tasks.service.ts", "status": "M"}], mode="worktree",
                      tree_commit=OTHER, tree_dirty=True)
    add("STALE_GRAPH: worktree HEAD ≠ graph source_commit is refused, not answered", ok, got=got)
    ok, got = refuses("STALE_GRAPH", files=[{"path": "apps/api/src/tasks/tasks.service.ts", "status": "M"}], mode="diff",
                      base=OTHER, head=SRC, tree_commit=SRC, tree_dirty=False)
    add("STALE_GRAPH: diff mode with graph ≠ base is refused", ok, got=got)
    ok, got = refuses("STALE_GRAPH", files=[{"path": "apps/api/src/tasks/tasks.service.ts", "status": "M"}], mode="diff",
                      base=SRC, head=OTHER, tree_commit=OTHER, tree_dirty=True)
    add("STALE_GRAPH: diff mode on a dirty working tree is refused", ok, got=got)
    q = query(g01, [{"path": "apps/api/src/tasks/tasks.service.ts", "status": "M"}], mode="diff", base=SRC, head=OTHER,
              tree_commit=OTHER, tree_dirty=False, rules=rules)
    add("diff mode with graph at base and a clean tree answers (fresh)", q["staleness"]["verdict"] == "fresh")
    # dirty graph manifest
    dd = json.loads(canonical(g01.doc))
    dd["manifest"]["dirty"] = True
    dd["manifest"]["graph_digest"] = schema_check.graph_digest(dd)
    tmp = Path(os.environ.get("IMPACT_TMP", "/tmp")) / "impact-selftest-dirty-graph.json"
    tmp.write_bytes(dump(dd))
    ok, got = False, "answered"
    try:
        load_graph(tmp, rules)
    except Refusal as r:
        ok, got = r.code == "STALE_GRAPH", r.code
    finally:
        tmp.unlink(missing_ok=True)
    add("STALE_GRAPH: a graph with manifest.dirty = true is refused by load_graph", ok, got=got)
    # hash mismatch: a tracked, unchanged node whose bytes differ from the tree
    # a reader that returns the declared bytes for every node except one
    def reader_factory(bad: str | None):
        table = {}
        for n in g01.doc["nodes"]:
            p = n.get("path")
            if p and n["type"] in FILE_HASH_TYPES:
                key = p.rstrip("/") + "/package.json" if n["type"] == "deployable_unit" else p
                table[key] = n["content_hash"]

        def reader(path):
            h = table.get(path)
            if h is None:
                return None
            return b"drifted" if path == bad else _HashBytes(h)
        return reader

    ok, got = refuses("STALE_GRAPH", files=[{"path": "apps/api/src/tasks/tasks.service.ts", "status": "M"}], mode="worktree",
                      tree_commit=SRC, tree_dirty=True, reader=reader_factory("apps/api/src/tasks/tasks.controller.ts"))
    add("STALE_GRAPH: an unchanged tracked node whose content hash no longer matches the tree is refused (mismatched_nodes)", ok, got=got)
    q = query(g01, [{"path": "apps/api/src/tasks/tasks.service.ts", "status": "M"}], mode="worktree", tree_commit=SRC,
              tree_dirty=True, reader=reader_factory(None), rules=rules)
    add("hash check passes when every unchanged node matches (changed file excluded from the comparison)",
        q["staleness"]["verdict"] == "fresh" and q["staleness"].get("checked_nodes", 0) >= 5, checked=q["staleness"].get("checked_nodes"))
    ok, got = refuses("UNKNOWN_NODE", files=[{"path": "apps/api/src/tasks/not-in-graph.ts", "status": "M"}], mode="worktree",
                      tree_commit=SRC, tree_dirty=True)
    add("UNKNOWN_NODE: a modified code file without a node is refused", ok, got=got)
    ok, got = refuses("EMPTY_CHANGE_SET", files=[], mode="worktree", tree_commit=SRC, tree_dirty=False)
    add("EMPTY_CHANGE_SET: nothing changed ⇒ refusal, not an empty (approving) impact set", ok, got=got)
    q = query(g01, [{"path": "apps/api/scripts/setup.sh", "status": "M"}], mode="worktree", tree_commit=SRC, tree_dirty=True, rules=rules)
    add("uncovered file kind (.sh) is not UNKNOWN_NODE: answered with uncovered flag + EMPTY_IMPACT event",
        q["change_set"]["files"][0].get("uncovered") is True and [e["code"] for e in q["events"]] == ["EMPTY_IMPACT_REQUIRES_EXPLANATION"])

    # --- provenance separation, depth and edge-type filters on the fixture graph
    files = [{"path": "apps/api/src/tasks/tasks.service.ts", "status": "M"}]
    q = query(g01, files, mode="worktree", tree_commit=SRC, tree_dirty=True, max_depth=3, rules=rules)
    v = _entity_view(q)
    add("provenance split: web client (reached only through an inferred/observed consumes_contract hop) sits in inferred_tail with boundary service; "
        "no inferred hop inside deterministic_core",
        v.get("code_unit:apps/web/lib/api/tasks.ts", {}).get("section") == "inferred_tail"
        and v["code_unit:apps/web/lib/api/tasks.ts"]["boundary"] == "service"
        and all(h["provenance"] == "deterministic" for e in q["impact_set"]["deterministic_core"] for h in e["path"]), view=v.get("code_unit:apps/web/lib/api/tasks.ts"))
    add("best path prefers deterministic: tasks.controller.ts is reached via imports (deterministic), not via the inferred DI calls edge",
        v.get("code_unit:apps/api/src/tasks/tasks.controller.ts", {}).get("section") == "deterministic_core")
    q1 = query(g01, files, mode="worktree", tree_commit=SRC, tree_dirty=True, max_depth=1, rules=rules)
    add("depth filter: max_depth 1 keeps only depth-1 entries (route at depth 2 and web client at depth 3 drop out)",
        all(e["depth"] == 1 for e in q1["impact_set"]["deterministic_core"] + q1["impact_set"]["inferred_tail"])
        and "route:POST /tasks" not in _entity_view(q1) and q1["impact_set"]["total"] >= 3, total=q1["impact_set"]["total"])
    qe = query(g01, files, mode="worktree", tree_commit=SRC, tree_dirty=True, max_depth=3, edge_types={"imports"}, rules=rules)
    ve = _entity_view(qe)
    add("edge-type filter: --edge-types imports keeps importers only (no route, no test-verifies-only entity, no work item)",
        "route:POST /tasks" not in ve and "work_item:MUN-0041" not in ve and "code_unit:apps/api/src/tasks/tasks.controller.ts" in ve
        and all(h["edge_type"] == "imports" for e in qe["impact_set"]["deterministic_core"] + qe["impact_set"]["inferred_tail"] for h in e["path"]),
        entities=sorted(ve))
    # forward declared-by hops: dto file change ⇒ its contract seeded, route (implements_contract reverse) and controller (consumes) affected
    q = query(g01, [{"path": "apps/api/src/tasks/dto/create-task.dto.ts", "status": "M"}], mode="worktree", tree_commit=SRC, tree_dirty=True, rules=rules)
    v = _entity_view(q)
    add("changed DTO file seeds its contract node; the route serving it and the controller consuming it are depth-1 deterministic impact",
        "contract:apps/api/src/tasks/dto/create-task.dto.ts#CreateTaskDto" in q["seeds"]
        and v.get("route:POST /tasks", {}).get("depth") == 1 and v.get("code_unit:apps/api/src/tasks/tasks.controller.ts", {}).get("depth") == 1
        and v["route:POST /tasks"]["section"] == "deterministic_core", seeds=q["seeds"])
    q = query(g01, [{"path": "apps/api/prisma/schema.prisma", "status": "M"}], mode="worktree", tree_commit=SRC, tree_dirty=True, rules=rules)
    v = _entity_view(q)
    add("schema.prisma change: the declared data models are affected (seeded when the node carries the declaring path, else a forward "
        "declared-by hop at depth 1) and the service mapping Task follows (reverse maps_model)",
        all(m in q["seeds"] or v.get(m, {}).get("depth") == 1 and v[m]["section"] == "deterministic_core" for m in ("data_model:Task", "data_model:Project"))
        and v.get("code_unit:apps/api/src/tasks/tasks.service.ts", {}).get("depth") in (1, 2), seeds=q["seeds"], view={k: v[k] for k in v if k.startswith("data_model")})
    q = query(g01, [{"path": "apps/api/src/prisma/prisma.service.ts", "status": "M"}], mode="worktree", tree_commit=SRC, tree_dirty=True, rules=rules)
    v = _entity_view(q)
    add("containment is never expanded backwards: a change in prisma.service.ts reaches deployable apps/api (forward) but not every unit of apps/api",
        v.get("deployable_unit:apps/api", {}).get("section") == "deterministic_core"
        and "code_unit:apps/api/src/tasks/dto/create-task.dto.ts" not in v, entities=sorted(v))
    # determinism
    qa = query(g01, files, mode="worktree", tree_commit=SRC, tree_dirty=True, rules=rules)
    qb = query(g01, files, mode="worktree", tree_commit=SRC, tree_dirty=True, rules=rules)
    add("determinism: the same query twice yields identical output (timestamps excluded)",
        canonical(strip_volatile(qa)) == canonical(strip_volatile(qb)))

    # --- ts-mini: exact expectations (IMPACT_EXPECTED.json), built with build_graph from the fixture tree
    tsdoc = build_graph.build(TS_MINI, worktree=True, built_at=build_graph.FIXED_BUILT_AT)
    tsdoc["manifest"]["dirty"] = False  # the fixture tree is read from the worktree; freshness is asserted by the expectations file
    tidx = GraphIndex(tsdoc)
    TSRC = tsdoc["manifest"]["source_commit"]
    expected = json.loads(IMPACT_EXPECTED_PATH.read_text(encoding="utf-8")) if IMPACT_EXPECTED_PATH.exists() else {"scenarios": []}
    ts_reader = lambda rel: (TS_MINI / rel).read_bytes() if (TS_MINI / rel).is_file() else None  # noqa: E731
    for sc in expected.get("scenarios", []):
        try:
            q = query(tidx, [dict(f) for f in sc["files"]], mode="worktree", tree_commit=TSRC, tree_dirty=False, reader=ts_reader,
                      max_depth=sc.get("max_depth", DEFAULT_MAX_DEPTH),
                      edge_types=set(sc["edge_types"]) if sc.get("edge_types") else None, rules=rules)
        except Refusal as r:
            add(f"ts-mini {sc['id']}: {sc['title']}", sc.get("refusal") == r.code, got=r.code)
            continue
        if sc.get("refusal"):
            add(f"ts-mini {sc['id']}: {sc['title']}", False, got="answered")
            continue
        got = {e: (v["section"], v["depth"]) for e, v in _entity_view(q).items()}
        if sc.get("impact_all_nodes"):
            want = {n: ("deterministic_core", 0) for n in tidx.nodes if n not in sc["seeds"]}
        else:
            want = {e: (v[0], v[1]) for e, v in sc["impact"].items()}
        ok = got == want and sorted(q["seeds"]) == sorted(sc["seeds"]) and [e["code"] for e in q["events"]] == sc.get("events", []) \
            and q["impact_set"]["global_fallback"]["triggered"] == sc.get("global_fallback", False) \
            and q["staleness"]["verdict"] == "fresh" and q["staleness"]["checked_nodes"] >= 20
        add(f"ts-mini {sc['id']}: {sc['title']}", ok,
            missing=sorted(set(want) - set(got)), extra=sorted(set(got) - set(want)),
            different=sorted(e for e in set(want) & set(got) if want[e] != got[e]), seeds=q["seeds"], events=[e["code"] for e in q["events"]],
            checked_nodes=q["staleness"]["checked_nodes"])
        okr, codes = _check_receipt_conformant(q)
        add(f"ts-mini {sc['id']}: receipt skeleton conformant", okr, codes=codes)
    add("ts-mini IMPACT_EXPECTED.json present with ≥ 6 scenarios", len(expected.get("scenarios", [])) >= 6, n=len(expected.get("scenarios", [])))
    return checks


# ----------------------------------------------------------------------------------------------- pilot replay
def _stem(path: str) -> str:
    """outbox.relay.postgres.spec.ts → outbox.relay ; result-authority.migration.spec.ts → result-authority"""
    base = os.path.basename(path)
    base = re.sub(r"\.(spec|test)\.[cm]?[jt]sx?$", "", base)
    base = re.sub(r"\.(postgres|migration|contract|e2e|integration|status-mutation|smoke)$", "", base)
    return re.sub(r"\.[cm]?[jt]sx?$", "", base)


def _source_class(idx: GraphIndex, path: str, covered: list[dict]) -> str:
    """Why a co-changed file was selected by no other changed file (registry candidate classes)."""
    kind = classify_file(path, idx)
    ids = idx.by_path.get(path, [])
    fwd = [e for i in ids for e in idx.fwd.get(i, []) if e["type"] != "deploys_to"]
    rev = [e for i in ids for e in idx.rev.get(i, []) if e["type"] not in ("deploys_to", "documents")]
    if kind == "test":
        if not any(e["type"] in ("verifies", "imports") and e["to"].startswith("code_unit:") for e in fwd):
            return "unlinked test: the spec imports no unit (binds through fs/process/DB — e.g. *.migration.spec.ts reading prisma/migrations/*.sql, *.postgres.spec.ts spawning the app)"
        return "test whose imported units did not change in this commit (bundled edit)"
    if kind == "data_model":
        return "upstream data model (schema.prisma): the presumed cause, never selected by its dependents"
    if kind == "doc":
        return "document linking none of the changed files"
    if not rev:
        return "leaf unit nothing depends on in the graph (presumed cause or dead code)"
    return "upstream unit (types/errors/constants/service) or bundled unrelated edit: presumed cause, indistinguishable statically"


def replay(repo: Repo, n_commits: int, max_depths=(1, DEFAULT_MAX_DEPTH, None), out_dir: Path | None = None) -> dict:
    """History replay: for each selected commit C, build the graph at C^ (git objects), then for every covered
    modified/deleted file f of C compute impact({f}) and test whether the other changed files of C are selected."""
    revs = git(["rev-list", "--no-merges", "HEAD"], repo.top).split()
    selected, skipped = [], []
    per_commit = []
    graph_cache: dict[str, GraphIndex] = {}
    t_start = time.monotonic()
    for c in revs:
        if len(selected) >= n_commits:
            break
        parents = git(["rev-list", "--parents", "-n", "1", c], repo.top).split()[1:]
        if len(parents) != 1:
            skipped.append({"commit": c[:12], "reason": "root or merge commit"})
            continue
        parent = parents[0]
        files = repo.diff_files(parent, c)
        if not files:
            skipped.append({"commit": c[:12], "reason": "no files under the queried path"})
            continue
        if parent not in graph_cache:
            try:
                graph_cache[parent] = GraphIndex(build_graph.build(repo.top, rev=parent, built_at=build_graph.FIXED_BUILT_AT))
            except Exception as ex:  # noqa: BLE001
                skipped.append({"commit": c[:12], "reason": f"parent graph failed: {type(ex).__name__}: {str(ex)[:80]}"})
                continue
        idx = graph_cache[parent]
        existing = [f for f in files if f["status"] in ("M", "D", "R")]
        covered = [f for f in existing if idx.by_path.get(f["path"])]
        if len(covered) < 2:
            skipped.append({"commit": c[:12], "reason": f"< 2 covered modified files ({len(covered)} covered of {len(existing)} existing, {len(files)} total)"})
            continue
        selected.append(c)
        subject = git(["log", "-n", "1", "--format=%s", c], repo.top).strip()
        rec = {"commit": c, "parent": parent, "subject": subject[:100], "files_total": len(files),
               "files_existing": len(existing), "files_covered": len(covered), "files_new": sum(1 for f in files if f["status"] == "A"),
               "files_uncovered": [f["path"] for f in existing if not idx.by_path.get(f["path"])],
               "graph": {"source_commit": parent, "graph_digest": idx.manifest["graph_digest"], "nodes": idx.manifest["node_count"],
                         "edges": idx.manifest["edge_count"]},
               "by_depth": {}}
        cov_paths = [f["path"] for f in covered]
        ex_paths = [f["path"] for f in existing]
        for md in max_depths:
            key = "unlimited" if md is None else str(md)
            reach: dict[str, set[str]] = {}   # seed path -> set of affected paths
            fallback = False
            sizes = []
            for f in covered:
                try:
                    q = query(idx, [{"path": f["path"], "status": f["status"]}], mode="diff", base=parent, head=c,
                              tree_commit=repo.head(), tree_dirty=False, max_depth=md, rules=set(RULES) - {"hash_check"})
                except Refusal as r:
                    reach[f["path"]] = set()
                    rec.setdefault("refusals", []).append({"file": f["path"], "code": r.code})
                    continue
                imp = q["impact_set"]
                fallback = fallback or imp["global_fallback"]["triggered"]
                paths = set()
                for e in imp["deterministic_core"] + imp["inferred_tail"]:
                    p = idx.nodes[e["entity"]].get("path")
                    if p:
                        paths.add(p)
                reach[f["path"]] = paths
                sizes.append(imp["total"])
            predicted_by_others = {g for g in ex_paths if any(g in reach.get(f, set()) for f in cov_paths if f != g)}
            pairs = [(f, g) for f in cov_paths for g in cov_paths if f != g]
            pair_hits = sum(1 for f, g in pairs if g in reach.get(f, set()))
            # sources = changed files no other changed file selects: the commit's own cause(s) — by construction a
            # dependency is never selected by its dependents — plus genuine blind spots. One root per commit is free
            # (explained recall); every further source is an unexplained co-change (a miss).
            sources_cov = sorted(g for g in cov_paths if g not in predicted_by_others)
            sources_ex = sorted(g for g in ex_paths if g not in predicted_by_others)
            n_c, n_e = len(cov_paths), len(ex_paths)
            unit_names = [os.path.basename(g) for g in ex_paths if classify_file(g, idx) != "test"]
            stem_linked = [g for g in sources_cov if classify_file(g, idx) == "test"
                           and any(u == _stem(g) + os.path.splitext(u)[1] or u.startswith(_stem(g) + ".") for u in unit_names)]
            rec["by_depth"][key] = {
                "what_if_stem_linked_tests": {"tests": stem_linked,
                                              "recall_explained_covered": round(min(1.0, (n_c - len(sources_cov) + len(stem_linked)) / (n_c - 1)), 4) if n_c > 1 else None},
                "recall_explained_covered": round(min(1.0, (n_c - len(sources_cov)) / (n_c - 1)), 4) if n_c > 1 else None,
                "recall_explained_existing": round(min(1.0, (n_e - len(sources_ex)) / (n_e - 1)), 4) if n_e > 1 else None,
                "recall_strict_covered": round((n_c - len(sources_cov)) / n_c, 4),
                "recall_strict_existing": round((n_e - len(sources_ex)) / n_e, 4),
                "pairwise_recall": round(pair_hits / len(pairs), 4) if pairs else None,
                "sources_covered": [{"file": g, "class": _source_class(idx, g, covered)} for g in sources_cov],
                "sources_uncovered": [g for g in sources_ex if g not in sources_cov],
                "mean_impact_size": round(sum(sizes) / len(sizes), 1) if sizes else None,
                "selection_ratio": round((sum(sizes) / len(sizes)) / max(1, idx.manifest["node_count"]), 4) if sizes else None,
                "global_fallback": fallback}
        per_commit.append(rec)
    # reproducibility: the whole replay again for the first commit, compared canonically
    repro = None
    if per_commit:
        first = per_commit[0]
        idx = graph_cache[first["parent"]]
        f0 = next(f for f in repo.diff_files(first["parent"], first["commit"]) if idx.by_path.get(f["path"]) and f["status"] in ("M", "D", "R"))
        qa = query(idx, [{"path": f0["path"], "status": f0["status"]}], mode="diff", base=first["parent"], head=first["commit"],
                   tree_commit=repo.head(), tree_dirty=False, rules=set(RULES) - {"hash_check"})
        idx2 = GraphIndex(build_graph.build(repo.top, rev=first["parent"], built_at=build_graph.FIXED_BUILT_AT))
        qb = query(idx2, [{"path": f0["path"], "status": f0["status"]}], mode="diff", base=first["parent"], head=first["commit"],
                   tree_commit=repo.head(), tree_dirty=False, rules=set(RULES) - {"hash_check"})
        repro = {"commit": first["commit"], "file": f0["path"], "graph_digest_rebuilt_equal": idx.manifest["graph_digest"] == idx2.manifest["graph_digest"],
                 "impact_identical": canonical(strip_volatile(qa)) == canonical(strip_volatile(qb)),
                 "impact_sha256": hashlib.sha256(canonical(strip_volatile(qa)).encode()).hexdigest()}
    depth_keys = ["unlimited" if md is None else str(md) for md in max_depths]
    summary = {"commits_selected": len(selected), "commits_skipped": len(skipped), "seconds": round(time.monotonic() - t_start, 1)}

    def mean(xs):
        xs = [x for x in xs if x is not None]
        return round(sum(xs) / len(xs), 4) if xs else None

    for key in depth_keys:
        bd = [r["by_depth"][key] for r in per_commit]
        summary[f"depth_{key}"] = {"mean_recall_explained_covered": mean(b["recall_explained_covered"] for b in bd),
                                   "mean_recall_explained_existing": mean(b["recall_explained_existing"] for b in bd),
                                   "mean_recall_strict_covered": mean(b["recall_strict_covered"] for b in bd),
                                   "mean_recall_strict_existing": mean(b["recall_strict_existing"] for b in bd),
                                   "mean_pairwise_recall": mean(b["pairwise_recall"] for b in bd),
                                   "commits_explained_at_or_above_0_8_covered": sum(1 for b in bd if (b["recall_explained_covered"] or 0) >= 0.8),
                                   "commits_fully_explained_covered": sum(1 for b in bd if b["recall_explained_covered"] == 1.0),
                                   "sources_covered_total": sum(len(b["sources_covered"]) for b in bd),
                                   "unexplained_covered_total": sum(max(0, len(b["sources_covered"]) - 1) for b in bd),
                                   "sources_uncovered_total": sum(len(b["sources_uncovered"]) for b in bd),
                                   "source_classes": _count(sc["class"] for b in bd for sc in b["sources_covered"]),
                                   "what_if_stem_linked_tests": {"tests_total": sum(len(b["what_if_stem_linked_tests"]["tests"]) for b in bd),
                                                                 "mean_recall_explained_covered": mean(b["what_if_stem_linked_tests"]["recall_explained_covered"] for b in bd),
                                                                 "note": "builder1 candidate: an inferred `verifies` edge from a spec to a changed unit whose basename starts with the spec's stem (outbox.relay.postgres.spec.ts → outbox.relay.ts; result-authority.migration.spec.ts → result-authority.*.ts)"},
                                   "mean_selection_ratio": mean(b["selection_ratio"] for b in bd)}
    result = {"schema": "ImpactReplay/v1", "repo": {"name": repo.name, "path": str(repo.top), "head": repo.head()},
              "selection_rule": "git rev-list --no-merges HEAD order; a commit is selected when it has one parent, its parent graph builds, "
                                "and ≥ 2 of its modified/deleted/renamed files have a node in the parent graph (covered); first N such commits",
              "metric": "co-change recall from the parent graph. A changed file g is selected when it lies in impact({f}) of at least one "
                        "other changed covered file f of the same commit (impact of a set = union of singleton impacts). sources = changed "
                        "files nobody selects: the commit's own cause (a dependency is never selected by its dependents — schema.prisma, a "
                        "types/errors module) or a blind spot. recall_explained = (n − sources) / (n − 1): one root per commit is free, every "
                        "further source is an unexplained co-change (the acceptance number); recall_strict = (n − sources) / n (leave-one-out, "
                        "penalises the cause; reported); pairwise = hits / ordered pairs. _covered: over modified/deleted files with a node in "
                        "the parent graph; _existing: over all modified/deleted files incl. uncovered kinds (sql, yml, json, sh). New files "
                        "(status A) cannot be selected from the parent graph and are excluded. selection_ratio = mean singleton impact size / "
                        "graph nodes (precision proxy).",
              "max_depths": depth_keys, "summary": summary, "commits": per_commit, "skipped": skipped, "reproducibility": repro}
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "replay.json").write_bytes(dump(result))
    return result


# ----------------------------------------------------------------------------------------------- selftest driver
def selftest(receipt_out: Path | None, pilot: Path | None, pilot_graph: Path | None, replay_commits: int, replay_out: Path | None) -> int:
    t0 = time.monotonic()
    checks = fixture_battery(set(RULES))
    n_ok = sum(1 for c in checks if c["ok"])
    print(f"fixture battery: {n_ok}/{len(checks)} checks")
    for c in checks:
        if not c["ok"]:
            print("  FAIL", c["name"], {k: v for k, v in c.items() if k not in ("name", "ok")})
    # negative control: a wrong expectation must be red
    ctrl_ok = False
    try:
        bad = json.loads(IMPACT_EXPECTED_PATH.read_text(encoding="utf-8"))
        if bad["scenarios"]:
            bad["scenarios"][0]["impact"]["code_unit:definitely/not/there.ts"] = ["deterministic_core", 1]
            tmp = IMPACT_EXPECTED_PATH.with_name("IMPACT_EXPECTED.negative-control.tmp.json")
            orig = IMPACT_EXPECTED_PATH
            try:
                globals()["IMPACT_EXPECTED_PATH"] = tmp
                tmp.write_bytes(dump(bad))
                ctrl = fixture_battery(set(RULES))
                ctrl_ok = any(not c["ok"] and c["name"].startswith(f"ts-mini {bad['scenarios'][0]['id']}:") for c in ctrl)
            finally:
                globals()["IMPACT_EXPECTED_PATH"] = orig
                tmp.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    checks.append({"name": "selftest negative control: a wrong ts-mini expectation is reported red", "ok": ctrl_ok})
    # mutation battery over the rules
    mutants = {}
    for rule in RULES:
        res = fixture_battery(set(RULES) - {rule})
        killed_by = [c["name"] for c in res if not c["ok"]]
        mutants[rule] = {"killed": bool(killed_by), "killed_by": killed_by[:4], "n_red": len(killed_by)}
    survived = [r for r, m in mutants.items() if not m["killed"]]
    checks.append({"name": f"mutation battery: disabling each of the {len(RULES)} rules turns ≥ 1 expectation red (0 mutants survived)",
                   "ok": not survived, "survived": survived})
    print(f"mutation battery: {len(RULES) - len(survived)}/{len(RULES)} mutants killed" + (f"; SURVIVED {survived}" if survived else ""))
    receipt = {"schema": "ReadinessReceipt/v1", "portion_id": "AUP-GRAPH-003:impact0", "tool": TOOL, "tool_version": VERSION,
               "captured_at_utc": now_iso(), "host": os.uname().nodename, "python": sys.version.split()[0],
               "checks": checks, "mutation_battery": {"rules": RULES, "results": mutants, "survived": survived},
               "fixtures": {"receipt_fixtures_replayed": "conformant-08/09/10/11/12/13/14/15/16 on conformant-01 graph (GRAPH-001)",
                            "ts_mini_expectations": str(IMPACT_EXPECTED_PATH.relative_to(ROOT)),
                            "note": "GRAPH-001 receipt fixtures list an illustrative subset of the closure; the check is containment with "
                                    "matching section and depth, the full closure of each is recorded under extra_full_closure"}}
    # pilot
    pilot_ok = True
    if pilot:
        repo = Repo(pilot)
        pchecks = []

        def pcheck(name, ok, **kw):
            pchecks.append({"name": name, "ok": bool(ok), **kw})

        head = repo.head()
        dirty = repo.dirty()
        pcheck("pilot clone is clean and untouched (git status --porcelain empty)", not dirty, head=head)
        gidx = load_graph(pilot_graph, set(RULES))
        pcheck("pilot graph loads and is RelationshipGraph/v1 conformant", True, source_commit=gidx.manifest["source_commit"],
               graph_digest=gidx.manifest["graph_digest"])
        # freshness against HEAD (worktree mode, hash check over every tracked node)
        try:
            st = check_staleness(gidx, repo, "worktree", None, head, dirty, set(), set(RULES))
            pcheck("pilot graph is fresh against the clone HEAD: source_commit == HEAD and every node hash matches the tree",
                   st["verdict"] == "fresh", checked_nodes=st["checked_nodes"])
        except Refusal as r:
            pcheck("pilot graph is fresh against the clone HEAD", False, refusal=r.code, reason=r.reason)
        # an empty worktree change set is a refusal, not an approval
        try:
            query(gidx, repo.worktree_files(), mode="worktree", tree_commit=head, tree_dirty=dirty, repo=repo)
            pcheck("clean pilot tree: --worktree refuses with EMPTY_CHANGE_SET", False)
        except Refusal as r:
            pcheck("clean pilot tree: --worktree refuses with EMPTY_CHANGE_SET (no empty approving set)", r.code == "EMPTY_CHANGE_SET", got=r.code)
        # diff mode with the HEAD graph is stale (graph must sit at base)
        parent = repo.rev("HEAD^")
        files = repo.diff_files(parent, head)
        try:
            query(gidx, files, mode="diff", base=parent, head=head, tree_commit=head, tree_dirty=dirty, repo=repo)
            pcheck("diff HEAD^..HEAD with the HEAD graph: refused STALE_GRAPH (graph ≠ base)", False)
        except Refusal as r:
            pcheck("diff HEAD^..HEAD with the HEAD graph: refused STALE_GRAPH (graph ≠ base)", r.code == "STALE_GRAPH", got=r.code)
        # the same query with the graph rebuilt at base answers
        pidx = GraphIndex(build_graph.build(repo.top, rev=parent, built_at=build_graph.FIXED_BUILT_AT))
        try:
            q = query(pidx, files, mode="diff", base=parent, head=head, tree_commit=head, tree_dirty=dirty, repo=repo)
            okr, codes = _check_receipt_conformant(q)
            pcheck("diff HEAD^..HEAD with the graph rebuilt at HEAD^ (--rev): answers, hashes verified against git objects, receipt skeleton conformant",
                   q["staleness"]["verdict"] == "fresh" and okr, checked_nodes=q["staleness"]["checked_nodes"], total=q["impact_set"]["total"],
                   files=len(files), codes=codes, events=[e["code"] for e in q["events"]])
        except Refusal as r:
            pcheck("diff HEAD^..HEAD with the graph rebuilt at HEAD^", False, refusal=r.code, reason=r.reason)
        # a lockfile change on the pilot ⇒ every node
        q = query(gidx, [{"path": "pnpm-lock.yaml", "status": "M"}], mode="worktree", tree_commit=head, tree_dirty=dirty, repo=None)
        pcheck("pilot: pnpm-lock.yaml change ⇒ global fallback covers every node", q["impact_set"]["global_fallback"]["triggered"]
               and q["impact_set"]["total"] == len(gidx.nodes), total=q["impact_set"]["total"])
        # history replay
        rep = replay(repo, replay_commits, out_dir=replay_out)
        s = rep["summary"]
        d3 = s.get(f"depth_{DEFAULT_MAX_DEPTH}", {})
        du = s.get("depth_unlimited", {})
        pcheck(f"history replay: ≥ 10 real commits replayed from their parent graphs", s["commits_selected"] >= 10, **s)
        pcheck("history replay is reproducible (parent graph digest equal on rebuild; impact identical)",
               bool(rep["reproducibility"]) and rep["reproducibility"]["graph_digest_rebuilt_equal"] and rep["reproducibility"]["impact_identical"],
               **(rep["reproducibility"] or {}))
        pcheck(f"proxy recall (explained co-change, covered files, max_depth {DEFAULT_MAX_DEPTH}) ≥ 0.8 mean",
               (d3.get("mean_recall_explained_covered") or 0) >= 0.8, clause="recall", what_if_stem_linked=d3.get("what_if_stem_linked_tests"), **{k: d3.get(k) for k in ("mean_recall_explained_covered", "mean_recall_strict_covered",
                                                                                                  "mean_pairwise_recall", "commits_explained_at_or_above_0_8_covered",
                                                                                                  "commits_fully_explained_covered", "unexplained_covered_total")}, of=s["commits_selected"])
        pcheck("proxy recall (explained co-change) over ALL existing files incl. uncovered kinds ≥ 0.8 mean, unlimited depth — the uncovered "
               "kinds (sql/yml/json/sh) are the GRAPH-009 gap; reported, sources go to the negative-results candidates",
               (du.get("mean_recall_explained_existing") or 0) >= 0.8, clause="recall", mean_recall_explained_existing=du.get("mean_recall_explained_existing"),
               mean_recall_strict_existing=du.get("mean_recall_strict_existing"), mean_recall_explained_covered_unlimited=du.get("mean_recall_explained_covered"))
        pcheck(f"depth {DEFAULT_MAX_DEPTH} loses nothing against unlimited depth on the pilot (same explained recall)",
               d3.get("mean_recall_explained_covered") == du.get("mean_recall_explained_covered"),
               at_depth=d3.get("mean_recall_explained_covered"), unlimited=du.get("mean_recall_explained_covered"))
        misses = []
        for r in rep["commits"]:
            bd = r["by_depth"]["unlimited"]
            for m in bd["sources_covered"]:
                misses.append({"commit": r["commit"][:12], "file": m["file"], "class": m["class"],
                               "note": "one source per commit is the presumed cause (free); every further one is an unexplained co-change"
                               if len(bd["sources_covered"]) > 1 else "sole source of its commit (presumed cause) — listed for completeness"})
            for m in bd["sources_uncovered"]:
                misses.append({"commit": r["commit"][:12], "file": m, "class": "uncovered file kind (no node: sql/yml/json/sh…) — GRAPH-009 language coverage"})
            bd3 = r["by_depth"][str(DEFAULT_MAX_DEPTH)]
            for m in bd3["sources_covered"]:
                if m["file"] not in {x["file"] for x in bd["sources_covered"]}:
                    misses.append({"commit": r["commit"][:12], "file": m["file"], "class": f"depth-limited (selected only beyond max_depth {DEFAULT_MAX_DEPTH})"})
        receipt["pilot"] = {"repo": repo.name, "path": str(repo.top), "head": head, "graph": str(pilot_graph), "checks": pchecks,
                            "replay_summary": s, "replay_metric": rep["metric"], "replay_selection_rule": rep["selection_rule"],
                            "replay_commits": [{"commit": r["commit"][:12], "subject": r["subject"], "files_total": r["files_total"],
                                                "files_covered": r["files_covered"], "files_new": r["files_new"],
                                                "explained_covered@1": r["by_depth"]["1"]["recall_explained_covered"],
                                                f"explained_covered@{DEFAULT_MAX_DEPTH}": r["by_depth"][str(DEFAULT_MAX_DEPTH)]["recall_explained_covered"],
                                                "explained_covered@inf": r["by_depth"]["unlimited"]["recall_explained_covered"],
                                                "explained_existing@inf": r["by_depth"]["unlimited"]["recall_explained_existing"],
                                                f"strict_covered@{DEFAULT_MAX_DEPTH}": r["by_depth"][str(DEFAULT_MAX_DEPTH)]["recall_strict_covered"],
                                                f"pairwise@{DEFAULT_MAX_DEPTH}": r["by_depth"][str(DEFAULT_MAX_DEPTH)]["pairwise_recall"],
                                                f"selection_ratio@{DEFAULT_MAX_DEPTH}": r["by_depth"][str(DEFAULT_MAX_DEPTH)]["selection_ratio"],
                                                "sources_covered@inf": [m["file"] for m in r["by_depth"]["unlimited"]["sources_covered"]],
                                                "sources_uncovered@inf": r["by_depth"]["unlimited"]["sources_uncovered"]}
                                               for r in rep["commits"]],
                            "replay_detail": str(replay_out / "replay.json") if replay_out else None,
                            "negative_results_candidates": {"target": "science/negative-results/REGISTRY.md (NOT edited by this tool; the registrar decides)",
                                                            "entries": misses}}
        pilot_ok = all(c["ok"] for c in pchecks)
        print(f"pilot: {sum(1 for c in pchecks if c['ok'])}/{len(pchecks)} checks; replay {s['commits_selected']} commits, explained recall "
              f"covered@{DEFAULT_MAX_DEPTH} {d3.get('mean_recall_explained_covered')} (strict {d3.get('mean_recall_strict_covered')}), "
              f"@inf {du.get('mean_recall_explained_covered')}, existing@inf {du.get('mean_recall_explained_existing')}")
        for c in pchecks:
            if not c["ok"]:
                print("  PILOT FAIL", c["name"], {k: v for k, v in c.items() if k not in ("name", "ok")})
    pchecks_all = receipt.get("pilot", {}).get("checks", [])
    only_recall_failed = all(c["ok"] or c.get("clause") == "recall" for c in pchecks_all)
    all_ok = all(c["ok"] for c in checks) and pilot_ok
    receipt["summary"] = {"checks_ok": sum(1 for c in checks if c["ok"]), "checks_total": len(checks),
                          "mutants_killed": len(RULES) - len(survived), "mutants_total": len(RULES),
                          "pilot_checks_ok": sum(1 for c in receipt.get("pilot", {}).get("checks", []) if c["ok"]),
                          "pilot_checks_total": len(receipt.get("pilot", {}).get("checks", [])),
                          "seconds": round(time.monotonic() - t0, 1)}
    receipt["verdict"] = "PASS" if all_ok else ("PARTIAL" if all(c["ok"] for c in checks) and only_recall_failed else "FAIL")
    if receipt["verdict"] == "PARTIAL":
        receipt["verdict_note"] = ("tool, fixtures, refusals, fallback, reproducibility: PASS; the acceptance clause 'proxy-recall ≥ 0.8 on ≥ 10 "
                                   "real commits' is MEASURED AND NOT MET — the unexplained co-changes are listed under "
                                   "pilot.negative_results_candidates for science/negative-results/REGISTRY.md (not edited here)")
    if receipt_out:
        receipt_out.parent.mkdir(parents=True, exist_ok=True)
        receipt_out.write_bytes(dump(receipt))
        print(f"receipt: {receipt_out}")
    print(f"SELFTEST {receipt['verdict']} ({receipt['summary']['checks_ok']}/{receipt['summary']['checks_total']} checks, "
          f"{receipt['summary']['mutants_killed']}/{receipt['summary']['mutants_total']} mutants killed"
          + (f", pilot {receipt['summary']['pilot_checks_ok']}/{receipt['summary']['pilot_checks_total']}" if pilot else "") + ")")
    return 0 if all_ok else 1


# ----------------------------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--graph", type=Path, help="RelationshipGraph/v1 JSON")
    ap.add_argument("--repo", type=Path, help="repository (or a sub-directory of it: paths become relative to it)")
    ap.add_argument("--diff", help="<base>..<head> commit range (graph must be built at base; tree must be clean)")
    ap.add_argument("--worktree", action="store_true", help="change set = git status of the working tree (graph must be built at HEAD)")
    ap.add_argument("--files", nargs="*", help="explicit change set path[:A|M|D] (worktree freshness rules apply)")
    ap.add_argument("--max-depth", type=int, default=None, help=f"traversal depth (default {DEFAULT_MAX_DEPTH}; -1 = unlimited)")
    ap.add_argument("--edge-types", default="all", help="comma-separated edge types to follow (default all)")
    ap.add_argument("--json", action="store_true", help="print the ImpactQuery/v1 JSON instead of the human view")
    ap.add_argument("--out", type=Path, help="write the ImpactQuery/v1 JSON here")
    ap.add_argument("--emit-receipt", type=Path, help="write a ChangeAdmissionReceipt/v1 skeleton (verdicts not_measured, paused_safe)")
    ap.add_argument("--work-item", default=None)
    ap.add_argument("--disable", default="", help="comma-separated rules to disable (mutation battery / diagnostics only)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--receipt", type=Path, help="with --selftest: write the ReadinessReceipt/v1 here")
    ap.add_argument("--pilot", type=Path, help="with --selftest: pilot repo for the history replay")
    ap.add_argument("--pilot-graph", type=Path, help="with --pilot: the pilot graph built at the clone HEAD")
    ap.add_argument("--replay-commits", type=int, default=12)
    ap.add_argument("--replay-out", type=Path, help="with --pilot: directory for replay.json")
    a = ap.parse_args(argv)
    if a.selftest:
        if a.pilot and not a.pilot_graph:
            ap.error("--pilot requires --pilot-graph")
        return selftest(a.receipt, a.pilot, a.pilot_graph, a.replay_commits, a.replay_out)
    if not a.graph or not a.repo or not (a.diff or a.worktree or a.files):
        ap.error("--graph, --repo and one of --diff/--worktree/--files are required (or --selftest)")
    q, code = run_query(a)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_bytes(dump(q))
    if a.emit_receipt:
        try:
            rec = receipt_skeleton(q, a.work_item)
            a.emit_receipt.parent.mkdir(parents=True, exist_ok=True)
            a.emit_receipt.write_bytes(dump(rec))
        except Refusal as r:
            print(f"no receipt: {r}", file=sys.stderr)
    print(json.dumps(q, indent=1, sort_keys=True, ensure_ascii=False) if a.json else human(q))
    return code


if __name__ == "__main__":
    sys.exit(main())

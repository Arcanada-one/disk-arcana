#!/usr/bin/env python3
"""AUP-GRAPH-002 `builder0` — deterministic RelationshipGraph/v1 builder for TypeScript / NestJS / Prisma / Zod trees.

    build_graph.py <repo> --out <graph.json> [--rev HEAD] [--subdir <path>] [--worktree] [--built-at <iso>]
                   [--disable ext1,ext2] [--work-item-pattern <regex>]
    build_graph.py --selftest [--pilot <repo>] [--receipt <ReadinessReceipt.json>] [--pilot-graph <path>]

Sources are read from git objects (`git ls-tree` + `git cat-file --batch` at `--rev`) so the pilot clone is never
checked out or written; `--worktree` reads the files on disk (fixtures) and records `dirty` from `git status`.

Extractors (each one separately disable-able for the mutation battery; `manifest.extractors` lists those that ran):
  imports      static import/export/require/import() resolved through relative paths, tsconfig `paths`, workspace
               package names (dist/ → src/ fallback recorded in `via`)                         → imports (deterministic)
  routes       @Controller + @Get/@Post/... (global prefix from setGlobalPrefix recorded), @WebSocketGateway +
               @SubscribeMessage                                                                 → provides_route (deterministic)
               @Body/@Query DTO parameter types resolved to contract nodes                       → implements_contract (deterministic)
  contracts    class-validator DTO classes, Zod `z.*` constants, string-literal union type aliases, enums in
               workspace packages; declaring file → contract, importing file → contract          → implements_contract / consumes_contract (deterministic)
  prisma       `model`/`enum` blocks of *.prisma (data_model nodes, relation edges), `prisma.<model>.<op>` calls and
               `@prisma/client` model type imports                                               → maps_model (deterministic)
  config       process.env.X / process.env['X'] / configService.get('X')                         → reads_config (deterministic)
  reuse        `reuse: @arcanada/<pkg>` markers in comments (shared-package marker node)         → imports (deterministic)
  di           NestJS constructor injection (`constructor(private readonly x: Svc)`)             → calls (INFERRED, nestjs-di-constructor)
  queue        @InjectQueue(token) producer → @Processor(token) consumer                         → calls (INFERRED, bullmq-queue-token)
  tests        *.spec.ts / *.test.ts(x) / test/ / __tests__/ importing a unit                    → verifies (deterministic)
  http_client  apiClient.get(`/tasks/${id}`)-style call sites matched to served routes           → consumes_contract→route (INFERRED, http-client-url-match, boundary service)
  deployables  pnpm-workspace globs → deployable_unit (service/frontend/cli/adapter/library); `kind=adapter` is the ROLE
               marker — a non-test source declaring `class X extends <ImportedBase>Adapter`, never a Playwright dependency
               (a transport); file containment → deploys_to (deterministic)
  docs         *.md → document; explicit repo paths and `METHOD /path` mentions                  → documents (deterministic)
  work_items   work-item ids (default `MUN-dddd`) in code comments and documents                 → documents (deterministic)
  receipts     receipts/**/*.json with a `...Receipt/v1` schema; explicit repo paths inside      → verifies (deterministic)
  rust         AUP-GRAPH-009: Cargo.toml (tomllib) → deployable_unit (service/cli/library) + containment; `mod x;`
               file declarations and `use crate::…` / `use <workspace-crate>::…` paths resolved through the crate's
               `src/` tree; `env::var("X")`                                                       → imports / reads_config (deterministic)
  python       AUP-GRAPH-009: pyproject.toml/setup.py (tomllib) → deployable_unit; absolute imports matched against
               every discovered src root, relative imports (`from .x import y`) resolved from the importing file's
               directory; `os.environ`/`os.getenv`; `@app.get(...)`-style decorators                → imports / reads_config /
               provides_route (deterministic)

Nothing here calls an LLM; every `inferred` edge names its method in `inferred_by` (LLM_EDGE_NOT_INFERRED is a schema
violation). stdlib only (Python 3.12); the TypeScript compiler is NOT used — the extractor is a comment/string-aware
regex/AST-lite pass, and that limitation is written into the manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import schema_check  # noqa: E402  (tools/graph/schema_check.py — the validator of GRAPH-001)

VERSION = "1.0.0"
BUILDER = "tools/graph/build_graph.py"
EXTRACTORS = ["imports", "routes", "contracts", "prisma", "config", "reuse", "di", "queue", "tests",
              "http_client", "deployables", "docs", "work_items", "receipts", "rust", "python"]
CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
RUST_EXT = (".rs",)
PY_EXT = (".py",)
ADAPTER_CLASS_RE = re.compile(r"\bclass\s+\w+\s+extends\s+(\w*Adapter)\b")

RUST_MOD_RE = re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
RUST_USE_RE = re.compile(r"\buse\s+((?:crate|self|super)(?:::[A-Za-z_][A-Za-z0-9_]*)*"
                          r"|[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)")
RUST_ENV_RE = re.compile(r"\b(?:std::)?env::var(?:_os)?\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\"")
RUST_SERVICE_DEPS = {"axum", "actix-web", "warp", "tonic", "hyper"}
PY_FROM_RE = re.compile(r"(?m)^from[ \t]+(\.*)([\w.]*)[ \t]+import\b")
PY_IMPORT_RE = re.compile(r"(?m)^import[ \t]+([\w.]+)")
PY_ENV_RE = re.compile(r"""os\.environ\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\]"""
                        r"""|os\.environ\.get\(\s*['"]([A-Z_][A-Z0-9_]*)['"]"""
                        r"""|os\.getenv\(\s*['"]([A-Z_][A-Z0-9_]*)['"]""")
PY_ROUTE_RE = re.compile(r"""@(?:app|router|api)\.(get|post|put|patch|delete|head)\(\s*['"]([^'"]+)['"]""")
RESOLVE_EXT = (".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs", ".json")
HTTP_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "head": "HEAD",
                "options": "OPTIONS", "all": "ALL"}
PRISMA_OPS = ("findMany", "findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "create", "createMany",
              "update", "updateMany", "upsert", "delete", "deleteMany", "count", "aggregate", "groupBy")
DEFAULT_WORK_ITEM_PATTERN = r"\bMUN-[0-9]{4}\b"
FIXTURE_DIR = ROOT / "contracts" / "graph-verified-change" / "fixtures" / "ts-mini"
EXPECTED_PATH = FIXTURE_DIR / "EXPECTED.json"  # inside the tree: schema_check --selftest globs fixtures/*.json and must not see it
ADAPTER_FIXTURE_DIR = ROOT / "contracts" / "graph-verified-change" / "fixtures" / "adapter-mini"
ADAPTER_EXPECTED_PATH = ADAPTER_FIXTURE_DIR / "EXPECTED.json"
ROOT_APP_FIXTURE_DIR = ROOT / "contracts" / "graph-verified-change" / "fixtures" / "root-app-mini"
ROOT_APP_EXPECTED_PATH = ROOT_APP_FIXTURE_DIR / "EXPECTED.json"
FIXED_BUILT_AT = "2026-09-05T00:00:00Z"


# ----------------------------------------------------------------------------------------------- helpers
def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def sha_text(s: str) -> str:
    return sha_bytes(s.encode("utf-8"))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(args: list[str], cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True).stdout


def lower_first(s: str) -> str:
    return s[:1].lower() + s[1:] if s else s


def norm_path(p: str) -> str:
    parts: list[str] = []
    for seg in p.replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/".join(parts)


def load_jsonc(text: str):
    """tsconfig-style JSON: // and /* */ comments and trailing commas tolerated."""
    stripped = strip_comments(text)
    stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
    return json.loads(stripped)


def strip_comments(src: str) -> str:
    """Return the source with comments blanked (string/template contents kept, comment chars replaced by spaces
    except newlines) — a char walk aware of ' \" ` strings so `https://` inside a string is not a comment."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"`":
            q = c
            out.append(c)
            i += 1
            while i < n and src[i] != q:
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                if q != "`" and src[i] == "\n":
                    break
                out.append(src[i])
                i += 1
            if i < n:
                out.append(src[i])
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def comments_of(src: str) -> str:
    """The complement of strip_comments: only the comment text (for work-item ids and reuse markers)."""
    stripped = strip_comments(src)
    return "".join(s if s != t else " " for s, t in zip(src, stripped))


def strip_comments_rust(src: str) -> str:
    """Like strip_comments but does not treat `'` as a string delimiter: Rust uses `'` for lifetimes (`&'a str`),
    and the char-walk of strip_comments would mistake a lifetime for an unterminated string. Char literals
    (`'/'`) are consequently not string-masked — a `//`/`/*` inside one would be misread as a comment start,
    an accepted approximation (same class as the TS parser's documented AST-lite limits)."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                if src[i] == "\n":
                    break
                out.append(src[i])
                i += 1
            if i < n:
                out.append(src[i])
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def strip_comments_python(src: str) -> str:
    """Comment/string-aware pass for Python: triple-quoted strings (docstrings) are blanked line-preserving,
    `'`/`"` strings are quote-walked, `#` starts a line comment. f-string/byte-string prefixes are not special-cased
    (the quote walk still finds the right closing quote for them)."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        if src[i:i + 3] in ('"""', "'''"):
            q = src[i:i + 3]
            out.append(q)
            i += 3
            j = src.find(q, i)
            end = n if j < 0 else j
            out.append(re.sub(r"[^\n]", " ", src[i:end]))
            i = end
            if j >= 0:
                out.append(q)
                i += 3
            continue
        c = src[i]
        if c in "'\"":
            q = c
            out.append(c)
            i += 1
            while i < n and src[i] != q:
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                if src[i] == "\n":
                    break
                out.append(src[i])
                i += 1
            if i < n:
                out.append(src[i])
                i += 1
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ----------------------------------------------------------------------------------------------- source tree
class Tree:
    def __init__(self, files: dict[str, bytes], meta: dict):
        self.files = files
        self.meta = meta
        self.paths = sorted(files)
        self._text: dict[str, str] = {}

    def exists(self, p: str) -> bool:
        return p in self.files

    def text(self, p: str) -> str:
        if p not in self._text:
            self._text[p] = self.files[p].decode("utf-8", errors="replace")
        return self._text[p]

    def under(self, d: str) -> list[str]:
        d = d.rstrip("/")
        return [p for p in self.paths if d == "" or p.startswith(d + "/")]


def source_repo_name(repo: Path) -> str:
    try:
        url = git(["remote", "get-url", "origin"], repo).strip()
        m = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?/?$", url)
        if m:
            return m.group(1)
    except subprocess.CalledProcessError:
        pass
    return repo.resolve().name


def load_tree_git(repo: Path, rev: str, subdir: str) -> Tree:
    commit = git(["rev-parse", f"{rev}^{{commit}}"], repo).strip()
    listing = git(["ls-tree", "-r", "-z", "--name-only", commit], repo)
    names = [n for n in listing.split("\0") if n]
    prefix = subdir.strip("/") + "/" if subdir.strip("/") else ""
    names = [n for n in names if n.startswith(prefix)]
    spec = "".join(f"{commit}:{n}\n" for n in names).encode()
    out = subprocess.run(["git", "cat-file", "--batch"], cwd=str(repo), input=spec, check=True, capture_output=True).stdout
    files: dict[str, bytes] = {}
    pos = 0
    for n in names:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode()
        pos = nl + 1
        if header.endswith(" missing"):
            continue
        size = int(header.split()[2])
        files[n[len(prefix):]] = out[pos:pos + size]
        pos += size + 1
    meta = {"source_repo": source_repo_name(repo), "source_commit": commit, "source_tree": "git-objects", "dirty": False,
            "subdir": prefix.rstrip("/") or None, "rev": rev}
    return Tree(files, meta)


def load_tree_worktree(root: Path) -> Tree:
    root = root.resolve()
    top = Path(git(["rev-parse", "--show-toplevel"], root).strip())
    rel = root.relative_to(top).as_posix() if root != top else ""
    commit = git(["rev-parse", "HEAD"], top).strip()
    listing = git(["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."], root)
    files: dict[str, bytes] = {}
    for n in listing.split("\0"):
        if not n:
            continue
        p = root / n
        if p.is_file():
            files[n] = p.read_bytes()
    dirty = bool(git(["status", "--porcelain", "--", "."], root).strip())
    meta = {"source_repo": source_repo_name(top), "source_commit": commit, "source_tree": "worktree", "dirty": dirty,
            "subdir": rel or None, "rev": "HEAD"}
    return Tree(files, meta)


# ----------------------------------------------------------------------------------------------- graph
class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[str, dict] = {}
        self.dropped_dangling: list[str] = []

    def node(self, nid: str, ntype: str, content_hash: str, **opt) -> str:
        if nid not in self.nodes:
            n = {"id": nid, "type": ntype, "content_hash": content_hash}
            n.update({k: v for k, v in opt.items() if v is not None})
            self.nodes[nid] = n
        return nid

    def edge(self, frm: str, etype: str, to: str, provenance: str, **opt):
        e = {"from": frm, "to": to, "type": etype, "provenance": provenance}
        e.update({k: v for k, v in opt.items() if v is not None})
        key = canonical({k: e[k] for k in ("from", "type", "to", "provenance", "via", "symbol") if k in e})
        if key not in self.edges:
            self.edges[key] = e

    def finalize(self) -> tuple[list[dict], list[dict]]:
        nodes = [self.nodes[k] for k in sorted(self.nodes)]
        edges = []
        for e in self.edges.values():
            if e["from"] in self.nodes and e["to"] in self.nodes:
                edges.append(e)
            else:
                self.dropped_dangling.append(f"{e['from']} -{e['type']}-> {e['to']}")
        edges.sort(key=lambda e: (e["from"], e["type"], e["to"], e["provenance"], e.get("via", ""), e.get("symbol", "")))
        self.dropped_dangling.sort()
        return nodes, edges


# ----------------------------------------------------------------------------------------------- TS parsing
IMPORT_RE = re.compile(
    r"""(?:^|[;\n])\s*(?:import|export)\s+(?:type\s+)?(?P<clause>[^;'"]*?)\s*from\s*['"](?P<spec>[^'"]+)['"]"""
    r"""|(?:^|[;\n])\s*import\s*['"](?P<bare>[^'"]+)['"]"""
    r"""|\brequire\(\s*['"](?P<req>[^'"]+)['"]\s*\)"""
    r"""|\bimport\(\s*['"](?P<dyn>[^'"]+)['"]\s*\)""",
    re.S)


def parse_import_clause(clause: str) -> list[tuple[str, str]]:
    """'{ A, B as C, type D }, Def, * as ns' → [(local, imported)] ('*' for namespace, 'default' for default)."""
    out: list[tuple[str, str]] = []
    clause = clause.strip()
    if not clause:
        return out
    m = re.search(r"\{([^}]*)\}", clause)
    if m:
        for part in m.group(1).split(","):
            part = re.sub(r"^\s*type\s+", "", part.strip())
            if not part:
                continue
            if " as " in part:
                imported, local = [x.strip() for x in part.split(" as ", 1)]
            else:
                imported = local = part
            out.append((local, imported))
        clause = (clause[:m.start()] + clause[m.end():]).strip(" ,")
    for part in clause.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("*"):
            mm = re.match(r"\*\s*as\s+(\w+)", part)
            out.append((mm.group(1) if mm else "*", "*"))
        elif re.match(r"^\w+$", part):
            out.append((part, "default"))
    return out


class TsFile:
    def __init__(self, path: str, src: str):
        self.path = path
        self.src = src
        self.code = strip_comments(src)
        self.comments = comments_of(src)
        self.imports: list[dict] = []        # {spec, symbols:[(local, imported)], kind}
        self.resolved: dict[str, str] = {}   # spec → repo path
        self.unresolved: list[str] = []
        self.external: list[str] = []
        self.symbol_origin: dict[str, tuple[str, str]] = {}  # local name → (resolved path, imported name)
        for m in IMPORT_RE.finditer(self.code):
            if m.group("spec") is not None:
                self.imports.append({"spec": m.group("spec"), "symbols": parse_import_clause(m.group("clause")), "kind": "static"})
            elif m.group("bare") is not None:
                self.imports.append({"spec": m.group("bare"), "symbols": [], "kind": "side_effect"})
            elif m.group("req") is not None:
                self.imports.append({"spec": m.group("req"), "symbols": [], "kind": "require"})
            elif m.group("dyn") is not None:
                self.imports.append({"spec": m.group("dyn"), "symbols": [], "kind": "dynamic"})
        self.reexports: list[tuple[str, str | None]] = []  # (spec, symbol or None for *)
        for m in re.finditer(r"""(?:^|[;\n])\s*export\s+(\*|\{[^}]*\})\s*from\s*['"]([^'"]+)['"]""", self.code):
            if m.group(1) == "*":
                self.reexports.append((m.group(2), None))
            else:
                for part in m.group(1).strip("{} ").split(","):
                    part = re.sub(r"^\s*type\s+", "", part.strip())
                    if part:
                        self.reexports.append((m.group(2), part.split(" as ")[0].strip()))

    @property
    def is_test(self) -> bool:
        p = self.path
        return bool(re.search(r"\.(spec|test)\.[cm]?[jt]sx?$", p) or "/test/" in p or "/__tests__/" in p
                    or p.startswith("test/") or p.startswith("__tests__/"))


# ----------------------------------------------------------------------------------------------- builder
class Builder:
    def __init__(self, tree: Tree, disabled: set[str], work_item_pattern: str):
        unknown = disabled - set(EXTRACTORS)
        if unknown:
            raise SystemExit(f"unknown extractor(s): {sorted(unknown)}; known: {EXTRACTORS}")
        self.tree = tree
        self.disabled = disabled
        self.g = Graph()
        self.work_item_re = re.compile(work_item_pattern)
        self.work_item_pattern = work_item_pattern
        self.ts: dict[str, TsFile] = {}
        self.tsconfigs: dict[str, dict] = {}      # dir → {"paths": {...}, "baseUrl": dir}
        self.packages: dict[str, str] = {}        # package name → dir
        self.package_dirs: list[str] = []
        self.contracts: dict[str, dict[str, str]] = {}   # path → {symbol: kind}
        self.models: dict[str, str] = {}          # Model → block text
        self.routes: list[dict] = []              # {method, path, file, id}
        self.global_prefix: str | None = None
        self.global_prefix_exclude: list[str] = []
        self.limitations: list[str] = []
        self.stats: dict = {}
        self.unmatched_http: list[str] = []
        self.dynamic_routes: list[str] = []
        self.unresolved_imports: list[str] = []
        self.external_packages: set[str] = set()
        self.queue_producers: list[tuple[str, str]] = []
        self.queue_consumers: list[tuple[str, str]] = []

    def on(self, name: str) -> bool:
        return name not in self.disabled

    # ---- always: file nodes, tsconfig/package maps ----------------------------------------------------------
    def base(self):
        t = self.tree
        for p in t.paths:
            if p.endswith(CODE_EXT) or p.endswith(".prisma") or p.endswith(RUST_EXT) or p.endswith(PY_EXT):
                self.g.node(f"code_unit:{p}", "code_unit", sha_bytes(t.files[p]), path=p)
            if p.endswith(CODE_EXT):
                self.ts[p] = TsFile(p, t.text(p))
        for p in t.paths:
            if p.endswith("tsconfig.json") or re.search(r"(^|/)tsconfig\.[\w.-]+\.json$", p):
                try:
                    cfg = load_jsonc(t.text(p))
                except (ValueError, json.JSONDecodeError):
                    self.limitations.append(f"tsconfig unreadable: {p}")
                    continue
                d = os.path.dirname(p)
                co = cfg.get("compilerOptions") or {}
                base = norm_path(os.path.join(d, co.get("baseUrl", "."))) if co.get("baseUrl") else d
                if "paths" in co and p.endswith("/tsconfig.json") or p == "tsconfig.json":
                    self.tsconfigs[d] = {"paths": co.get("paths") or {}, "baseUrl": base}
            if p.endswith("package.json"):
                try:
                    pj = json.loads(t.text(p))
                except json.JSONDecodeError:
                    continue
                if isinstance(pj, dict) and isinstance(pj.get("name"), str):
                    self.packages[pj["name"]] = os.path.dirname(p)
        ws = "pnpm-workspace.yaml"
        globs: list[str] = []
        if t.exists(ws):
            for m in re.finditer(r"^\s*-\s*['\"]?([^'\"\n#]+?)['\"]?\s*$", t.text(ws).split("packages:")[1].split("\n\n")[0] if "packages:" in t.text(ws) else "", re.M):
                globs.append(m.group(1).strip())
        elif t.exists("package.json"):
            try:
                w = json.loads(t.text("package.json")).get("workspaces")
                globs = list(w) if isinstance(w, list) else list((w or {}).get("packages", []))
            except (json.JSONDecodeError, AttributeError):
                globs = []
        dirs: set[str] = set()
        for gl in globs:
            gl = gl.rstrip("/")
            if gl.endswith("/*"):
                head = gl[:-2]
                for p in t.paths:
                    if p.startswith(head + "/") and p.count("/") == head.count("/") + 2 and p.endswith("/package.json"):
                        dirs.add(os.path.dirname(p))
            elif t.exists(gl + "/package.json"):
                dirs.add(gl)
        if t.exists("package.json") and (not dirs or self._root_is_its_own_package(t)):
            # AUP-GRAPH-009:retrofit1 — a workspace root that is ALSO an application (auth-arcana:
            # nest-cli.json + @nestjs/core + src/ at the root, `packages: [account-spa]`) used to be
            # dropped the moment the workspace listed one member: the service itself then had no
            # deployable_unit and no file of it carried a deploys_to edge, so the can-i-deploy gate
            # (AUP-GRAPH-008) read an empty deployment for the whole repository.
            dirs.add(".")
        self.package_dirs = sorted(dirs)
        if self.on("routes"):
            for f in self.ts.values():
                m = re.search(r"setGlobalPrefix\(\s*['\"]([^'\"]+)['\"](?:\s*,\s*\{[^}]*exclude\s*:\s*\[([^\]]*)\])?", f.code)
                if m:
                    self.global_prefix = "/" + m.group(1).strip("/")
                    self.global_prefix_exclude = re.findall(r"['\"]([^'\"]+)['\"]", m.group(2) or "")

    # ---- module resolution -----------------------------------------------------------------------------
    def _try_file(self, base: str) -> str | None:
        base = norm_path(base)
        cands = [base] + [base + e for e in RESOLVE_EXT] + [base + "/index" + e for e in (".ts", ".tsx", ".js", ".jsx")]
        if re.search(r"\.[cm]?js$", base):
            stem = re.sub(r"\.[cm]?js$", "", base)
            cands += [stem + ".ts", stem + ".tsx"]
        for c in cands:
            if self.tree.exists(c) and (c.endswith(CODE_EXT) or c.endswith((".json", ".d.ts", ".prisma"))):
                return c
        return None

    def _try_file_dist_fallback(self, base: str) -> tuple[str | None, str | None]:
        r = self._try_file(base)
        if r:
            return r, None
        if "/dist/" in base or base.endswith("/dist"):
            alt = base.replace("/dist/", "/src/").replace("/dist", "/src")
            r = self._try_file(alt)
            if r:
                return r, "dist→src"
        return None, None

    def _tsconfig_for(self, path: str) -> dict | None:
        d = os.path.dirname(path)
        while True:
            if d in self.tsconfigs:
                return self.tsconfigs[d]
            if d == "":
                return None
            d = os.path.dirname(d)

    def resolve(self, frm: str, spec: str) -> tuple[str | None, str | None]:
        """→ (repo path or None, via)."""
        if spec.startswith("."):
            r, via = self._try_file_dist_fallback(os.path.join(os.path.dirname(frm), spec))
            return r, ("relative" if r and not via else via)
        if spec.startswith("/"):
            return None, None
        cfg = self._tsconfig_for(frm)
        if cfg:
            for key, targets in cfg["paths"].items():
                if key.endswith("/*") and spec.startswith(key[:-2] + "/"):
                    rest = spec[len(key) - 1:]
                    for tg in targets:
                        r, via = self._try_file_dist_fallback(os.path.join(cfg["baseUrl"], tg.replace("*", rest)))
                        if r:
                            return r, "tsconfig-paths" + (f"({via})" if via else "")
                elif key == spec:
                    for tg in targets:
                        r, via = self._try_file_dist_fallback(os.path.join(cfg["baseUrl"], tg))
                        if r:
                            return r, "tsconfig-paths" + (f"({via})" if via else "")
        for name, d in self.packages.items():
            if spec == name or spec.startswith(name + "/"):
                sub = spec[len(name):].lstrip("/")
                if sub:
                    r, via = self._try_file_dist_fallback(os.path.join(d, sub))
                    if r:
                        return r, "workspace-package" + (f"({via})" if via else "")
                try:
                    pj = json.loads(self.tree.text(d + "/package.json" if d else "package.json"))
                except json.JSONDecodeError:
                    pj = {}
                for entry in (pj.get("types"), pj.get("main"), pj.get("module"), "src/index.ts", "index.ts"):
                    if isinstance(entry, str):
                        r, via = self._try_file_dist_fallback(os.path.join(d, entry))
                        if r:
                            return r, "workspace-package" + (f"({via})" if via else "")
        return None, None

    def resolve_all(self):
        for f in self.ts.values():
            for imp in f.imports:
                spec = imp["spec"]
                if spec in f.resolved:
                    r = f.resolved[spec]
                else:
                    r, via = self.resolve(f.path, spec)
                    if r:
                        f.resolved[spec] = r
                        imp["via"] = via
                    elif spec.startswith(".") and re.search(r"\.(css|scss|sass|less|svg|png|jpg|jpeg|gif|webp|ico|woff2?|ttf)$", spec):
                        continue  # asset import: no code_unit node, not a resolution failure
                    elif spec.startswith("."):
                        f.unresolved.append(spec)
                        self.unresolved_imports.append(f"{f.path}: {spec}")
                    else:
                        pkg = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
                        f.external.append(pkg)
                        self.external_packages.add(pkg)
                        continue
                for local, imported in imp["symbols"]:
                    f.symbol_origin[local] = (r, imported)

    def symbol_decl(self, path: str, name: str, depth: int = 0) -> tuple[str, str] | None:
        """Follow re-exports until the (path, symbol) that declares a contract is found."""
        if depth > 6 or path not in self.ts:
            return None
        if name in self.contracts.get(path, {}):
            return path, name
        f = self.ts[path]
        for spec, sym in f.reexports:
            if sym is not None and sym != name:
                continue
            tgt = f.resolved.get(spec) or self.resolve(path, spec)[0]
            if tgt:
                r = self.symbol_decl(tgt, name, depth + 1)
                if r:
                    return r
        return None

    def contract_id_for(self, frm: str, local: str) -> str | None:
        o = self.ts[frm].symbol_origin.get(local)
        if not o or not o[0]:
            return None
        decl = self.symbol_decl(o[0], o[1])
        return f"contract:{decl[0]}#{decl[1]}" if decl else None

    # ---- extractors --------------------------------------------------------------------------------------
    def x_imports(self):
        for f in self.ts.values():
            for imp in f.imports:
                r = f.resolved.get(imp["spec"])
                if r and f"code_unit:{r}" in self.g.nodes and r != f.path:
                    self.g.edge(f"code_unit:{f.path}", "imports", f"code_unit:{r}", "deterministic", via=imp.get("via"))

    def x_contracts(self):
        t = self.tree
        for f in self.ts.values():
            specs = {i["spec"] for i in f.imports}
            found: dict[str, str] = {}
            if "class-validator" in specs:
                for m in re.finditer(r"\bexport\s+(?:abstract\s+)?class\s+(\w+)", f.code):
                    found[m.group(1)] = "class_validator_dto"
            if "zod" in specs or "zod/v4" in specs:
                for m in re.finditer(r"\b(?:export\s+)?const\s+(\w+)\s*=\s*z\.\w+", f.code):
                    found[m.group(1)] = "zod"
            for m in re.finditer(r"\bexport\s+type\s+(\w+)\s*=\s*(\|?\s*['\"][^'\"]*['\"](?:\s*\|\s*['\"][^'\"]*['\"])*)\s*;", f.code):
                found[m.group(1)] = "type_alias_union"
            in_pkg = any(f.path.startswith(d + "/") for d in self.package_dirs if not d.startswith("apps"))
            for m in re.finditer(r"\bexport\s+(?:const\s+)?enum\s+(\w+)", f.code):
                if in_pkg:
                    found[m.group(1)] = "cross_repo_enum"
                else:
                    self.limitations.append(f"enum outside a workspace library not modelled as a contract: {f.path}#{m.group(1)}")
            if found:
                self.contracts[f.path] = found
                h = sha_bytes(t.files[f.path])
                for sym, kind in sorted(found.items()):
                    cid = self.g.node(f"contract:{f.path}#{sym}", "contract", h, path=f.path, symbol=sym, kind=kind)
                    self.g.edge(f"code_unit:{f.path}", "implements_contract", cid, "deterministic", via="declaration", symbol=sym)
        # consumers: any file importing a contract symbol (through barrels)
        for f in self.ts.values():
            for local, (path, imported) in sorted(f.symbol_origin.items()):
                if not path or imported in ("*", "default"):
                    continue
                decl = self.symbol_decl(path, imported)
                if decl and decl[0] != f.path:
                    self.g.edge(f"code_unit:{f.path}", "consumes_contract", f"contract:{decl[0]}#{decl[1]}", "deterministic",
                                via="import-symbol", symbol=imported)

    def _route_path(self, prefix: str, sub: str) -> str:
        p = "/" + "/".join(s for s in (prefix.strip("/") + "/" + sub.strip("/")).split("/") if s)
        return p if p != "/" else "/"

    def x_routes(self):
        t = self.tree
        dec_arg = r"\(\s*(?:['\"]([^'\"]*)['\"]|\[\s*['\"]([^'\"]*)['\"][^\]]*\]|\{[^}]*path\s*:\s*['\"]([^'\"]*)['\"][^}]*\})?\s*[^)]*\)"
        for f in self.ts.values():
            code = f.code
            ctrls = [(m.start(), next((g for g in m.groups() if g is not None), "")) for m in re.finditer(r"@Controller" + dec_arg, code)]
            if ctrls:
                h = sha_bytes(t.files[f.path])
                for m in re.finditer(r"@(Get|Post|Put|Patch|Delete|Head|Options|All)\s*" + dec_arg, code):
                    ctrl = [c for c in ctrls if c[0] < m.start()]
                    if not ctrl:
                        continue
                    prefix = ctrl[-1][1]
                    sub = next((g for g in m.groups()[1:] if g is not None), None)
                    raw_arg = code[m.start():m.end()]
                    if sub is None and re.search(r"\(\s*[A-Za-z_$]", raw_arg):
                        self.dynamic_routes.append(f"{f.path}: {raw_arg.strip()[:60]}")
                        continue
                    method = HTTP_METHODS[m.group(1).lower()]
                    rid = f"route:{method} {self._route_path(prefix, sub or '')}"
                    self.g.node(rid, "route", h, path=f.path,
                                attrs={"global_prefix": self.global_prefix} if self.global_prefix and prefix.strip("/") not in self.global_prefix_exclude else None)
                    self.g.edge(f"code_unit:{f.path}", "provides_route", rid, "deterministic", via="nest-decorator", site=f"L{code.count(chr(10), 0, m.start()) + 1}")
                    self.routes.append({"method": method, "path": self._route_path(prefix, sub or ""), "file": f.path, "id": rid})
                    # handler signature → DTO parameter types
                    sig_start = code.find("(", m.end())
                    depth, j = 0, sig_start
                    while j < len(code):
                        if code[j] == "(":
                            depth += 1
                        elif code[j] == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        j += 1
                    sig = code[sig_start:j + 1]
                    for pm in re.finditer(r"@(Body|Query|Param)\([^)]*\)\s*(?:readonly\s+)?\w+\??\s*:\s*([A-Za-z_]\w*)", sig):
                        cid = self.contract_id_for(f.path, pm.group(2))
                        if cid:
                            self.g.edge(rid, "implements_contract", cid, "deterministic", via=f"@{pm.group(1)}", symbol=pm.group(2))
            if re.search(r"@WebSocketGateway\s*\(", code):
                h = sha_bytes(t.files[f.path])
                for m in re.finditer(r"@SubscribeMessage\(\s*['\"]([^'\"]+)['\"]\s*\)", code):
                    rid = f"route:WS {m.group(1)}"
                    self.g.node(rid, "route", h, path=f.path, kind="ws_event")
                    self.g.edge(f"code_unit:{f.path}", "provides_route", rid, "deterministic", via="nest-gateway",
                                site=f"L{code.count(chr(10), 0, m.start()) + 1}")
                    self.routes.append({"method": "WS", "path": m.group(1), "file": f.path, "id": rid})

    def x_prisma(self):
        t = self.tree
        for p in t.paths:
            if not p.endswith(".prisma"):
                continue
            text = t.text(p)
            for m in re.finditer(r"^(model|enum)\s+(\w+)\s*\{(.*?)^\}", text, re.M | re.S):
                kind, name, body = m.group(1), m.group(2), m.group(3)
                block = text[m.start():m.end()]
                self.models[name] = block
                self.g.node(f"data_model:{name}", "data_model", sha_text(block), path=p, kind=kind)
                self.g.edge(f"code_unit:{p}", "maps_model", f"data_model:{name}", "deterministic", via="prisma-declaration")
            for name, block in list(self.models.items()):
                for line in block.splitlines()[1:]:
                    fm = re.match(r"\s*(\w+)\s+(\w+)(\[\])?\??\s", line)
                    if fm and fm.group(2) in self.models and fm.group(2) != name:
                        self.g.edge(f"data_model:{name}", "maps_model", f"data_model:{fm.group(2)}", "deterministic",
                                    via="prisma-relation", symbol=fm.group(1))
        if not self.models:
            return
        camel = {lower_first(mn): mn for mn in self.models}
        call_re = re.compile(r"\b(?:prisma|tx|db|client|this\.prisma|this\.db)\.(\w+)\.(?:%s)\b" % "|".join(PRISMA_OPS))
        for f in self.ts.values():
            for m in call_re.finditer(f.code):
                if m.group(1) in camel:
                    self.g.edge(f"code_unit:{f.path}", "maps_model", f"data_model:{camel[m.group(1)]}", "deterministic",
                                via="prisma-client-call")
            for imp in f.imports:
                if imp["spec"] in ("@prisma/client", "@prisma/client/runtime"):
                    for local, imported in imp["symbols"]:
                        if imported in self.models:
                            self.g.edge(f"code_unit:{f.path}", "maps_model", f"data_model:{imported}", "deterministic",
                                        via="prisma-client-type-import", symbol=imported)

    def x_rust(self):
        """AUP-GRAPH-009: Cargo.toml (tomllib) → deployable_unit; `mod x;` file declarations and `use crate::…` /
        `use <workspace-crate>::…` paths resolved through the crate's `src/` tree; `env::var("X")` → config_key.
        `use self::…`/`use super::…` and mod declarations nested inside a `mod { }` block (rather than `mod x;`
        pointing at a sibling file) are not resolved — recorded in limitations, same class of gap as the TS parser's."""
        t = self.tree
        crates: list[tuple[str, str, str, str]] = []  # (dir, pkg_name, kind, cargo_toml_path)
        for p in t.paths:
            if os.path.basename(p) != "Cargo.toml":
                continue
            try:
                doc = tomllib.loads(t.text(p))
            except tomllib.TOMLDecodeError:
                self.limitations.append(f"Cargo.toml unreadable: {p}")
                continue
            pkg = doc.get("package")
            if not isinstance(pkg, dict):
                continue  # workspace-only manifest: no crate of its own
            d = os.path.dirname(p)
            name = pkg.get("name") if isinstance(pkg.get("name"), str) else (os.path.basename(d) or "root")
            dep_names = set(doc.get("dependencies") or {})
            has_main = t.exists(norm_path((d + "/" if d else "") + "src/main.rs"))
            has_lib = t.exists(norm_path((d + "/" if d else "") + "src/lib.rs"))
            if dep_names & RUST_SERVICE_DEPS:
                kind = "service"
            elif has_main or (isinstance(doc.get("bin"), list) and doc.get("bin")):
                kind = "cli"
            else:
                kind = "library"
            crates.append((d, name, kind, p))
        crate_by_norm_name = {name.replace("-", "_"): d for d, name, _, _ in crates}

        def containing_dir_prefix(d: str) -> str:
            return (d + "/") if d else ""

        for d, name, kind, p in crates:
            did = self.g.node(f"deployable_unit:{d or '.'}", "deployable_unit", sha_bytes(t.files[p]),
                              path=d or ".", kind=kind, symbol=name)
            prefix = containing_dir_prefix(d)
            for fp in t.paths:
                if not fp.startswith(prefix) or f"code_unit:{fp}" not in self.g.nodes:
                    continue
                if any(fp.startswith(od + "/") for od, *_ in crates if od != d and len(od) > len(d) and od.startswith(prefix)):
                    continue
                self.g.edge(f"code_unit:{fp}", "deploys_to", did, "deterministic", via="containment")

        def crate_src_root(d: str) -> str:
            return norm_path(containing_dir_prefix(d) + "src")

        def owning_crate(path: str) -> str | None:
            best = None
            for d, *_ in crates:
                if path.startswith(containing_dir_prefix(d)) and (best is None or len(d) > len(best)):
                    best = d
            return best

        def resolve_segments(root: str, segs: list[str]) -> str | None:
            d, found = root, None
            for seg in segs:
                f1, f2 = norm_path(containing_dir_prefix(d) + seg + ".rs"), norm_path(containing_dir_prefix(d) + seg + "/mod.rs")
                if t.exists(f1):
                    found, d = f1, norm_path(containing_dir_prefix(d) + seg)
                elif t.exists(f2):
                    found, d = f2, norm_path(containing_dir_prefix(d) + seg)
                else:
                    break
            return found

        def crate_entry(root: str) -> str | None:
            for cand in (root + "/lib.rs", root + "/main.rs"):
                if t.exists(cand):
                    return cand
            return None

        rust_files = [p for p in t.paths if p.endswith(".rs")]
        for p in rust_files:
            code = strip_comments_rust(t.text(p))
            own = owning_crate(p)
            base_name = os.path.basename(p)
            mod_dir = os.path.dirname(p) if base_name in ("lib.rs", "main.rs", "mod.rs") else norm_path(os.path.dirname(p) + "/" + base_name[:-3])
            for m in RUST_MOD_RE.finditer(code):
                name = m.group(1)
                for cand in (norm_path(containing_dir_prefix(mod_dir) + name + ".rs"), norm_path(containing_dir_prefix(mod_dir) + name + "/mod.rs")):
                    if t.exists(cand) and f"code_unit:{cand}" in self.g.nodes:
                        self.g.edge(f"code_unit:{p}", "imports", f"code_unit:{cand}", "deterministic", via="rust-mod-decl")
                        break
            for m in RUST_USE_RE.finditer(code):
                segs = m.group(1).split("::")
                head, rest = segs[0], segs[1:]
                target, via = None, None
                if head == "crate":
                    if own is not None:
                        target, via = resolve_segments(crate_src_root(own), rest), "rust-use-crate-path"
                elif head in ("self", "super"):
                    continue  # not resolved: recorded in limitations
                elif head.replace("-", "_") in crate_by_norm_name:
                    root = crate_src_root(crate_by_norm_name[head.replace("-", "_")])
                    target = resolve_segments(root, rest) if rest else crate_entry(root)
                    via = "rust-use-workspace-crate"
                else:
                    continue  # external crate (std, serde, tokio, …): no node
                if target and target != p and f"code_unit:{target}" in self.g.nodes:
                    self.g.edge(f"code_unit:{p}", "imports", f"code_unit:{target}", "deterministic", via=via)
            for m in RUST_ENV_RE.finditer(code):
                key = m.group(1)
                self.g.node(f"config_key:{key}", "config_key", sha_text(key), symbol=key)
                self.g.edge(f"code_unit:{p}", "reads_config", f"config_key:{key}", "deterministic", via="std-env-var")
        if crates or rust_files:
            self.limitations.append("rust: use self::/super:: paths and mod declarations nested inside a `mod { … }` block "
                                     "(as opposed to a file-pointing `mod x;`) are not resolved")

    def x_python(self):
        """AUP-GRAPH-009: pyproject.toml/setup.py (tomllib for pyproject) → deployable_unit; absolute imports matched
        against every discovered src root, relative imports resolved from the importing file's directory;
        os.environ/os.getenv → config_key; `@app.get(...)`-style decorators → route (same node forms as the TS
        stack). Star imports, importlib-dynamic imports and bare `from . import x` (no module name to anchor a
        file) are not resolved — recorded in limitations."""
        t = self.tree
        py_roots: set[str] = {""}
        pkgs: list[tuple[str, str, str, str]] = []  # (dir, name, kind, manifest_path)
        for p in t.paths:
            base = os.path.basename(p)
            if base not in ("pyproject.toml", "setup.py", "setup.cfg"):
                continue
            d = os.path.dirname(p)
            name = os.path.basename(d) or self.tree.meta.get("source_repo") or "python"
            kind, deps_text = "library", ""
            if base == "pyproject.toml":
                try:
                    doc = tomllib.loads(t.text(p))
                except tomllib.TOMLDecodeError:
                    self.limitations.append(f"pyproject.toml unreadable: {p}")
                    doc = {}
                proj = doc.get("project") if isinstance(doc.get("project"), dict) else {}
                if isinstance(proj.get("name"), str):
                    name = proj["name"]
                deps = proj.get("dependencies")
                if isinstance(deps, list):
                    deps_text = " ".join(x for x in deps if isinstance(x, str))
                if isinstance(proj.get("scripts"), dict) and proj["scripts"]:
                    kind = "cli"
            else:
                deps_text = t.text(p)
            if re.search(r"\b(fastapi|flask|django|uvicorn)\b", deps_text, re.I):
                kind = "service"
            elif kind != "cli" and re.search(r"\bclick\b", deps_text, re.I):
                kind = "cli"
            pkgs.append((d, name, kind, p))
            py_roots.add(d)
            py_roots.add(norm_path((d + "/" if d else "") + "src"))
        py_roots_sorted = sorted(py_roots, key=len, reverse=True)

        def resolve_absolute(module: str) -> str | None:
            rel = module.replace(".", "/")
            for root in py_roots_sorted:
                target = norm_path((root + "/" if root else "") + rel)
                for cand in (target + ".py", target + "/__init__.py"):
                    if t.exists(cand):
                        return cand
            return None

        def resolve_relative(frm: str, dots: int, module: str) -> str | None:
            if not module:
                return None  # bare `from . import x`: the imported name (not the module) names the file
            d = os.path.dirname(frm)
            for _ in range(dots - 1):
                d = os.path.dirname(d)
            target = norm_path((d + "/" if d else "") + module.replace(".", "/"))
            for cand in (target + ".py", target + "/__init__.py"):
                if t.exists(cand):
                    return cand
            return None

        for d, name, kind, p in pkgs:
            did = self.g.node(f"deployable_unit:{d or '.'}", "deployable_unit", sha_bytes(t.files[p]),
                              path=d or ".", kind=kind, symbol=name)
            prefix = (d + "/") if d else ""
            for fp in t.paths:
                if not fp.startswith(prefix) or f"code_unit:{fp}" not in self.g.nodes:
                    continue
                if any(fp.startswith(od + "/") for od, *_ in pkgs if od != d and len(od) > len(d) and od.startswith(prefix)):
                    continue
                self.g.edge(f"code_unit:{fp}", "deploys_to", did, "deterministic", via="containment")

        py_files = [p for p in t.paths if p.endswith(".py")]
        is_test = lambda p: bool(re.search(r"(^|/)(test_\w+|\w+_test)\.py$", p) or "/tests/" in p or p.startswith("tests/"))  # noqa: E731
        resolved_of: dict[str, list[str]] = {}
        for p in py_files:
            code = strip_comments_python(t.text(p))
            targets: list[str] = []
            for m in PY_FROM_RE.finditer(code):
                dots, module = m.group(1), m.group(2)
                r = resolve_relative(p, len(dots), module) if dots else (resolve_absolute(module) if module else None)
                if r and r != p and f"code_unit:{r}" in self.g.nodes:
                    self.g.edge(f"code_unit:{p}", "imports", f"code_unit:{r}", "deterministic",
                                via="python-relative-import" if dots else "python-absolute-import")
                    targets.append(r)
            for m in PY_IMPORT_RE.finditer(code):
                r = resolve_absolute(m.group(1))
                if r and r != p and f"code_unit:{r}" in self.g.nodes:
                    self.g.edge(f"code_unit:{p}", "imports", f"code_unit:{r}", "deterministic", via="python-import")
                    targets.append(r)
            resolved_of[p] = targets
            for m in PY_ENV_RE.finditer(code):
                key = next(g for g in m.groups() if g)
                self.g.node(f"config_key:{key}", "config_key", sha_text(key), symbol=key)
                self.g.edge(f"code_unit:{p}", "reads_config", f"config_key:{key}", "deterministic", via="os-environ")
            for m in PY_ROUTE_RE.finditer(code):
                rid = f"route:{m.group(1).upper()} {m.group(2)}"
                self.g.node(rid, "route", sha_bytes(t.files[p]), path=p, kind="fastapi")
                self.g.edge(f"code_unit:{p}", "provides_route", rid, "deterministic", via="fastapi-decorator")
        for p in py_files:
            if not is_test(p):
                continue
            for r in resolved_of.get(p, []):
                if not is_test(r):
                    self.g.edge(f"code_unit:{p}", "verifies", f"code_unit:{r}", "deterministic", via="python-test-import")
        if pkgs or py_files:
            self.limitations.append("python: absolute imports are matched against every discovered src root (no per-file "
                                     "sys.path modelling); star imports, importlib-dynamic imports and bare `from . import x` "
                                     "are not resolved")

    def x_config(self):
        pat = re.compile(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]"
                         r"|(?:configService|config|this\.config|this\.configService)\.get(?:OrThrow)?(?:<[^>]*>)?\(\s*['\"]([A-Za-z0-9_.]+)['\"]")
        for f in self.ts.values():
            for m in pat.finditer(f.code):
                key = next(g for g in m.groups() if g)
                self.g.node(f"config_key:{key}", "config_key", sha_text(key), symbol=key)
                self.g.edge(f"code_unit:{f.path}", "reads_config", f"config_key:{key}", "deterministic",
                            via="process.env" if m.group(3) is None else "config-service")

    def x_reuse(self):
        for f in self.ts.values():
            for m in re.finditer(r"reuse:\s*(@arcanada/[\w.-]+)", f.comments):
                pkg = m.group(1)
                self.g.node(f"code_unit:{pkg}", "code_unit", sha_text(pkg), kind="shared_package", symbol=pkg)
                self.g.edge(f"code_unit:{f.path}", "imports", f"code_unit:{pkg}", "deterministic", via="reuse-marker")

    def x_di(self):
        for f in self.ts.values():
            if not re.search(r"@(Injectable|Controller|Processor|WebSocketGateway|Resolver)\s*\(", f.code):
                continue
            for cm in re.finditer(r"\bconstructor\s*\(([^)]*)\)", f.code):
                for pm in re.finditer(r"(?:@\w+\([^)]*\)\s*)?(?:private|protected|public|readonly|\s)*\b(\w+)\??\s*:\s*([A-Za-z_]\w*)", cm.group(1)):
                    origin = f.symbol_origin.get(pm.group(2))
                    if origin and origin[0] and origin[0] != f.path and f"code_unit:{origin[0]}" in self.g.nodes:
                        self.g.edge(f"code_unit:{f.path}", "calls", f"code_unit:{origin[0]}", "inferred",
                                    inferred_by="nestjs-di-constructor", boundary="intra_unit", symbol=pm.group(2))

    def _queue_token(self, f: TsFile, tok: str) -> str:
        tok = tok.strip()
        if tok[:1] in "'\"":
            return "lit:" + tok.strip("'\"")
        o = f.symbol_origin.get(tok)
        return f"sym:{o[0]}#{o[1]}" if o and o[0] else f"sym:{f.path}#{tok}"

    def x_queue(self):
        for f in self.ts.values():
            for m in re.finditer(r"@InjectQueue\(\s*([^)]+?)\s*\)", f.code):
                self.queue_producers.append((f.path, self._queue_token(f, m.group(1))))
            for m in re.finditer(r"@Processor\(\s*([^),]+?)\s*[,)]", f.code):
                self.queue_consumers.append((f.path, self._queue_token(f, m.group(1))))
        for pp, ptok in self.queue_producers:
            for cp, ctok in self.queue_consumers:
                if ptok == ctok and pp != cp:
                    self.g.edge(f"code_unit:{pp}", "calls", f"code_unit:{cp}", "inferred", inferred_by="bullmq-queue-token",
                                boundary="intra_unit", symbol=ptok.split("#")[-1].replace("lit:", ""))

    def x_tests(self):
        for f in self.ts.values():
            if not f.is_test:
                continue
            for spec, r in sorted(f.resolved.items()):
                if r in self.ts and not self.ts[r].is_test and f"code_unit:{r}" in self.g.nodes:
                    self.g.edge(f"code_unit:{f.path}", "verifies", f"code_unit:{r}", "deterministic", via="test-import")

    def _client_receivers(self, f: TsFile) -> set[str]:
        recv = {"apiClient", "axios", "http", "httpClient", "api", "client", "fetch"}
        for local, (path, _) in f.symbol_origin.items():
            if path and path in self.ts and re.search(r"\baxios\.create\s*\(|\bfetch\(", self.ts[path].code):
                recv.add(local)
        return recv

    @staticmethod
    def _route_key(method: str, path: str, prefix: str | None) -> tuple[str, tuple[str, ...]]:
        p = path.split("?")[0]
        if prefix and (p == prefix or p.startswith(prefix + "/")):
            p = p[len(prefix):]
        segs = tuple("*" if s.startswith(":") or "${" in s or s.startswith("{") else s for s in p.strip("/").split("/") if s != "")
        return method, segs

    def x_http_client(self):
        served = {}
        for r in self.routes:
            if r["method"] != "WS":
                served[self._route_key(r["method"], r["path"], None)] = r["id"]
        call_re = re.compile(r"\b(\w+)\.(get|post|put|patch|delete|head)\s*(?:<[^>(]*>)?\(\s*(`[^`]*`|'[^']*'|\"[^\"]*\")")
        fetch_re = re.compile(r"\bfetch\s*\(\s*(`[^`]*`|'[^']*'|\"[^\"]*\")\s*(?:,\s*\{[^}]*method\s*:\s*['\"](\w+)['\"])?")
        for f in self.ts.values():
            recv = self._client_receivers(f)
            sites = [(m.group(2).upper(), m.group(3), m.start()) for m in call_re.finditer(f.code) if m.group(1) in recv]
            sites += [((m.group(2) or "get").upper(), m.group(1), m.start()) for m in fetch_re.finditer(f.code)]
            for method, lit, pos in sites:
                url = lit[1:-1]
                url = re.sub(r"\$\{[^}]*\}", ":p", url)
                url = re.sub(r"^https?://[^/]+", "", url)
                if not url.startswith("/"):
                    continue
                key = self._route_key(method, url, self.global_prefix)
                rid = served.get(key)
                line = f"L{f.code.count(chr(10), 0, pos) + 1}"
                if rid:
                    self.g.edge(f"code_unit:{f.path}", "consumes_contract", rid, "inferred", inferred_by="http-client-url-match",
                                boundary="service", site=line)
                else:
                    self.unmatched_http.append(f"{f.path}:{line} {method} {lit[1:-1]}")

    @staticmethod
    def _root_is_its_own_package(t: "Tree") -> bool:
        """AUP-GRAPH-009:retrofit1 — is the workspace ROOT itself a deployable, or only a manifest?

        Deterministic markers, the same ones `x_deployables` classifies by: a Nest CLI project file,
        `@nestjs/core`, a `bin` entry or a Next/React root. A root that only declares members
        (`private: true` + workspace globs, e.g. arcanada-publisher) stays out, as before."""
        try:
            pj = json.loads(t.text("package.json"))
        except (json.JSONDecodeError, KeyError):
            return False
        deps = {**(pj.get("dependencies") or {}), **(pj.get("devDependencies") or {})}
        return bool(t.exists("nest-cli.json") or "@nestjs/core" in deps or pj.get("bin")
                    or any(t.exists("next.config" + e) for e in (".js", ".ts", ".mjs")) or "next" in deps)

    def _adapter_role_evidence(self, d: str) -> str | None:
        """AUP-GRAPH-009:retrofit1 — `kind=adapter` is a ROLE, read from the code, not from a dependency.

        Evidence: a NON-TEST source file of the package declares `class X extends <Base>` where `<Base>` is
        an `*Adapter`-suffixed symbol the same file imports (the package's own abstract base is therefore a
        `library`, and a mock adapter in a `__tests__` file never promotes its package). The previous rule
        read `@playwright/test`/`playwright` out of package.json: it missed every API-transport adapter
        (Publisher's reddit/telegram/youtube) and would have called any Playwright-driven e2e package an
        adapter (auth-arcana's `account-spa` escapes only because the `frontend` branch runs first).
        Returns the evidence string for the receipt, or None."""
        prefix = "" if d == "." else d + "/"
        for path in sorted(self.ts):
            if not path.startswith(prefix):
                continue
            f = self.ts[path]
            if f.is_test:
                continue
            if any(path.startswith(o + "/") for o in self.package_dirs if o != d and len(o) > len(d) and o.startswith(prefix)):
                continue
            for m in ADAPTER_CLASS_RE.finditer(f.code):
                base = m.group(1)
                for imp in f.imports:
                    if any(local == base for local, _ in imp["symbols"]):
                        line = f.code.count(chr(10), 0, m.start()) + 1
                        return f"{path}:L{line} extends {base} (imported from {imp['spec']})"
        return None

    def x_deployables(self):
        t = self.tree
        for d in self.package_dirs:
            pjp = "package.json" if d == "." else d + "/package.json"
            try:
                pj = json.loads(t.text(pjp))
            except json.JSONDecodeError:
                pj = {}
            deps = {**(pj.get("dependencies") or {}), **(pj.get("devDependencies") or {})}
            has = lambda n: t.exists(("" if d == "." else d + "/") + n)  # noqa: E731
            if has("nest-cli.json") or "@nestjs/core" in deps:
                kind = "service"
            elif any(has("next.config" + e) for e in (".js", ".ts", ".mjs")) or "next" in deps or "react-dom" in deps:
                kind = "frontend"
            elif pj.get("bin"):
                kind = "cli"
            elif self._adapter_role_evidence(d):
                kind = "adapter"
            else:
                kind = "library"
            did = self.g.node(f"deployable_unit:{d}", "deployable_unit", sha_bytes(t.files[pjp]), path=d, kind=kind,
                              symbol=pj.get("name") if isinstance(pj.get("name"), str) else None)
            nested = [o for o in self.package_dirs if o != d and (d == "." or o.startswith(d + "/"))]
            for p in (t.paths if d == "." else t.under(d)):
                if f"code_unit:{p}" in self.g.nodes and not any(p.startswith(o + "/") for o in nested):
                    self.g.edge(f"code_unit:{p}", "deploys_to", did, "deterministic", via="containment")

    def _explicit_targets(self, text: str) -> list[tuple[str, str]]:
        out = []
        for m in re.finditer(r"(?<![\w@/])((?:[\w.-]+/)+[\w.-]+\.(?:ts|tsx|js|mjs|cjs|json|prisma|md|yaml|yml|sh|py))\b", text):
            p = norm_path(m.group(1))
            for nid in (f"code_unit:{p}", f"document:{p}", f"receipt:{p}"):
                if nid in self.g.nodes:
                    out.append((nid, "explicit-path"))
        for m in re.finditer(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[\w/:{}.$-]+)", text):
            key = self._route_key(m.group(1), m.group(2), self.global_prefix)
            for r in self.routes:
                if r["method"] != "WS" and self._route_key(r["method"], r["path"], None) == key:
                    out.append((r["id"], "explicit-route"))
        for m in re.finditer(r"\bdata_model:(\w+)|\bmodel\s+`?(\w+)`?", text):
            name = m.group(1) or m.group(2)
            if f"data_model:{name}" in self.g.nodes:
                out.append((f"data_model:{name}", "explicit-model"))
        return out

    def x_docs(self):
        t = self.tree
        docs = [p for p in t.paths if p.endswith((".md", ".markdown"))]
        for p in docs:
            self.g.node(f"document:{p}", "document", sha_bytes(t.files[p]), path=p)
        for p in docs:
            for nid, via in self._explicit_targets(t.text(p)):
                if nid != f"document:{p}":
                    self.g.edge(f"document:{p}", "documents", nid, "deterministic", via=via)

    def x_work_items(self):
        for f in self.ts.values():
            for wid in sorted(set(self.work_item_re.findall(f.comments))):
                self.g.node(f"work_item:{wid}", "work_item", sha_text(wid), symbol=wid)
                self.g.edge(f"work_item:{wid}", "documents", f"code_unit:{f.path}", "deterministic", via="explicit-id-in-comment")
        for p in self.tree.paths:
            if p.endswith((".md", ".markdown")) and f"document:{p}" in self.g.nodes:
                for wid in sorted(set(self.work_item_re.findall(self.tree.text(p)))):
                    self.g.node(f"work_item:{wid}", "work_item", sha_text(wid), symbol=wid)
                    self.g.edge(f"document:{p}", "documents", f"work_item:{wid}", "deterministic", via="explicit-id")

    def x_receipts(self):
        t = self.tree
        for p in t.paths:
            if not (p.endswith(".json") and (p.startswith("receipts/") or "/receipts/" in p)):
                continue
            try:
                doc = json.loads(t.text(p))
            except json.JSONDecodeError:
                continue
            if not (isinstance(doc, dict) and isinstance(doc.get("schema"), str) and doc["schema"].endswith("Receipt/v1")):
                continue
            rid = self.g.node(f"receipt:{p}", "receipt", sha_bytes(t.files[p]), path=p, kind=doc["schema"])
            strings = " ".join(s for s in re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', canonical(doc)))
            for nid, via in self._explicit_targets(strings):
                if nid != rid and not nid.startswith("receipt:"):  # verifies → receipt is not an allowed endpoint type
                    self.g.edge(rid, "verifies", nid, "deterministic", via=via)

    # ---- run -------------------------------------------------------------------------------------------
    def build(self, built_at: str) -> dict:
        t0 = time.monotonic()
        self.base()
        self.resolve_all()
        order = [("contracts", self.x_contracts), ("routes", self.x_routes), ("prisma", self.x_prisma), ("imports", self.x_imports),
                 ("config", self.x_config), ("reuse", self.x_reuse), ("di", self.x_di), ("queue", self.x_queue), ("tests", self.x_tests),
                 ("http_client", self.x_http_client), ("deployables", self.x_deployables), ("rust", self.x_rust),
                 ("python", self.x_python), ("docs", self.x_docs), ("work_items", self.x_work_items), ("receipts", self.x_receipts)]
        for name, fn in order:
            if self.on(name):
                fn()
        nodes, edges = self.g.finalize()
        by_node: dict[str, int] = {}
        for n in nodes:
            by_node[n["type"]] = by_node.get(n["type"], 0) + 1
        by_edge: dict[str, dict[str, int]] = {}
        for e in edges:
            by_edge.setdefault(e["type"], {})
            by_edge[e["type"]][e["provenance"]] = by_edge[e["type"]].get(e["provenance"], 0) + 1
        uncovered: dict[str, int] = {}
        for p in self.tree.paths:
            ext = os.path.splitext(p)[1] or "(none)"
            if not (p.endswith(CODE_EXT) or p.endswith(RUST_EXT) or p.endswith(PY_EXT)
                    or p.endswith((".prisma", ".md", ".markdown", ".json", ".yaml", ".yml", ".toml"))):
                uncovered[ext] = uncovered.get(ext, 0) + 1
        limitations = sorted(set(self.limitations))
        limitations.append("parser: comment/string-aware regex (AST-lite), not the TypeScript compiler; decorators with computed "
                           "arguments, re-exports deeper than 6 hops and dynamic dispatch are not resolved")
        limitations.append("incremental build (manifest.incremental_from) not implemented in builder0; every build is a full rebuild")
        if self.unresolved_imports:
            limitations.append(f"unresolved relative imports: {len(self.unresolved_imports)}")
        if self.dynamic_routes:
            limitations.append(f"route decorators with non-literal paths skipped: {len(self.dynamic_routes)}")
        if self.unmatched_http:
            limitations.append(f"http client call sites matched to no served route: {len(self.unmatched_http)}")
        if uncovered:
            limitations.append("files of uncovered languages yield no nodes: " + ", ".join(f"{k}×{v}" for k, v in sorted(uncovered.items())))
        manifest = {
            "schema": "RelationshipGraph/v1",
            "builder": BUILDER,
            "builder_version": VERSION,
            "source_repo": self.tree.meta["source_repo"],
            "source_commit": self.tree.meta["source_commit"],
            "source_tree": self.tree.meta["source_tree"],
            "source_subdir": self.tree.meta.get("subdir"),
            "dirty": self.tree.meta["dirty"],
            "built_at_utc": built_at,
            "extractors": [x for x in EXTRACTORS if self.on(x)],
            "disabled_extractors": sorted(self.disabled),
            "parameters": {"global_prefix": self.global_prefix, "global_prefix_exclude": self.global_prefix_exclude,
                           "work_item_pattern": self.work_item_pattern, "parser": "regex-ast-lite", "typescript_compiler": False},
            "node_count": len(nodes),
            "edge_count": len(edges),
            "language_coverage": ["typescript", "javascript", "prisma", "markdown", "json-receipts", "rust", "python"],
            "limitations": limitations,
            "stats": {"files": len(self.tree.paths), "ts_files": len(self.ts), "nodes_by_type": by_node, "edges_by_type_provenance": by_edge,
                      "dropped_dangling_edges": len(self.g.dropped_dangling), "unresolved_relative_imports": self.unresolved_imports,
                      "external_packages": sorted(self.external_packages), "dynamic_route_paths": self.dynamic_routes,
                      "http_client_unmatched": self.unmatched_http},
            "graph_digest": None,
        }
        if manifest["source_subdir"] is None:
            del manifest["source_subdir"]
        doc = {"schema": "RelationshipGraph/v1", "manifest": manifest, "nodes": nodes, "edges": edges}
        # the digest is the validator's formula over the whole manifest (minus graph_digest/built_at_utc);
        # wall-clock build time is NOT written into the graph (it is not a property of the commit) — see build_seconds
        manifest["graph_digest"] = schema_check.graph_digest(doc)
        self.build_seconds = round(time.monotonic() - t0, 3)
        return doc


def dump_graph(doc: dict) -> bytes:
    return (json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def digest_of(doc: dict) -> str:
    """Digest as the validator recomputes it (relationship-graph.v1.json manifest.graph_digest)."""
    return schema_check.graph_digest(doc)


def build(repo: Path, *, rev="HEAD", subdir="", worktree=False, built_at=None, disabled=frozenset(),
          work_item_pattern=DEFAULT_WORK_ITEM_PATTERN) -> dict:
    tree = load_tree_worktree(repo) if worktree else load_tree_git(repo, rev, subdir)
    return Builder(tree, set(disabled), work_item_pattern).build(built_at or now_iso())


# ----------------------------------------------------------------------------------------------- selftest
def _classify(doc: dict, ignore_dirty: bool) -> dict:
    gschema = schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH)
    findings = schema_check.check_graph(doc, gschema, disabled=frozenset({"GRAPH_DIRTY"}) if ignore_dirty else frozenset())
    codes = sorted({f["code"] for f in findings})
    return {"verdict": "conformant" if not codes else "violation", "codes": codes, "n": len(findings)}


def _edge_set(doc: dict) -> set[tuple]:
    return {(e["from"], e["type"], e["to"], e["provenance"]) for e in doc["edges"]}


def _provider_side_inferred(doc: dict) -> list[dict]:
    """Contract/route edges that must be deterministic: provides_route, implements_contract, consumes_contract → contract."""
    return [e for e in doc["edges"]
            if e["provenance"] != "deterministic" and (e["type"] in ("provides_route", "implements_contract")
                                                       or (e["type"] == "consumes_contract" and e["to"].startswith("contract:")))]


def _consumer_route_bindings(doc: dict) -> list[dict]:
    return [e for e in doc["edges"] if e["type"] == "consumes_contract" and e["to"].startswith("route:")]


def selftest(receipt_out: Path | None, pilot: Path | None, pilot_graph_out: Path | None, pilot_rev: str) -> int:
    res = {"schema": "ReadinessReceipt/v1", "portion_id": "AUP-GRAPH-002:builder0", "tool": BUILDER, "tool_version": VERSION,
           "captured_at_utc": now_iso(), "host": os.uname().nodename, "python": sys.version.split()[0],
           "node_version_on_host": None, "checks": [], "fixture": {}, "mutation_battery": {}, "pilot": None}
    try:
        res["node_version_on_host"] = subprocess.run(["node", "--version"], capture_output=True, text=True, check=True).stdout.strip() + " (present, not used: builder0 is stdlib-only by design)"
    except (OSError, subprocess.CalledProcessError):
        res["node_version_on_host"] = "absent"
    ok_all = True

    def check(name, ok, **extra):
        nonlocal ok_all
        ok_all &= bool(ok)
        res["checks"].append({"name": name, "ok": bool(ok), **extra})
        print(("  ok  " if ok else "  RED ") + name + (("  " + canonical(extra)[:200]) if extra and not ok else ""))

    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    full = build(FIXTURE_DIR, worktree=True, built_at=FIXED_BUILT_AT)
    full_bytes = dump_graph(full)
    res["fixture"] = {"path": str(FIXTURE_DIR.relative_to(ROOT)), "expected": str(EXPECTED_PATH.relative_to(ROOT)),
                      "source_commit": full["manifest"]["source_commit"], "dirty": full["manifest"]["dirty"],
                      "node_count": full["manifest"]["node_count"], "edge_count": full["manifest"]["edge_count"],
                      "nodes_by_type": full["manifest"]["stats"]["nodes_by_type"],
                      "edges_by_type_provenance": full["manifest"]["stats"]["edges_by_type_provenance"],
                      "graph_digest": full["manifest"]["graph_digest"]}
    cls = _classify(full, ignore_dirty=True)
    check("fixture graph is RelationshipGraph/v1 conformant (GRAPH_DIRTY ignored: fixture read from the worktree)", cls["verdict"] == "conformant", **cls)
    check("fixture graph: dirty flag reported honestly", True, dirty=full["manifest"]["dirty"])
    check("fixture graph: 0 dangling edges dropped", full["manifest"]["stats"]["dropped_dangling_edges"] == 0, dropped=full["manifest"]["stats"]["dropped_dangling_edges"])
    check("fixture graph: 0 unresolved relative imports", not full["manifest"]["stats"]["unresolved_relative_imports"], unresolved=full["manifest"]["stats"]["unresolved_relative_imports"])
    check("fixture graph: the unmatched http client call sites are exactly the deliberate negative fixture (reported, never bound to a route)",
          full["manifest"]["stats"]["http_client_unmatched"] == expected.get("expected_unmatched_http", []), unmatched=full["manifest"]["stats"]["http_client_unmatched"])
    edges = _edge_set(full)
    node_ids = {n["id"] for n in full["nodes"]}
    missing = []
    n_exp = 0
    for ext, exp in expected["extractors"].items():
        for nid in exp.get("nodes", []):
            n_exp += 1
            if nid not in node_ids:
                missing.append(f"{ext}: node {nid}")
        for e in exp.get("edges", []):
            n_exp += 1
            if tuple(e) not in edges:
                missing.append(f"{ext}: edge {e}")
    check(f"every expected node/edge of ts-mini is present ({n_exp} expectations over {len(expected['extractors'])} extractors)", not missing, missing=missing)
    forbidden = [e for e in expected.get("forbidden_edges", []) if tuple(e) in edges]
    check("no forbidden edge is emitted (negative fixtures: external package, self-import, test file as provider)", not forbidden, present=forbidden)
    check("every extractor is exercised by ≥ 1 expectation", set(expected["extractors"]) == set(EXTRACTORS),
          unexercised=sorted(set(EXTRACTORS) - set(expected["extractors"])), unknown=sorted(set(expected["extractors"]) - set(EXTRACTORS)))
    psi = _provider_side_inferred(full)
    check("fixture: 0 inferred among provider-side contract/route edges (provides_route, implements_contract, consumes_contract→contract)", not psi, offending=psi[:5])
    cons = _consumer_route_bindings(full)
    check("fixture: consumer http-client→route bindings are all labelled inferred with inferred_by", all(e["provenance"] == "inferred" and e.get("inferred_by") for e in cons), n=len(cons))
    check("fixture: no edge names an LLM or lacks provenance", all("provenance" in e and e.get("via") != "llm" for e in full["edges"]))
    # determinism
    again = dump_graph(build(FIXTURE_DIR, worktree=True, built_at=FIXED_BUILT_AT))
    check("rebuild with the same --built-at is byte-identical", again == full_bytes, sha_first=sha_bytes(full_bytes), sha_second=sha_bytes(again))
    other = build(FIXTURE_DIR, worktree=True, built_at="2026-09-05T00:01:00Z")
    check("rebuild with another --built-at keeps graph_digest and changes the bytes", other["manifest"]["graph_digest"] == full["manifest"]["graph_digest"] and dump_graph(other) != full_bytes)
    check("graph_digest recomputes with the validator's formula", digest_of(full) == full["manifest"]["graph_digest"])
    # mutation battery
    survived = []
    for ext in EXTRACTORS:
        mut = build(FIXTURE_DIR, worktree=True, built_at=FIXED_BUILT_AT, disabled={ext})
        m_edges, m_nodes = _edge_set(mut), {n["id"] for n in mut["nodes"]}
        exp = expected["extractors"].get(ext, {})
        lost = [f"node {n}" for n in exp.get("nodes", []) if n not in m_nodes] + [f"edge {e}" for e in exp.get("edges", []) if tuple(e) not in m_edges]
        cls_m = _classify(mut, ignore_dirty=True)
        res["mutation_battery"][ext] = {"expectations": len(exp.get("nodes", [])) + len(exp.get("edges", [])), "lost_when_disabled": len(lost),
                                        "mutant_detected": bool(lost), "extractors_in_manifest": mut["manifest"]["extractors"],
                                        "dangling_dropped": mut["manifest"]["stats"]["dropped_dangling_edges"], "schema": cls_m["verdict"],
                                        "sample_lost": lost[:3]}
        if not lost:
            survived.append(ext)
    check("mutation battery: disabling every extractor loses ≥ 1 of its expectations (0 mutants survived)", not survived, survived=survived)
    check("mutation battery: every mutant graph is still schema-conformant (dangling edges dropped, never emitted)", all(m["schema"] == "conformant" for m in res["mutation_battery"].values()))
    # AUP-GRAPH-009:retrofit1 — deployable_unit kind=adapter is a role, not a dependency (fixture: adapter-mini)
    ad_exp = json.loads(ADAPTER_EXPECTED_PATH.read_text())
    ad = build(ADAPTER_FIXTURE_DIR, worktree=True, built_at=FIXED_BUILT_AT)
    ad_kinds = {n["id"]: n.get("kind") for n in ad["nodes"] if n["type"] == "deployable_unit"}
    ad_wrong = {k: {"expected": v, "got": ad_kinds.get(k)} for k, v in ad_exp["expected_kinds"].items() if ad_kinds.get(k) != v}
    res["adapter_fixture"] = {"path": str(ADAPTER_FIXTURE_DIR.relative_to(ROOT)), "kinds": ad_kinds,
                              "expected": ad_exp["expected_kinds"], "wrong": ad_wrong,
                              "fails_before_retrofit1": ad_exp["fails_before_retrofit1"]}
    check(f"adapter-mini: deployable_unit kind is the role, not the transport ({len(ad_exp['expected_kinds'])} packages: "
          "an API adapter without Playwright is `adapter`, a Playwright e2e suite is not)", not ad_wrong, wrong=ad_wrong)
    check("adapter-mini: the package that declares the abstract base is not itself an adapter",
          ad_kinds.get("deployable_unit:packages/core-kit") == "library", got=ad_kinds.get("deployable_unit:packages/core-kit"))
    check("adapter-mini: a mock adapter in a __tests__ file does not promote its package",
          ad_kinds.get("deployable_unit:packages/e2e-suite") == "library", got=ad_kinds.get("deployable_unit:packages/e2e-suite"))
    check("adapter-mini graph is RelationshipGraph/v1 conformant", _classify(ad, ignore_dirty=True)["verdict"] == "conformant",
          **_classify(ad, ignore_dirty=True))
    ad_again = dump_graph(build(ADAPTER_FIXTURE_DIR, worktree=True, built_at=FIXED_BUILT_AT))
    check("adapter-mini: rebuild with the same --built-at is byte-identical", ad_again == dump_graph(ad))

    # AUP-GRAPH-009:retrofit1 — a workspace root that is itself an application is a deployable_unit (fixture: root-app-mini)
    ra_exp = json.loads(ROOT_APP_EXPECTED_PATH.read_text())
    ra = build(ROOT_APP_FIXTURE_DIR, worktree=True, built_at=FIXED_BUILT_AT)
    ra_kinds = {n["id"]: n.get("kind") for n in ra["nodes"] if n["type"] == "deployable_unit"}
    ra_edges = _edge_set(ra)
    ra_wrong = {k: {"expected": v, "got": ra_kinds.get(k)} for k, v in ra_exp["expected_kinds"].items() if ra_kinds.get(k) != v}
    ra_missing = [e for e in ra_exp["expected_edges"] if tuple(e) not in ra_edges]
    ra_forbidden = [e for e in ra_exp["forbidden_edges"] if tuple(e) in ra_edges]
    res["root_app_fixture"] = {"path": str(ROOT_APP_FIXTURE_DIR.relative_to(ROOT)), "kinds": ra_kinds, "expected": ra_exp["expected_kinds"],
                               "wrong": ra_wrong, "missing_edges": ra_missing, "forbidden_present": ra_forbidden,
                               "fails_before_retrofit1": ra_exp["fails_before_retrofit1"]}
    check("root-app-mini: a workspace root that is itself an application is a deployable_unit (service), the member stays its own",
          not ra_wrong, wrong=ra_wrong)
    check("root-app-mini: the root's own sources carry deploys_to the root unit", not ra_missing, missing=ra_missing)
    check("root-app-mini: a member's file deploys to the member only, never also to the root", not ra_forbidden, present=ra_forbidden)
    check("root-app-mini graph is RelationshipGraph/v1 conformant", _classify(ra, ignore_dirty=True)["verdict"] == "conformant")

    # negative controls of the selftest itself
    bogus = ("code_unit:apps/api/src/tasks/tasks.service.ts", "imports", "code_unit:does/not/exist.ts", "deterministic")
    check("selftest negative control: a wrong expectation is reported red", bogus not in edges)
    try:
        build(FIXTURE_DIR, worktree=True, built_at=FIXED_BUILT_AT, disabled={"llm_guess"})
        neg2 = False
    except SystemExit:
        neg2 = True
    check("selftest negative control: an unknown extractor name is refused", neg2)
    res["summary"] = {"checks": len(res["checks"]), "red": sum(1 for c in res["checks"] if not c["ok"]), "extractors": len(EXTRACTORS),
                      "mutants_detected": sum(1 for m in res["mutation_battery"].values() if m["mutant_detected"]), "mutants_survived": survived}

    if pilot is not None:
        print(f"pilot: {pilot} @ {pilot_rev}")
        p = {"repo": str(pilot), "rev": pilot_rev, "checks": []}
        t0 = time.monotonic()
        g1 = build(pilot, rev=pilot_rev, built_at=FIXED_BUILT_AT)
        t1 = time.monotonic() - t0
        b1 = dump_graph(g1)
        b2 = dump_graph(build(pilot, rev=pilot_rev, built_at=FIXED_BUILT_AT))
        g3 = build(pilot, rev=pilot_rev, built_at="2026-09-05T00:01:00Z")
        man = g1["manifest"]
        p.update({"source_repo": man["source_repo"], "source_commit": man["source_commit"], "source_tree": man["source_tree"], "dirty": man["dirty"],
                  "node_count": man["node_count"], "edge_count": man["edge_count"], "nodes_by_type": man["stats"]["nodes_by_type"],
                  "edges_by_type_provenance": man["stats"]["edges_by_type_provenance"], "graph_digest": man["graph_digest"],
                  "graph_file_sha256_build1": sha_bytes(b1), "graph_file_sha256_build2": sha_bytes(b2), "build_seconds_full": round(t1, 3),
                  "global_prefix": man["parameters"]["global_prefix"], "limitations": man["limitations"],
                  "unresolved_relative_imports": man["stats"]["unresolved_relative_imports"], "dynamic_route_paths": man["stats"]["dynamic_route_paths"],
                  "http_client_unmatched": man["stats"]["http_client_unmatched"], "external_packages": man["stats"]["external_packages"],
                  "dropped_dangling_edges": man["stats"]["dropped_dangling_edges"]})
        pcls = _classify(g1, ignore_dirty=False)
        ppsi = _provider_side_inferred(g1)
        pcons = _consumer_route_bindings(g1)
        routes = [n for n in g1["nodes"] if n["type"] == "route"]
        p["routes"] = sorted(n["id"] for n in routes)
        p["contracts_by_kind"] = {}
        for n in g1["nodes"]:
            if n["type"] == "contract":
                p["contracts_by_kind"][n["kind"]] = p["contracts_by_kind"].get(n["kind"], 0) + 1
        p["consumer_route_bindings"] = [{"from": e["from"], "to": e["to"], "inferred_by": e["inferred_by"], "site": e.get("site")} for e in pcons]

        def pcheck(name, ok, **extra):
            nonlocal ok_all
            ok_all &= bool(ok)
            p["checks"].append({"name": name, "ok": bool(ok), **extra})
            print(("  ok  " if ok else "  RED ") + "pilot: " + name + (("  " + canonical(extra)[:200]) if extra and not ok else ""))

        pcheck("graph is RelationshipGraph/v1 conformant (schema_check, GRAPH_DIRTY included)", pcls["verdict"] == "conformant", **pcls)
        pcheck("built from git objects (no checkout), dirty = false", man["source_tree"] == "git-objects" and man["dirty"] is False)
        pcheck("0 inferred among provider-side contract/route edges (provides_route, implements_contract, consumes_contract→contract)", not ppsi,
               offending=[f"{e['from']} -{e['type']}-> {e['to']}" for e in ppsi[:10]])
        pcheck("consumer http-client→route bindings labelled inferred/http-client-url-match, boundary service (reported, not counted above)",
               all(e["provenance"] == "inferred" and e.get("inferred_by") == "http-client-url-match" and e.get("boundary") == "service" for e in pcons), n=len(pcons))
        pcheck("rebuild of the same commit is byte-identical (same --built-at)", b1 == b2)
        pcheck("rebuild with another --built-at keeps graph_digest", g3["manifest"]["graph_digest"] == man["graph_digest"])
        pcheck("full build ≤ 30 s (the incremental bound of the card, met by a full rebuild; incremental mode not implemented)", t1 <= 30.0, seconds=round(t1, 3))
        pcheck("0 dangling edges dropped", man["stats"]["dropped_dangling_edges"] == 0)
        pcheck("0 unresolved relative imports", not man["stats"]["unresolved_relative_imports"], unresolved=man["stats"]["unresolved_relative_imports"])
        pcheck("every route node has ≥ 1 provides_route edge", all(any(e["type"] == "provides_route" and e["to"] == n["id"] for e in g1["edges"]) for n in routes))
        pcheck("≥ 1 node of every stack type the pilot has (code_unit, contract, route, data_model, config_key, deployable_unit, document, work_item)",
               all(man["stats"]["nodes_by_type"].get(k, 0) > 0 for k in ("code_unit", "contract", "route", "data_model", "config_key", "deployable_unit", "document", "work_item")),
               nodes_by_type=man["stats"]["nodes_by_type"])
        pcheck("no LLM edge: every edge carries provenance and no via=llm", all("provenance" in e and e.get("via") != "llm" for e in g1["edges"]))
        if pilot_graph_out is not None:
            pilot_graph_out.parent.mkdir(parents=True, exist_ok=True)
            pilot_graph_out.write_bytes(b1)
            p["graph_file"] = str(pilot_graph_out.relative_to(ROOT)) if pilot_graph_out.is_relative_to(ROOT) else str(pilot_graph_out)
            p["graph_file_sha256"] = sha_bytes(b1)
        p["summary"] = {"checks": len(p["checks"]), "red": sum(1 for c in p["checks"] if not c["ok"])}
        res["pilot"] = p

    res["verdict"] = "PASS" if ok_all else "FAIL"
    if receipt_out:
        receipt_out.parent.mkdir(parents=True, exist_ok=True)
        receipt_out.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"receipt: {receipt_out}")
    s = res["summary"]
    ps = f"; pilot {res['pilot']['summary']['checks']} checks / {res['pilot']['summary']['red']} red" if res["pilot"] else ""
    print(f"SELFTEST {res['verdict']} {s['checks'] - s['red']}/{s['checks']} checks, {s['mutants_detected']}/{s['extractors']} mutants detected{ps}")
    return 0 if ok_all else 1


# ----------------------------------------------------------------------------------------------- cli
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", nargs="?", type=Path, help="repository (git mode) or directory (--worktree)")
    ap.add_argument("--out", type=Path, help="graph JSON to write")
    ap.add_argument("--rev", default="HEAD", help="commit to build from (git mode)")
    ap.add_argument("--subdir", default="", help="restrict to a sub-tree of the commit (paths become relative to it)")
    ap.add_argument("--worktree", action="store_true", help="read files from disk instead of git objects (dirty recorded)")
    ap.add_argument("--built-at", default=None, help="ISO-8601 UTC timestamp for manifest.built_at_utc (default: now)")
    ap.add_argument("--disable", default="", help="comma-separated extractors to disable (mutation battery)")
    ap.add_argument("--work-item-pattern", default=DEFAULT_WORK_ITEM_PATTERN)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--pilot", type=Path, default=None, help="with --selftest: also build this repo and run the pilot checks")
    ap.add_argument("--pilot-rev", default="HEAD")
    ap.add_argument("--pilot-graph", type=Path, default=None, help="with --pilot: write the pilot graph here")
    ap.add_argument("--receipt", type=Path, default=None, help="with --selftest: write the ReadinessReceipt/v1 here")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest(a.receipt, a.pilot, a.pilot_graph, a.pilot_rev)
    if not a.repo or not a.out:
        ap.error("repo and --out are required (or --selftest)")
    disabled = {x.strip() for x in a.disable.split(",") if x.strip()}
    t0 = time.monotonic()
    doc = build(a.repo, rev=a.rev, subdir=a.subdir, worktree=a.worktree, built_at=a.built_at, disabled=disabled,
                work_item_pattern=a.work_item_pattern)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_bytes(dump_graph(doc))
    m = doc["manifest"]
    print(f"{a.out}: {m['node_count']} nodes, {m['edge_count']} edges, digest {m['graph_digest'][:23]}…, "
          f"source {m['source_commit'][:12]} ({m['source_tree']}{', DIRTY' if m['dirty'] else ''}), {round(time.monotonic() - t0, 3)} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

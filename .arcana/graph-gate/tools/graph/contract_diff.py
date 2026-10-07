#!/usr/bin/env python3
"""AUP-GRAPH-004 `contract-diff0` — contract diff between two revisions + consumer ⊆ provider check over the
contract edges of a RelationshipGraph/v1 (DEC-AUP-0008: mandatory verifier for implements_contract / consumes_contract).

    contract_diff.py --repo <repo> --base <rev> --head <rev> [--graph <graph.json>] [--subdir <d>]
                     [--direction SYM=input|output|bidirectional ...] [--consumer-keys ID=k1,k2,... ...]
                     [--json] [--out <ContractDiff.json>]
    contract_diff.py --repo <repo> --extract [--rev <rev>]            # dump the schema-lite of every contract
    contract_diff.py --selftest [--receipt <ReadinessReceipt.json>] [--pilot <repo> --pilot-graph <graph.json>
                     --pilot-out <dir>]

What it does (schemas are TAKEN FROM CODE, never from a hand-written spec — GRAPH-004 failure condition):
  extraction   Zod (`z.object/string/number/enum/array/union/literal/record/tuple/optional/nullable/default/min/max/
               uuid/email/...`, `.extend/.merge/.pick/.omit/.partial/.required`, references between schemas), class-
               validator DTOs (decorators are the validation truth: IsString/IsInt/IsIn/IsEnum/IsUUID/IsDateString/
               ValidateNested+Type/IsArray/each/IsOptional/MaxLength/Min/...; `extends`, PartialType/PickType/OmitType/
               IntersectionType), string-literal union type aliases, TS enums → one canonical *schema-lite* per
               contract (`kind`, `properties`, `required`, `values`, `items`, `constraints`, `nullable`), plus the
               sha256 of the declaration text (the GRAPH-004 narrowing of the node content hash: comment-only edits
               keep the hash)
  taxonomy     breaking: CONTRACT_REMOVED, FIELD_REMOVED, FIELD_RENAMED, NEW_REQUIRED_FIELD, FIELD_MADE_REQUIRED,
               TYPE_CHANGED, TYPE_NARROWED, ENUM_VALUE_REMOVED, ERROR_CODE_CHANGED; direction-dependent:
               REQUIRED_TO_OPTIONAL, TYPE_WIDENED, ENUM_VALUE_ADDED (compatible when the contract is pure INPUT —
               class-validator DTOs are request bodies by construction — breaking for OUTPUT and BIDIRECTIONAL
               contracts: shared union types / enums; unknown direction counts as bidirectional, never as a warning);
               compatible: CONTRACT_ADDED, FIELD_ADDED_OPTIONAL; info: NON_SEMANTIC_TEXT (declaration text changed,
               schema-lite equal)
  edges        for every implements_contract / consumes_contract→contract edge of the graph (or discovered by
               import): provider verdict = the diff; consumer verdict from the consumer's *usage projection* — keys
               read (`dto.key`, destructuring), keys sent (typed object literals, `client.post<Sym>(url, {...})`),
               enum values used (string literals ∈ the enum) — `failed` if a used key/value is not in the provider
               at head or a breaking change sits on a used key or a sender omits a new required key; `verified` if
               the projection is complete and untouched; `not_measured` when the consumer forwards / spreads the
               object (usage not narrowable) and the provider has a breaking change, or when a bidirectional enum
               gained a value (consumer exhaustiveness unknown). Inferred edges never yield `verified` alone: they
               carry `requires_canary`. External consumers (other repos) are declared with --consumer-keys.

Exit codes: 0 no breaking change and no failed/not_measured edge · 1 breaking change or failed/not_measured edge ·
2 refusal (UNKNOWN_REV, GRAPH_INVALID, GRAPH_COMMIT_MISMATCH, NO_CONTRACTS).  Output: `ContractDiff/v1`.
stdlib only; Python ≥ 3.10.  The TypeScript compiler is NOT used (regex/AST-lite, comment- and string-aware) —
recorded as a limitation; the pilot clone is read through git objects and never written.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
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
import build_graph  # noqa: E402
import schema_check  # noqa: E402

VERSION = "1.0.0"
TOOL = "tools/graph/contract_diff.py"
OUT_SCHEMA = "ContractDiff/v1"
FIXTURE_DIR = ROOT / "contracts" / "graph-verified-change" / "fixtures" / "contract-diff"
EXPECTED_PATH = FIXTURE_DIR / "EXPECTED.json"

BREAKING_ALWAYS = {"CONTRACT_REMOVED", "FIELD_REMOVED", "FIELD_RENAMED", "NEW_REQUIRED_FIELD", "FIELD_MADE_REQUIRED",
                   "TYPE_CHANGED", "TYPE_NARROWED", "ENUM_VALUE_REMOVED", "ERROR_CODE_CHANGED"}
# direction-dependent codes: compatible for pure input contracts, breaking otherwise
BREAKING_UNLESS_INPUT = {"REQUIRED_TO_OPTIONAL", "TYPE_WIDENED", "ENUM_VALUE_ADDED"}
COMPATIBLE = {"CONTRACT_ADDED", "FIELD_ADDED_OPTIONAL"}
INFO = {"NON_SEMANTIC_TEXT"}
TAXONOMY = sorted(BREAKING_ALWAYS | BREAKING_UNLESS_INPUT | COMPATIBLE | INFO)

# rules the mutation battery disables one at a time (each must be caught by ≥ 1 fixture expectation)
RULES = ["field_removed", "field_renamed", "new_required", "made_required", "required_to_optional", "type_changed",
         "type_narrowed", "type_widened", "enum_removed", "enum_added", "error_code", "contract_removed",
         "direction", "nested_diff", "constraints", "nullable", "consumer_keys", "consumer_required", "consumer_values",
         "consumer_incomplete", "x_zod", "x_class_validator", "x_union", "x_enum", "decl_hash"]

ERROR_CODE_RE = re.compile(r"(?i)(error|err|failure|fault)[_-]?(code|kind|type|reason|name)s?$|(?<![a-z])codes?$")
IDENT = r"[A-Za-z_$][\w$]*"


# ----------------------------------------------------------------------------------------------- helpers
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha_text(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def dump(obj) -> bytes:
    return (json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def git(args: list[str], cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True).stdout


class Refusal(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


OPENERS = {"(": ")", "[": "]", "{": "}", "<": ">"}


def match_close(s: str, i: int, angle: bool = False) -> int:
    """Index of the bracket closing s[i] (quotes respected). Returns len(s) when unbalanced."""
    stack = [s[i]]
    j = i + 1
    n = len(s)
    while j < n and stack:
        c = s[j]
        if c in "'\"`":
            k = j + 1
            while k < n and s[k] != c:
                k += 2 if s[k] == "\\" else 1
            j = k + 1
            continue
        if c in "([{" or (angle and c == "<"):
            stack.append(c)
        elif c in ")]}" or (angle and c == ">"):
            if stack and OPENERS.get(stack[-1]) == c:
                stack.pop()
        j += 1
    return j - 1 if not stack else n


def split_top(s: str, sep: str = ",", angle: bool = False) -> list[str]:
    """Split at depth-0 separators (quotes and brackets respected); empty parts dropped."""
    parts, depth, cur, i, n = [], 0, [], 0, len(s)
    while i < n:
        c = s[i]
        if c in "'\"`":
            k = i + 1
            while k < n and s[k] != c:
                k += 2 if s[k] == "\\" else 1
            cur.append(s[i:k + 1])
            i = k + 1
            continue
        if c in "([{" or (angle and c == "<"):
            depth += 1
        elif c in ")]}" or (angle and c == ">"):
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def statement_end(s: str, i: int) -> int:
    """Index just past the `;` (depth 0) that ends the statement starting at i; a newline followed by a top-level
    `export`/`const`/`class`/`type`/`enum`/`function`/decorator at depth 0 also ends it (missing semicolon)."""
    depth, n = 0, len(s)
    j = i
    while j < n:
        c = s[j]
        if c in "'\"`":
            k = j + 1
            while k < n and s[k] != c:
                k += 2 if s[k] == "\\" else 1
            j = k + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth == 0:
            return j + 1
        elif c == "\n" and depth == 0 and re.match(r"\s*(?:export\b|const\b|let\b|class\b|type\b|enum\b|function\b|interface\b|@)", s[j + 1:j + 40]):
            return j
        j += 1
    return n


def norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def parse_literal(tok: str):
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] in "'\"`" and tok[-1] == tok[0]:
        return tok[1:-1]
    if tok in ("true", "false"):
        return tok == "true"
    if tok == "null":
        return None
    try:
        return int(tok) if re.fullmatch(r"-?\d+", tok) else float(tok)
    except ValueError:
        return tok


def literal_list(text: str) -> list | None:
    """['a', 'b'] / ('a' | 'b') → list of literal values, or None if any element is not a literal."""
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    out = []
    for p in split_top(text, "," if "," in text else "|"):
        p = p.strip().rstrip(",")
        if not (p and (p[0] in "'\"`" or re.fullmatch(r"-?\d+(\.\d+)?|true|false|null", p))):
            return None
        out.append(parse_literal(p))
    return out


def sort_values(vals) -> list:
    return sorted(vals, key=lambda v: (type(v).__name__, str(v)))


# ----------------------------------------------------------------------------------------------- trees
def load_tree_dir(root: Path) -> build_graph.Tree:
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            files[p.relative_to(root).as_posix()] = p.read_bytes()
    meta = {"source_repo": root.name, "source_commit": "0" * 40, "source_tree": "directory", "dirty": False, "subdir": None,
            "rev": str(root)}
    return build_graph.Tree(files, meta)


def ts_paths(tree: build_graph.Tree) -> list[str]:
    return [p for p in tree.paths if re.search(r"\.[cm]?tsx?$", p) and "/node_modules/" not in p and not p.startswith("node_modules/")
            and not p.endswith(".d.ts")]


# ----------------------------------------------------------------------------------------------- extraction
class Decl:
    """One declaration found in a file (contract candidates and the auxiliary types needed to resolve references)."""

    def __init__(self, path: str, symbol: str, kind: str, text: str, body: str, exported: bool, extra=None):
        self.path, self.symbol, self.kind, self.text, self.body, self.exported = path, symbol, kind, text, body, exported
        self.extra = extra or {}

    @property
    def id(self) -> str:
        return f"contract:{self.path}#{self.symbol}"


class Extractor:
    """Schema-lite extraction over a Tree. `disabled` holds mutation-battery rule names."""

    def __init__(self, tree: build_graph.Tree, disabled: set[str] | None = None):
        self.tree = tree
        self.disabled = disabled or set()
        self.decls: dict[str, dict[str, Decl]] = {}     # path → symbol → Decl
        self.by_symbol: dict[str, list[Decl]] = {}      # symbol → decls (cross-file resolution)
        self.imports: dict[str, dict[str, tuple[str, str]]] = {}  # path → local → (spec, imported)
        self.limitations: list[str] = []
        self._cache: dict[tuple[str, str], dict] = {}
        for p in ts_paths(tree):
            try:
                self._scan(p, build_graph.strip_comments(tree.text(p)))
            except Exception as e:  # noqa: BLE001 — extraction must never abort the diff
                self.limitations.append(f"{p}: extraction error {type(e).__name__}: {e}")

    def on(self, rule: str) -> bool:
        return rule not in self.disabled

    # ---- scanning -------------------------------------------------------------------------------------------
    def _add(self, d: Decl):
        prior = self.decls.get(d.path, {}).get(d.symbol)
        # TypeScript permits a schema value and its inferred type to share a name.
        # Keep the runtime contract: replacing it with this alias loses the schema
        # and makes existing graph consumer edges uncheckable.
        if (prior and prior.kind == "zod" and d.kind == "type_alias"
                and re.fullmatch(r"z\s*\.\s*infer\s*<\s*typeof\s+" + re.escape(d.symbol) + r"\s*>", d.body)):
            return
        self.decls.setdefault(d.path, {})[d.symbol] = d
        self.by_symbol.setdefault(d.symbol, []).append(d)

    def _scan(self, path: str, code: str):
        imports = {}
        for m in build_graph.IMPORT_RE.finditer(code):
            if m.group("spec") is None:
                continue
            for local, imported in build_graph.parse_import_clause(m.group("clause")):
                imports[local] = (m.group("spec"), imported)
        self.imports[path] = imports
        specs = {s for s, _ in imports.values()}
        has_zod = "zod" in specs or "zod/v4" in specs or "zod/v3" in specs
        has_cv = "class-validator" in specs
        # zod schemas + const arrays + generic consts
        for m in re.finditer(r"(?:^|[;\n])\s*(export\s+)?const\s+(" + IDENT + r")\s*(?::[^=]+)?=\s*", code):
            start = m.start(2) - (m.group(1) or "").__len__() - len("const ")
            start = code.rfind("\n", 0, m.start(2)) + 1
            end = statement_end(code, m.end())
            expr = code[m.end():end].rstrip().rstrip(";").strip()
            text = code[start:end]
            sym = m.group(2)
            if has_zod and re.match(r"z\.|" + IDENT + r"\.(extend|merge|pick|omit|partial|required|array|optional|nullable|deepPartial)\(", expr) and self.on("x_zod"):
                self._add(Decl(path, sym, "zod", text, expr, bool(m.group(1))))
            elif re.match(r"\[[^\]]*\]\s*as\s+const", expr):
                vals = literal_list(re.sub(r"\s*as\s+const\s*$", "", expr))
                if vals is not None:
                    self._add(Decl(path, sym, "const_array", text, expr, bool(m.group(1)), {"values": vals}))
            elif re.match(r"\{[\s\S]*\}\s*as\s+const", expr):
                self._add(Decl(path, sym, "const_object", text, expr, bool(m.group(1))))
        # classes
        for m in re.finditer(r"(?:^|\n)((?:\s*@" + IDENT + r"(?:\([^)]*\))?\s*)*)\s*(export\s+)?(?:abstract\s+)?class\s+(" + IDENT + r")\s*(?:extends\s+([^{]+?))?\s*(?:implements\s+[^{]+?)?\s*\{", code):
            ob = m.end() - 1
            cb = match_close(code, ob)
            body = code[ob + 1:cb]
            kind = "class_validator_dto" if (has_cv or re.search(r"@(Is\w+|ValidateNested|IsOptional)\b", body)) else "class"
            if kind == "class_validator_dto" and not self.on("x_class_validator"):
                kind = "class"
            self._add(Decl(path, m.group(3), kind, code[m.start(1) if m.group(1) else m.start(3):cb + 1], body, bool(m.group(2)),
                           {"extends": (m.group(4) or "").strip() or None}))
        # type aliases
        for m in re.finditer(r"(?:^|[;\n])\s*(export\s+)?type\s+(" + IDENT + r")(?:<[^=]*>)?\s*=\s*", code):
            end = statement_end(code, m.end())
            rhs = code[m.end():end].rstrip().rstrip(";").strip()
            vals = literal_list(rhs.lstrip("|")) if re.fullmatch(r"\|?\s*['\"][\s\S]*", rhs) else None
            kind = "type_alias_union" if vals is not None and self.on("x_union") else "type_alias"
            start = code.rfind("\n", 0, m.start(2)) + 1
            self._add(Decl(path, m.group(2), kind, code[start:end], rhs, bool(m.group(1)), {"values": vals}))
        # enums
        for m in re.finditer(r"(?:^|[;\n])\s*(export\s+)?(?:declare\s+)?(?:const\s+)?enum\s+(" + IDENT + r")\s*\{", code):
            ob = m.end() - 1
            cb = match_close(code, ob)
            members = {}
            for i, part in enumerate(split_top(code[ob + 1:cb], ",")):
                if "=" in part:
                    k, v = part.split("=", 1)
                    members[k.strip()] = parse_literal(v)
                else:
                    members[part.strip()] = i
            start = code.rfind("\n", 0, m.start(2)) + 1
            self._add(Decl(path, m.group(2), "ts_enum" if self.on("x_enum") else "enum_plain", code[start:cb + 1],
                           code[ob + 1:cb], bool(m.group(1)), {"members": members}))
        # interfaces (auxiliary: resolve refs)
        for m in re.finditer(r"(?:^|[;\n])\s*(export\s+)?interface\s+(" + IDENT + r")(?:<[^{]*>)?\s*(?:extends\s+([^{]+?))?\s*\{", code):
            ob = m.end() - 1
            cb = match_close(code, ob)
            start = code.rfind("\n", 0, m.start(2)) + 1
            self._add(Decl(path, m.group(2), "interface", code[start:cb + 1], code[ob + 1:cb], bool(m.group(1)),
                           {"extends": (m.group(3) or "").strip() or None}))

    # ---- contracts ------------------------------------------------------------------------------------------
    CONTRACT_KINDS = ("zod", "class_validator_dto", "type_alias_union", "ts_enum")

    def contracts(self) -> dict[str, dict]:
        """id → {kind, path, symbol, direction, schema, decl_hash, text_hash}."""
        out = {}
        for path in sorted(self.decls):
            for sym, d in sorted(self.decls[path].items()):
                if d.kind == "class" and d.exported and self.on("x_class_validator") and self._extends_dto(d):
                    d.kind = "class_validator_dto"
                if d.kind not in self.CONTRACT_KINDS or (d.kind != "zod" and not d.exported):
                    continue
                kind = {"ts_enum": "cross_repo_enum"}.get(d.kind, d.kind)
                schema = self.schema_of(d)
                out[d.id] = {"id": d.id, "kind": kind, "path": path, "symbol": sym, "exported": d.exported,
                             "direction": self.direction_of(d), "schema": schema,
                             "decl_hash": sha_text(norm_ws(d.text)) if self.on("decl_hash") else sha_text(d.text + "\n" + str(len(d.text))),
                             "error_code": bool(ERROR_CODE_RE.search(sym)) and schema.get("kind") == "enum"}
        return out

    def _extends_dto(self, d: Decl, depth: int = 0) -> bool:
        ext = d.extra.get("extends")
        if not ext or depth > 6:
            return False
        if re.match(r"(PartialType|PickType|OmitType|IntersectionType)\s*\(", ext.strip()):
            return True
        base = self.resolve(d.path, re.sub(r"<.*", "", ext).strip())
        return bool(base) and (base.kind == "class_validator_dto" or (base.kind == "class" and self._extends_dto(base, depth + 1)))

    @staticmethod
    def direction_of(d: Decl) -> str:
        s = d.symbol
        if re.search(r"(?i)(response|output|event|result|reply|view|projection)(schema|dto|v\d+)?$", s):
            return "output"
        if d.kind == "class_validator_dto":
            return "input"  # NestJS ValidationPipe validates inbound bodies/queries — the DTO is the accepted input
        if re.search(r"(?i)(request|input|body|query|params|payload|dto|command)(schema|v\d+)?$", s):
            return "input"
        return "bidirectional"

    # ---- resolution -----------------------------------------------------------------------------------------
    def resolve(self, path: str, name: str, depth: int = 0) -> Decl | None:
        """Follow the local declaration, an import, or (last resort) a unique symbol anywhere in the tree."""
        if depth > 8:
            return None
        name = name.strip()
        if name in self.decls.get(path, {}):
            return self.decls[path][name]
        imp = self.imports.get(path, {}).get(name)
        if imp:
            spec, imported = imp
            cands = [d for d in self.by_symbol.get(imported, []) if d.exported or d.path == path]
            if spec.startswith("."):
                base = build_graph.norm_path(os.path.join(os.path.dirname(path), spec))
                exact = [d for d in cands if d.path.startswith(base)]
                if exact:
                    return exact[0]
            if len(cands) == 1:
                return cands[0]
            if cands:
                # a barrel re-exports it: prefer the one whose directory shares the spec's package root
                return sorted(cands, key=lambda d: d.path)[0]
            return None
        cands = [d for d in self.by_symbol.get(name, []) if d.exported]
        return cands[0] if len(cands) == 1 else None

    def schema_of(self, d: Decl, stack: tuple = ()) -> dict:
        key = (d.path, d.symbol)
        if key in self._cache:
            return copy.deepcopy(self._cache[key])
        if key in stack:
            return {"kind": "ref", "name": d.symbol, "recursive": True}
        stack = stack + (key,)
        if d.kind == "zod":
            s = self.zod(d.body, d.path, stack)
        elif d.kind in ("class_validator_dto", "class"):
            s = self.cv_class(d, stack)
        elif d.kind == "type_alias_union":
            s = {"kind": "enum", "values": sort_values(d.extra["values"])}
        elif d.kind == "type_alias":
            s = self.ts_type(d.body, d.path, stack)
        elif d.kind in ("ts_enum", "enum_plain"):
            s = {"kind": "enum", "values": sort_values(d.extra["members"].values()), "members": dict(sorted(d.extra["members"].items()))}
        elif d.kind == "interface":
            s = self.members(d.body, d.path, stack, decorators=False)
            if d.extra.get("extends"):
                for b in split_top(d.extra["extends"], ","):
                    bd = self.resolve(d.path, re.sub(r"<.*", "", b))
                    if bd:
                        s = merge_objects(self.schema_of(bd, stack), s)
        elif d.kind == "const_array":
            s = {"kind": "enum", "values": sort_values(d.extra["values"])}
        elif d.kind == "const_object":
            vals = re.findall(r":\s*(['\"][^'\"]*['\"])", d.body)
            s = {"kind": "enum", "values": sort_values(parse_literal(v) for v in vals)}
        else:
            s = {"kind": "any"}
        self._cache[key] = s
        return copy.deepcopy(s)

    # ---- zod -------------------------------------------------------------------------------------------------
    def zod(self, expr: str, path: str, stack: tuple) -> dict:
        expr = expr.strip()
        m = re.match(r"\(\s*\)\s*=>\s*", expr)  # z.lazy(() => X)
        if m:
            expr = expr[m.end():]
        if expr.startswith("(") and match_close(expr, 0) == len(expr) - 1:
            return self.zod(expr[1:-1], path, stack)
        i = 0
        m = re.match(r"z\s*\.\s*(?:coerce\s*\.\s*)?" + IDENT + r"|" + IDENT, expr)
        if not m:
            return {"kind": "any", "unparsed": norm_ws(expr)[:80]}
        head = re.sub(r"\s+", "", m.group(0))
        i = m.end()
        args = None
        if i < len(expr) and expr[i] == "(":
            j = match_close(expr, i)
            args = expr[i + 1:j]
            i = j + 1
        parts = head.split(".")
        if parts[0] == "z":
            name = parts[-1] if parts[-1] != "coerce" else "any"
            schema = self.zod_base(name, args, path, stack)
        else:
            d = self.resolve(path, parts[0])
            schema = self.schema_of(d, stack) if d else {"kind": "ref", "name": parts[0], "unresolved": True}
            if args is not None:  # a schema factory call — treat the result as opaque
                schema = {"kind": "any", "call": head}
            # `Foo.shape.bar`: a property of another schema
            mm = re.match(r"\s*\.\s*shape\s*\.\s*(" + IDENT + r")", expr[i:])
            if mm:
                schema = schema.get("properties", {}).get(mm.group(1), {"kind": "any"})
                i += mm.end()
        # method chain
        while i < len(expr):
            m = re.match(r"\s*\.\s*(" + IDENT + r")", expr[i:])
            if not m:
                break
            meth = m.group(1)
            i += m.end()
            margs = None
            if i < len(expr) and expr[i] == "(":
                j = match_close(expr, i)
                margs = expr[i + 1:j]
                i = j + 1
            schema = self.zod_method(schema, meth, margs, path, stack)
        return schema

    def zod_base(self, name: str, args: str | None, path: str, stack: tuple) -> dict:
        prim = {"string": "string", "number": "number", "boolean": "boolean", "bigint": "bigint", "date": "date", "any": "any",
                "unknown": "any", "never": "never", "null": "null", "undefined": "undefined", "void": "undefined", "nan": "number",
                "symbol": "symbol", "int": "integer", "uuid": "string", "email": "string", "url": "string", "iso": "string"}
        if name in prim:
            s = {"kind": prim[name]}
            if name in ("uuid", "email", "url"):
                s["constraints"] = {"format": name}
            return s
        a = split_top(args or "", ",")
        if name == "literal":
            return {"kind": "enum", "values": [parse_literal(a[0])]} if a else {"kind": "any"}
        if name == "enum":
            vals = literal_list(a[0]) if a else None
            if vals is None and a:
                d = self.resolve(path, a[0])
                if d:
                    return self.schema_of(d, stack)
                return {"kind": "ref", "name": a[0], "unresolved": True}
            return {"kind": "enum", "values": sort_values(vals or [])}
        if name == "nativeEnum":
            d = self.resolve(path, a[0]) if a else None
            return self.schema_of(d, stack) if d else {"kind": "ref", "name": a[0] if a else "?", "unresolved": True}
        if name == "array":
            return {"kind": "array", "items": self.zod(a[0], path, stack) if a else {"kind": "any"}}
        if name == "set":
            return {"kind": "array", "items": self.zod(a[0], path, stack) if a else {"kind": "any"}, "unique": True}
        if name == "object" or name == "strictObject" or name == "looseObject":
            return self.zod_object(a[0] if a else "{}", path, stack)
        if name in ("union", "discriminatedUnion", "xor"):
            lst = a[-1] if a else "[]"
            lst = lst.strip()
            if lst.startswith("["):
                lst = lst[1:-1]
            variants = [self.zod(v, path, stack) for v in split_top(lst, ",")]
            return make_union(variants)
        if name == "intersection":
            l, r = (self.zod(a[0], path, stack), self.zod(a[1], path, stack)) if len(a) > 1 else ({"kind": "any"}, {"kind": "any"})
            return merge_objects(l, r) if l.get("kind") == r.get("kind") == "object" else {"kind": "intersection", "of": [l, r]}
        if name == "record":
            return {"kind": "record", "values": self.zod(a[-1], path, stack) if a else {"kind": "any"}}
        if name == "map":
            return {"kind": "record", "values": self.zod(a[-1], path, stack) if a else {"kind": "any"}}
        if name == "tuple":
            lst = a[0].strip()[1:-1] if a else ""
            return {"kind": "tuple", "items": [self.zod(v, path, stack) for v in split_top(lst, ",")]}
        if name == "optional":
            s = self.zod(a[0], path, stack) if a else {"kind": "any"}
            s["optional"] = True
            return s
        if name == "nullable":
            s = self.zod(a[0], path, stack) if a else {"kind": "any"}
            if self.on("nullable"):
                s["nullable"] = True
            return s
        if name == "lazy":
            return self.zod(a[0], path, stack) if a else {"kind": "any"}
        if name in ("preprocess", "effect", "pipe"):
            return self.zod(a[-1], path, stack) if a else {"kind": "any"}
        if name == "instanceof":
            return {"kind": "ref", "name": a[0] if a else "?", "instance": True}
        if name in ("function", "promise", "custom"):
            return {"kind": "any", "zod": name}
        return {"kind": "any", "zod": name}

    def zod_object(self, body: str, path: str, stack: tuple) -> dict:
        body = body.strip()
        if body.startswith("{") and body.endswith("}"):
            body = body[1:-1]
        props, required = {}, []
        for item in split_top(body, ","):
            if item.startswith("..."):
                ref = item[3:].strip()
                ref = re.sub(r"\.shape$", "", ref)
                sub = self.zod(ref, path, stack)
                if sub.get("kind") == "object":
                    props.update(sub["properties"])
                continue
            m = re.match(r"^\s*(?:(" + IDENT + r")|['\"]([^'\"]+)['\"]|\[([^\]]+)\])\s*:\s*", item)
            if not m:
                continue
            key = m.group(1) or m.group(2) or m.group(3)
            props[key] = self.zod(item[m.end():], path, stack)
        return finish_object(props)

    def zod_method(self, s: dict, meth: str, args: str | None, path: str, stack: tuple) -> dict:
        a = split_top(args or "", ",")
        kind = s.get("kind")
        if meth == "optional" or meth == "default" or meth == "catch":
            s["optional"] = True
        elif meth == "nullable":
            if self.on("nullable"):
                s["nullable"] = True
        elif meth == "nullish":
            s["optional"] = True
            if self.on("nullable"):
                s["nullable"] = True
        elif meth in ("min", "max", "length", "gte", "lte", "gt", "lt", "positive", "nonnegative", "negative", "nonpositive",
                      "int", "email", "uuid", "url", "datetime", "date", "time", "ip", "cuid", "cuid2", "ulid", "emoji", "regex",
                      "startsWith", "endsWith", "includes", "multipleOf", "safe", "finite", "nonempty", "trim", "toLowerCase",
                      "toUpperCase", "base64", "cidr", "duration", "nanoid"):
            if self.on("constraints"):
                self.apply_constraint(s, meth, a)
        elif meth == "array":
            s = {"kind": "array", "items": s}
        elif meth == "partial":
            if kind == "object":
                keys = list(s["properties"]) if not a else re.findall(IDENT + r"(?=\s*:)", a[0])
                for k in keys:
                    if k in s["properties"]:
                        s["properties"][k]["optional"] = True
                s = finish_object(s["properties"])
        elif meth == "deepPartial":
            s = deep_partial(s)
        elif meth == "required":
            if kind == "object":
                keys = list(s["properties"]) if not a else re.findall(IDENT + r"(?=\s*:)", a[0])
                for k in keys:
                    if k in s["properties"]:
                        s["properties"][k].pop("optional", None)
                s = finish_object(s["properties"])
        elif meth == "extend":
            ext = self.zod_object(a[0], path, stack) if a else {"kind": "object", "properties": {}}
            s = merge_objects(s, ext)
        elif meth == "merge" or meth == "and":
            other = self.zod(a[0], path, stack) if a else {"kind": "object", "properties": {}}
            s = merge_objects(s, other) if other.get("kind") == "object" and kind == "object" else s
        elif meth == "pick" or meth == "omit":
            if kind == "object" and a:
                keys = set(re.findall(r"(" + IDENT + r"|['\"][^'\"]+['\"])\s*:\s*true", a[0]))
                keys = {k.strip("'\"") for k in keys}
                props = {k: v for k, v in s["properties"].items() if (k in keys) == (meth == "pick")}
                s = finish_object(props)
        elif meth == "or":
            s = make_union([s, self.zod(a[0], path, stack)]) if a else s
        elif meth == "keyof":
            s = {"kind": "enum", "values": sort_values(s.get("properties", {}).keys())}
        elif meth == "element":
            s = s.get("items", {"kind": "any"})
        elif meth == "exclude" or meth == "extract":
            if kind == "enum" and a:
                vals = set(literal_list(a[0]) or [])
                s = {"kind": "enum", "values": sort_values(v for v in s["values"] if (v in vals) == (meth == "extract"))}
        elif meth in ("describe", "refine", "superRefine", "transform", "pipe", "brand", "readonly", "meta", "strict", "passthrough",
                      "strip", "strictObject", "check", "overwrite", "register", "openapi", "shape", "options", "unwrap", "innerType"):
            pass  # no effect on the accepted/produced shape (refinements are not schema)
        else:
            s.setdefault("unknown_methods", []).append(meth)
        return s

    @staticmethod
    def apply_constraint(s: dict, meth: str, a: list[str]):
        c = s.setdefault("constraints", {})
        kind = s.get("kind")
        num = parse_literal(a[0]) if a else None
        if meth in ("min", "gte"):
            c["minLength" if kind == "string" else "minItems" if kind == "array" else "min"] = num
        elif meth in ("max", "lte"):
            c["maxLength" if kind == "string" else "maxItems" if kind == "array" else "max"] = num
        elif meth == "gt":
            c["exclusiveMin"] = num
        elif meth == "lt":
            c["exclusiveMax"] = num
        elif meth == "length":
            c["minLength"] = c["maxLength"] = num
        elif meth == "nonempty":
            c["minLength" if kind == "string" else "minItems"] = 1
        elif meth == "positive":
            c["exclusiveMin"] = 0
        elif meth == "nonnegative":
            c["min"] = 0
        elif meth == "negative":
            c["exclusiveMax"] = 0
        elif meth == "nonpositive":
            c["max"] = 0
        elif meth == "int":
            s["kind"] = "integer"
        elif meth in ("regex", "startsWith", "endsWith", "includes"):
            c["pattern"] = norm_ws(a[0]) if a else "?"
        elif meth == "multipleOf":
            c["multipleOf"] = num
        elif meth in ("trim", "toLowerCase", "toUpperCase", "safe", "finite"):
            pass
        else:
            c["format"] = meth

    # ---- class-validator / TS types ----------------------------------------------------------------------------
    def cv_class(self, d: Decl, stack: tuple) -> dict:
        base = {"kind": "object", "properties": {}, "required": []}
        ext = d.extra.get("extends")
        if ext:
            base = self.mapped_type(ext, d.path, stack)
        own = self.members(d.body, d.path, stack, decorators=True)
        return merge_objects(base, own)

    def mapped_type(self, expr: str, path: str, stack: tuple) -> dict:
        expr = expr.strip()
        m = re.match(r"(PartialType|PickType|OmitType|IntersectionType|Partial|Pick|Omit)\s*\(", expr)
        if m:
            inner = expr[m.end():match_close(expr, m.end() - 1)]
            a = split_top(inner, ",")
            fn = m.group(1)
            if fn in ("PartialType", "Partial"):
                s = self.mapped_type(a[0], path, stack) if a else {"kind": "object", "properties": {}}
                if s.get("kind") == "object":
                    for p in s["properties"].values():
                        p["optional"] = True
                    s = finish_object(s["properties"])
                return s
            if fn in ("PickType", "OmitType", "Pick", "Omit"):
                s = self.mapped_type(a[0], path, stack) if a else {"kind": "object", "properties": {}}
                keys = set(literal_list(re.sub(r"\s*as\s+const\s*$", "", a[1])) or []) if len(a) > 1 else set()
                if s.get("kind") == "object":
                    s = finish_object({k: v for k, v in s["properties"].items() if (k in keys) == (fn in ("PickType", "Pick"))})
                return s
            if fn == "IntersectionType":
                s = {"kind": "object", "properties": {}}
                for part in a:
                    s = merge_objects(s, self.mapped_type(part, path, stack))
                return s
        name = re.sub(r"<.*", "", expr).strip()
        dd = self.resolve(path, name)
        if dd:
            return self.schema_of(dd, stack)
        return {"kind": "object", "properties": {}, "required": [], "unresolved_base": name}

    def members(self, body: str, path: str, stack: tuple, decorators: bool) -> dict:
        props: dict[str, dict] = {}
        i, n = 0, len(body)
        decos: list[tuple[str, str | None]] = []
        while i < n:
            c = body[i]
            if c.isspace() or c == ";" or c == ",":
                i += 1
                continue
            if c == "@":
                m = re.match(r"@(" + IDENT + r"(?:\." + IDENT + r")*)", body[i:])
                name = m.group(1)
                i += m.end()
                args = None
                if i < n and body[i] == "(":
                    j = match_close(body, i)
                    args = body[i + 1:j]
                    i = j + 1
                decos.append((name, args))
                continue
            m = re.match(r"(?:(?:public|private|protected|readonly|declare|static|override|abstract|accessor)\s+)*"
                         r"(?:(get|set)\s+)?(" + IDENT + r"|['\"][^'\"]+['\"]|\[[^\]]+\])\s*([?!]?)\s*", body[i:])
            if not m:
                i += 1
                continue
            i += m.end()
            name = m.group(2).strip("'\"")
            marker = m.group(3)
            if i < n and (body[i] == "(" or body[i] == "<") or m.group(1) or name == "constructor":
                # method / accessor / constructor → skip signature and block
                if i < n and body[i] == "<":
                    i = match_close(body, i, angle=True) + 1
                if i < n and body[i] == "(":
                    i = match_close(body, i) + 1
                while i < n and body[i] != "{" and body[i] != ";" and body[i] != "\n":
                    if body[i] in "([{":
                        i = match_close(body, i) + 1
                    else:
                        i += 1
                if i < n and body[i] == "{":
                    i = match_close(body, i) + 1
                decos = []
                continue
            ann = None
            if i < n and body[i] == ":":
                j = i + 1
                depth = 0
                while j < n:
                    ch = body[j]
                    if ch in "'\"`":
                        k = j + 1
                        while k < n and body[k] != ch:
                            k += 2 if body[k] == "\\" else 1
                        j = k + 1
                        continue
                    if ch in "([{<":
                        depth += 1
                    elif ch in ")]}>":
                        depth -= 1
                    elif depth == 0 and (ch == ";" or ch == "=" or (ch == "\n" and re.match(r"\s*(@|[\w$'\"[]+\s*[?!]?\s*[:(])", body[j + 1:j + 60]) and not body[i + 1:j].strip().endswith(("|", "&", ",")))):
                        break
                    j += 1
                ann = body[i + 1:j].strip()
                i = j
            if i < n and body[i] == "=":
                i = statement_end(body, i)
                default = True
            else:
                default = False
            schema = self.ts_type(ann, path, stack) if ann else {"kind": "any"}
            optional = marker == "?" or default or schema.pop("optional", False)
            if decorators:
                schema, optional = self.apply_decorators(schema, decos, ann, path, stack, optional)
            if optional:
                schema["optional"] = True
            props[name] = schema
            decos = []
        return finish_object(props)

    def ts_type(self, ann: str | None, path: str, stack: tuple) -> dict:
        if ann is None:
            return {"kind": "any"}
        t = ann.strip()
        while t.startswith("(") and match_close(t, 0) == len(t) - 1:
            t = t[1:-1].strip()
        parts = split_top(t, "|", angle=True)
        if len(parts) > 1 or t.startswith("|"):
            variants, nullable, optional = [], False, False
            for p in parts:
                p = p.strip()
                if p == "null":
                    nullable = True
                elif p == "undefined":
                    optional = True
                elif p:
                    variants.append(self.ts_type(p, path, stack))
            s = make_union(variants) if variants else {"kind": "null"}
            if nullable and self.on("nullable"):
                s["nullable"] = True
            if optional:
                s["optional"] = True
            return s
        if t.endswith("[]"):
            return {"kind": "array", "items": self.ts_type(t[:-2], path, stack)}
        m = re.match(r"(?:Readonly)?(Array|ReadonlyArray|Set)\s*<(.*)>$", t)
        if m:
            return {"kind": "array", "items": self.ts_type(m.group(2), path, stack)}
        m = re.match(r"(?:Readonly|Required|NonNullable)\s*<(.*)>$", t)
        if m:
            return self.ts_type(m.group(1), path, stack)
        m = re.match(r"Partial\s*<(.*)>$", t)
        if m:
            return deep_partial(self.ts_type(m.group(1), path, stack), shallow=True)
        m = re.match(r"(?:Record|Map)\s*<(.*)>$", t)
        if m:
            a = split_top(m.group(1), ",", angle=True)
            return {"kind": "record", "values": self.ts_type(a[-1], path, stack) if a else {"kind": "any"}}
        m = re.match(r"(Pick|Omit)\s*<(.*)>$", t)
        if m:
            a = split_top(m.group(2), ",", angle=True)
            s = self.ts_type(a[0], path, stack)
            keys = set(literal_list(a[1]) or []) if len(a) > 1 else set()
            if s.get("kind") == "object":
                s = finish_object({k: v for k, v in s["properties"].items() if (k in keys) == (m.group(1) == "Pick")})
            return s
        if t.startswith("{") and t.endswith("}"):
            return self.members(t[1:-1], path, stack, decorators=False)
        if t.startswith("[") and t.endswith("]"):
            return {"kind": "tuple", "items": [self.ts_type(p, path, stack) for p in split_top(t[1:-1], ",", angle=True)]}
        prim = {"string": "string", "number": "number", "boolean": "boolean", "bigint": "bigint", "Date": "date", "unknown": "any",
                "any": "any", "object": "object", "never": "never", "null": "null", "undefined": "undefined", "symbol": "symbol",
                "void": "undefined", "Buffer": "binary", "Uint8Array": "binary"}
        if t in prim:
            return {"kind": prim[t]} if prim[t] != "object" else {"kind": "object", "properties": {}, "required": [], "open": True}
        if t and (t[0] in "'\"`" or re.fullmatch(r"-?\d+(\.\d+)?|true|false", t)):
            return {"kind": "enum", "values": [parse_literal(t)]}
        m = re.match(r"typeof\s+(" + IDENT + r")\s*\[\s*number\s*\]$", t)
        if m:
            d = self.resolve(path, m.group(1))
            return self.schema_of(d, stack) if d else {"kind": "ref", "name": m.group(1), "unresolved": True}
        m = re.match(r"(?:keyof\s+)?typeof\s+(" + IDENT + r")$", t)
        if m:
            d = self.resolve(path, m.group(1))
            return self.schema_of(d, stack) if d else {"kind": "ref", "name": m.group(1), "unresolved": True}
        m = re.match(r"(" + IDENT + r")(?:\.(" + IDENT + r"))?(?:<.*>)?$", t)
        if m:
            d = self.resolve(path, m.group(1))
            if d:
                s = self.schema_of(d, stack)
                if m.group(2) and s.get("kind") == "enum" and "members" in s and m.group(2) in s["members"]:
                    return {"kind": "enum", "values": [s["members"][m.group(2)]]}
                return s
            return {"kind": "ref", "name": m.group(1), "unresolved": True}
        return {"kind": "any", "unparsed": norm_ws(t)[:80]}

    def apply_decorators(self, schema: dict, decos: list[tuple[str, str | None]], ann: str | None, path: str, stack: tuple,
                         optional: bool) -> tuple[dict, bool]:
        names = {n for n, _ in decos}
        is_array = "IsArray" in names or schema.get("kind") == "array" or any(a and re.search(r"\beach\s*:\s*true", a) for _, a in decos)
        item = schema.get("items", {"kind": "any"}) if schema.get("kind") == "array" else schema
        nullable = item.pop("nullable", False)
        typed = None  # the decorator-derived item schema
        cons: dict = {}
        for name, args in decos:
            a = split_top(args or "", ",")
            arg0 = a[0] if a else None
            if name == "IsOptional":
                optional = True
            elif name == "IsDefined":
                optional = False
            elif name == "IsString":
                typed = typed or {"kind": "string"}
            elif name in ("IsNumber", "IsNumberString", "IsDecimal"):
                typed = typed or {"kind": "number"}
            elif name == "IsInt":
                typed = {"kind": "integer"}
            elif name in ("IsBoolean", "IsBooleanString"):
                typed = typed or {"kind": "boolean"}
            elif name in ("IsDate",):
                typed = typed or {"kind": "date"}
            elif name in ("IsUUID", "IsEmail", "IsUrl", "IsDateString", "IsISO8601", "IsJWT", "IsHexadecimal", "IsIP", "IsFQDN",
                          "IsMongoId", "IsBase64", "IsJSON", "IsPhoneNumber", "IsSemVer", "IsHash", "IsAlpha", "IsAlphanumeric",
                          "IsNumberString", "IsAscii", "IsCreditCard", "IsCurrency", "IsHexColor", "IsLocale", "IsMimeType",
                          "IsMilitaryTime", "IsPort", "IsPostalCode", "IsRFC3339", "IsRgbColor", "IsTimeZone", "IsUppercase",
                          "IsLowercase", "IsLatitude", "IsLongitude", "IsMACAddress", "IsMagnetURI", "IsISBN", "IsISIN", "IsISRC",
                          "IsIBAN", "IsBIC", "IsEthereumAddress", "IsBtcAddress", "IsDataURI", "IsFirebasePushId", "IsHSL",
                          "IsIdentityCard", "IsISSN", "IsOctal", "IsPassportNumber", "IsSurrogatePair", "IsVariableWidth",
                          "IsHalfWidth", "IsFullWidth", "IsMultibyte", "IsStrongPassword", "IsTaxId", "IsEAN", "IsUUIDv4"):
                typed = {"kind": "string"}
                fmt = {"IsUUID": "uuid", "IsDateString": "date-time", "IsISO8601": "date-time", "IsUrl": "url", "IsEmail": "email",
                       "IsRFC3339": "date-time"}.get(name, name[2:].lower())
                if self.on("constraints"):
                    cons["format"] = fmt
            elif name == "IsIn":
                vals = literal_list(arg0) if arg0 else None
                if vals is None and arg0:
                    d = self.resolve(path, arg0)
                    typed = self.schema_of(d, stack) if d else {"kind": "ref", "name": arg0, "unresolved": True}
                else:
                    typed = {"kind": "enum", "values": sort_values(vals or [])}
            elif name == "IsEnum":
                d = self.resolve(path, arg0) if arg0 else None
                if d:
                    typed = self.schema_of(d, stack)
                elif arg0 and arg0.startswith("["):
                    typed = {"kind": "enum", "values": sort_values(literal_list(arg0) or [])}
                else:
                    typed = {"kind": "ref", "name": arg0 or "?", "unresolved": True}
            elif name == "Equals":
                typed = {"kind": "enum", "values": [parse_literal(arg0)]} if arg0 else typed
            elif name == "IsArray":
                is_array = True
            elif name == "ArrayNotEmpty":
                cons["minItems"] = 1
            elif name == "ArrayMinSize":
                cons["minItems"] = parse_literal(arg0)
            elif name == "ArrayMaxSize":
                cons["maxItems"] = parse_literal(arg0)
            elif name == "IsObject":
                typed = typed or {"kind": "object", "properties": {}, "required": [], "open": True}
            elif name == "Type":
                m = re.search(r"=>\s*(" + IDENT + r")", args or "")
                if m:
                    d = self.resolve(path, m.group(1))
                    if d and d.kind in ("class_validator_dto", "class", "interface"):
                        typed = self.schema_of(d, stack)
                    elif d is None and m.group(1) not in ("String", "Number", "Boolean", "Date", "Object", "Array"):
                        typed = {"kind": "ref", "name": m.group(1), "unresolved": True}
            elif name == "ValidateNested":
                pass  # the nested type comes from @Type / the annotation
            elif name == "IsNotEmpty":
                cons.setdefault("minLength", 1)
            elif name == "IsNotEmptyObject":
                pass
            elif name in ("MaxLength", "MinLength", "Min", "Max", "Length", "Matches", "Contains", "NotContains", "IsDivisibleBy",
                          "IsPositive", "IsNegative", "IsLatLong"):
                if self.on("constraints"):
                    if name == "MaxLength":
                        cons["maxLength"] = parse_literal(arg0)
                    elif name == "MinLength":
                        cons["minLength"] = parse_literal(arg0)
                    elif name == "Min":
                        cons["min"] = parse_literal(arg0)
                    elif name == "Max":
                        cons["max"] = parse_literal(arg0)
                    elif name == "Length":
                        cons["minLength"] = parse_literal(arg0)
                        if len(a) > 1 and not a[1].startswith("{"):
                            cons["maxLength"] = parse_literal(a[1])
                    elif name in ("Matches", "Contains", "NotContains"):
                        cons["pattern"] = norm_ws(arg0 or "?")
                    elif name == "IsPositive":
                        cons["exclusiveMin"] = 0
                    elif name == "IsNegative":
                        cons["exclusiveMax"] = 0
                    elif name == "IsDivisibleBy":
                        cons["multipleOf"] = parse_literal(arg0)
            elif name == "Allow":
                typed = {"kind": "any"}
            # other decorators (Transform, Expose, ApiProperty, ...) do not change the accepted shape
        if typed is not None:
            if typed.get("kind") == "string" and item.get("kind") == "enum" and "IsString" in names and not any(n in names for n in ("IsIn", "IsEnum")):
                pass  # @IsString on a union-typed field accepts any string — the decorator is the validation truth
            item = typed
        if "IsString" in names and typed and typed.get("kind") == "enum" and not ("IsIn" in names or "IsEnum" in names or "Equals" in names):
            item = {"kind": "string"}
        if cons and self.on("constraints"):
            item.setdefault("constraints", {}).update(cons)
        if nullable and self.on("nullable"):
            item["nullable"] = True
        if is_array:
            arr_cons = {k: item.get("constraints", {}).pop(k) for k in ("minItems", "maxItems") if k in item.get("constraints", {})}
            if item.get("constraints") == {}:
                item.pop("constraints", None)
            schema = {"kind": "array", "items": item}
            if arr_cons:
                schema["constraints"] = arr_cons
        else:
            schema = item
        return schema, optional


def finish_object(props: dict[str, dict]) -> dict:
    props = {k: props[k] for k in sorted(props)}
    required = sorted(k for k, v in props.items() if not v.get("optional"))
    return {"kind": "object", "properties": props, "required": required}


def merge_objects(a: dict, b: dict) -> dict:
    if a.get("kind") != "object":
        return b
    if b.get("kind") != "object":
        return a
    props = dict(a.get("properties", {}))
    props.update(b.get("properties", {}))
    out = finish_object(props)
    for k in ("open", "unresolved_base"):
        if a.get(k) or b.get(k):
            out[k] = a.get(k) or b.get(k)
    return out


def deep_partial(s: dict, shallow: bool = False) -> dict:
    if s.get("kind") != "object":
        return s
    props = {}
    for k, v in s["properties"].items():
        v = copy.deepcopy(v)
        v["optional"] = True
        props[k] = v if shallow else deep_partial(v)
    return finish_object(props)


def make_union(variants: list[dict]) -> dict:
    flat = []
    for v in variants:
        if v.get("kind") == "union":
            flat.extend(v["variants"])
        else:
            flat.append(v)
    if len(flat) == 1:
        return flat[0]
    if flat and all(v.get("kind") == "enum" for v in flat):
        vals = []
        for v in flat:
            vals.extend(v["values"])
        return {"kind": "enum", "values": sort_values(set(vals))}
    nullable = any(v.get("nullable") for v in flat)
    key = lambda v: canonical(v)  # noqa: E731
    flat = sorted({key(v): v for v in flat}.values(), key=key)
    if len(flat) == 1:
        return flat[0]
    s = {"kind": "union", "variants": flat}
    if nullable:
        s["nullable"] = True
    return s


# ----------------------------------------------------------------------------------------------- diff
class Differ:
    def __init__(self, disabled: set[str] | None = None):
        self.disabled = disabled or set()

    def on(self, rule: str) -> bool:
        return rule not in self.disabled

    def contract(self, cid: str, old: dict | None, new: dict | None, direction_override: str | None = None) -> dict:
        """Diff of one contract; returns {status, direction, changes[]} with severity per change."""
        c = old or new
        direction = direction_override or c["direction"]
        if not self.on("direction"):
            direction = "input"  # mutant: everything is treated as pure input (direction-dependent codes go compatible)
        error_code = bool(c.get("error_code")) or bool(new and new.get("error_code"))
        changes: list[dict] = []
        if old is None:
            changes.append(self.ch("CONTRACT_ADDED", "", f"{new['kind']} {new['symbol']} declared", direction, error_code))
            return {"status": "added", "direction": direction, "changes": changes}
        if new is None:
            if self.on("contract_removed"):
                changes.append(self.ch("CONTRACT_REMOVED", "", f"{old['kind']} {old['symbol']} no longer declared", direction, error_code))
            return {"status": "removed", "direction": direction, "changes": changes}
        if canonical(old["schema"]) == canonical(new["schema"]):
            if old["decl_hash"] != new["decl_hash"]:
                changes.append(self.ch("NON_SEMANTIC_TEXT", "", "declaration text changed, schema-lite equal (comments, messages, formatting)",
                                       direction, error_code))
                return {"status": "text_only", "direction": direction, "changes": changes}
            return {"status": "unchanged", "direction": direction, "changes": []}
        self.schema(old["schema"], new["schema"], "", changes, direction, error_code, top=True)
        if not changes:
            changes.append(self.ch("NON_SEMANTIC_TEXT", "", "schema-lite differs only in fields outside the taxonomy", direction, error_code))
            return {"status": "text_only", "direction": direction, "changes": changes}
        return {"status": "changed", "direction": direction, "changes": changes}

    @staticmethod
    def severity(code: str, direction: str) -> str:
        if code in BREAKING_ALWAYS:
            return "breaking"
        if code in BREAKING_UNLESS_INPUT:
            return "compatible" if direction == "input" else "breaking"
        if code in COMPATIBLE:
            return "compatible"
        return "info"

    def ch(self, code: str, path: str, detail: str, direction: str, error_code: bool, **extra) -> dict:
        if error_code and code.startswith("ENUM_VALUE_") and self.on("error_code"):
            extra["enum_code"] = code
            code = "ERROR_CODE_CHANGED"
        return {"code": code, "severity": self.severity(code, direction), "path": path, "detail": detail, **extra}

    def schema(self, a: dict, b: dict, path: str, out: list[dict], direction: str, error_code: bool, top: bool = False):
        ka, kb = a.get("kind"), b.get("kind")
        # nullable
        if self.on("nullable") and bool(a.get("nullable")) != bool(b.get("nullable")):
            if a.get("nullable"):
                out.append(self.ch("TYPE_NARROWED", path, "null no longer accepted", direction, error_code, aspect="nullable"))
            else:
                out.append(self.ch("TYPE_WIDENED", path, "null now allowed", direction, error_code, aspect="nullable"))
        if ka != kb:
            self.kind_change(a, b, path, out, direction, error_code)
            return
        if ka == "object":
            self.objects(a, b, path, out, direction, error_code)
        elif ka == "enum":
            va, vb = set(map(canonical, a.get("values", []))), set(map(canonical, b.get("values", [])))
            removed, added = sorted(va - vb), sorted(vb - va)
            if removed and self.on("enum_removed"):
                out.append(self.ch("ENUM_VALUE_REMOVED", path, f"values removed: {', '.join(removed)}", direction, error_code, values=removed))
            if added and self.on("enum_added"):
                out.append(self.ch("ENUM_VALUE_ADDED", path, f"values added: {', '.join(added)}", direction, error_code, values=added))
        elif ka == "array":
            if self.on("nested_diff"):
                self.schema(a.get("items", {}), b.get("items", {}), path + "[]", out, direction, error_code)
            self.constraints(a, b, path, out, direction, error_code)
        elif ka == "record":
            if self.on("nested_diff"):
                self.schema(a.get("values", {}), b.get("values", {}), path + "[*]", out, direction, error_code)
        elif ka == "tuple":
            ia, ib = a.get("items", []), b.get("items", [])
            if len(ia) != len(ib):
                out.append(self.ch("TYPE_CHANGED", path, f"tuple arity {len(ia)} → {len(ib)}", direction, error_code))
            elif self.on("nested_diff"):
                for i, (x, y) in enumerate(zip(ia, ib)):
                    self.schema(x, y, f"{path}[{i}]", out, direction, error_code)
        elif ka == "union":
            ca, cb = {canonical(v) for v in a["variants"]}, {canonical(v) for v in b["variants"]}
            if ca - cb and self.on("type_narrowed"):
                out.append(self.ch("TYPE_NARROWED", path, f"{len(ca - cb)} union variant(s) removed", direction, error_code, aspect="union"))
            if cb - ca and self.on("type_widened"):
                out.append(self.ch("TYPE_WIDENED", path, f"{len(cb - ca)} union variant(s) added", direction, error_code, aspect="union"))
        elif ka == "ref":
            if a.get("name") != b.get("name"):
                out.append(self.ch("TYPE_CHANGED", path, f"reference {a.get('name')} → {b.get('name')}", direction, error_code))
        else:
            self.constraints(a, b, path, out, direction, error_code)

    def kind_change(self, a: dict, b: dict, path: str, out: list[dict], direction: str, error_code: bool):
        ka, kb = a.get("kind"), b.get("kind")
        widen = {("integer", "number"), ("enum", "string"), ("enum", "number"), ("enum", "integer"), ("enum", "boolean"),
                 ("literal", "string"), ("date", "string"), ("null", "any"), ("undefined", "any")}
        narrow = {(y, x) for x, y in widen}
        if kb == "any" or (kb == "union" and any(canonical(strip_flags(v)) == canonical(strip_flags(a)) for v in b["variants"])):
            if self.on("type_widened"):
                out.append(self.ch("TYPE_WIDENED", path, f"{ka} → {kb}", direction, error_code))
        elif ka == "any" or (ka == "union" and any(canonical(strip_flags(v)) == canonical(strip_flags(b)) for v in a["variants"])):
            if self.on("type_narrowed"):
                out.append(self.ch("TYPE_NARROWED", path, f"{ka} → {kb}", direction, error_code))
        elif (ka, kb) in widen:
            if self.on("type_widened"):
                out.append(self.ch("TYPE_WIDENED", path, f"{ka} → {kb}", direction, error_code))
        elif (ka, kb) in narrow:
            if self.on("type_narrowed"):
                out.append(self.ch("TYPE_NARROWED", path, f"{ka} → {kb}" + (f" {b.get('values')}" if kb == "enum" else ""), direction, error_code))
        elif ka == "enum" and kb == "enum":
            pass
        else:
            if self.on("type_changed"):
                out.append(self.ch("TYPE_CHANGED", path, f"{ka} → {kb}", direction, error_code))

    def constraints(self, a: dict, b: dict, path: str, out: list[dict], direction: str, error_code: bool):
        if not self.on("constraints"):
            return
        ca, cb = a.get("constraints", {}), b.get("constraints", {})
        narrowed, widened = [], []
        for k in sorted(set(ca) | set(cb)):
            va, vb = ca.get(k), cb.get(k)
            if va == vb:
                continue
            if k in ("maxLength", "max", "maxItems", "exclusiveMax"):
                if vb is None or (va is not None and vb > va):
                    widened.append(f"{k} {va}→{vb}")
                else:
                    narrowed.append(f"{k} {va}→{vb}")
            elif k in ("minLength", "min", "minItems", "exclusiveMin"):
                if vb is None or (va is not None and vb < va):
                    widened.append(f"{k} {va}→{vb}")
                else:
                    narrowed.append(f"{k} {va}→{vb}")
            elif k in ("format", "pattern", "multipleOf"):
                if vb is None:
                    widened.append(f"{k} {va}→none")
                elif va is None:
                    narrowed.append(f"{k} none→{vb}")
                else:
                    narrowed.append(f"{k} {va}→{vb}")
                    widened.append(f"{k} {va}→{vb}")
            else:
                narrowed.append(f"{k} {va}→{vb}")
        if narrowed and self.on("type_narrowed"):
            out.append(self.ch("TYPE_NARROWED", path, "constraints tightened: " + "; ".join(narrowed), direction, error_code, aspect="constraints"))
        if widened and self.on("type_widened"):
            out.append(self.ch("TYPE_WIDENED", path, "constraints relaxed: " + "; ".join(widened), direction, error_code, aspect="constraints"))

    def objects(self, a: dict, b: dict, path: str, out: list[dict], direction: str, error_code: bool):
        pa, pb = a.get("properties", {}), b.get("properties", {})
        removed = [k for k in pa if k not in pb]
        added = [k for k in pb if k not in pa]
        renamed = {}
        if self.on("field_renamed"):
            for r in removed:
                sig = canonical(strip_flags(pa[r]))
                match = [x for x in added if x not in renamed.values() and canonical(strip_flags(pb[x])) == sig
                         and bool(pa[r].get("optional")) == bool(pb[x].get("optional"))]
                if len(match) == 1:
                    renamed[r] = match[0]
        for r in removed:
            p = f"{path}.{r}" if path else r
            if r in renamed:
                out.append(self.ch("FIELD_RENAMED", p, f"field renamed {r} → {renamed[r]} (identical schema)", direction, error_code, new_name=renamed[r]))
            elif self.on("field_removed"):
                out.append(self.ch("FIELD_REMOVED", p, f"field {r} removed", direction, error_code))
        for x in added:
            if x in renamed.values():
                continue
            p = f"{path}.{x}" if path else x
            if pb[x].get("optional"):
                out.append(self.ch("FIELD_ADDED_OPTIONAL", p, f"optional field {x} added", direction, error_code))
            elif self.on("new_required"):
                out.append(self.ch("NEW_REQUIRED_FIELD", p, f"required field {x} added", direction, error_code))
        for k in sorted(set(pa) & set(pb)):
            p = f"{path}.{k}" if path else k
            oa, ob = bool(pa[k].get("optional")), bool(pb[k].get("optional"))
            if oa and not ob and self.on("made_required"):
                out.append(self.ch("FIELD_MADE_REQUIRED", p, f"field {k} optional → required", direction, error_code))
            elif ob and not oa and self.on("required_to_optional"):
                out.append(self.ch("REQUIRED_TO_OPTIONAL", p, f"field {k} required → optional", direction, error_code))
            if self.on("nested_diff") or not path:
                self.schema(pa[k], pb[k], p, out, direction, error_code)


def strip_flags(s: dict) -> dict:
    return {k: v for k, v in s.items() if k not in ("optional",)}


# ----------------------------------------------------------------------------------------------- consumer projection
def _executable_text(code, issues=None, literals=None):
    """Keep executable template expressions, masking only inert text at identical offsets."""
    issues = issues if issues is not None else []
    literals = literals if literals is not None else []
    out = list(code)

    def mask(start, end):
        for i in range(start, end):
            if out[i] != '\n':
                out[i] = ' '

    def quoted(start):
        i = start + 1
        while i < len(code):
            if code[i] == '\\':
                i += 2
                continue
            if code[i] == code[start]:
                literals.append((start, i + 1))
                mask(start, i + 1)
                return i + 1
            if code[i] in '\r\n':
                break
            i += 1
        mask(start, len(code))
        issues.append('unterminated quoted text')
        return len(code)

    def template(start, depth):
        if depth > 16:
            mask(start, len(code))
            issues.append('template nesting exceeds bounded scan')
            return len(code)
        i, text, interpolated = start + 1, start, False
        while i < len(code):
            if code[i] == '\\':
                i += 2
            elif code[i] == '`':
                if not interpolated:
                    literals.append((start, i + 1))
                mask(text, i + 1)
                return i + 1
            elif code[i:i + 2] == '${':
                interpolated = True
                mask(text, i + 2)
                i = scan(i + 2, True, depth + 1)
                text = i
            else:
                i += 1
        mask(text, len(code))
        issues.append('unterminated template literal')
        return len(code)

    def regexp(start):
        i, character_class = start + 1, False
        while i < len(code) and code[i] not in '\r\n':
            if code[i] == '\\':
                i += 2
                continue
            if code[i] == '[':
                character_class = True
            elif code[i] == ']':
                character_class = False
            elif code[i] == '/' and not character_class:
                i += 1
                flags = re.match(r'[A-Za-z]*', code[i:]).group()
                if len(set(flags)) != len(flags) or set(flags) - set('dgimsuy'):
                    issues.append('unsupported regexp flags')
                i += len(flags)
                mask(start, i)
                return i
            i += 1
        issues.append('unterminated regexp literal')
        mask(start, len(code))
        return len(code)

    def jsx(start, depth):
        # Tags/text are inert; braces retain executable expressions at their
        # original offsets. Unsupported TS assertions and malformed JSX stay NM.
        def unknown(reason):
            issues.append(reason)
            mask(start, len(code))
            return len(code)

        if depth > 16:
            return unknown('JSX nesting exceeds bounded scan')
        opening = re.match(r'<([A-Za-z_$][\w$.:\-]*|)(?=[\s/>])', code[start:])
        if not opening:
            return unknown('unsupported JSX opening')
        name = opening.group(1)
        i = start + opening.end()
        mask(start, i)
        while i < len(code):
            if code[i:i + 2] == '/>':
                mask(i, i + 2)
                return i + 2
            if code[i] == '>':
                mask(i, i + 1)
                i += 1
                break
            if code[i] in "'\"":
                count = len(literals)
                i = quoted(i)
                del literals[count:]  # JSX string attributes never become uses.
            elif code[i] == '{':
                mask(i, i + 1)
                i = scan(i + 1, True, depth + 1)
            elif code[i] == '<':
                return unknown('unsupported JSX attribute')
            else:
                mask(i, i + 1)
                i += 1
        else:
            return unknown('unterminated JSX opening')
        while i < len(code):
            if code[i:i + 2] == '</':
                closing_tag = re.match(r'</' + re.escape(name) + r'\s*>', code[i:])
                if not closing_tag:
                    return unknown('mismatched JSX closing')
                end = i + closing_tag.end()
                mask(i, end)
                return end
            if code[i] == '<':
                i = jsx(i, depth + 1)
            elif code[i] == '{':
                mask(i, i + 1)
                i = scan(i + 1, True, depth + 1)
            else:
                mask(i, i + 1)
                i += 1
        return unknown('unterminated JSX element')

    def scan(start, interpolation=False, depth=0):
        i, braces, parens, previous, operand = start, [], [], None, True
        closing = {'(': ')', '[': ']', '{': '}'}
        while i < len(code):
            if code[i] in "'\"":
                i = quoted(i)
                operand, previous = False, 'literal'
            elif code[i] == '`':
                i = template(i, depth)
                operand, previous = False, 'literal'
            elif code[i:i + 2] in ('//', '/*'):
                marker = '\n' if code[i:i + 2] == '//' else '*/'
                end = code.find(marker, i + 2)
                if end < 0 and marker == '*/':
                    issues.append('unterminated block comment')
                end = len(code) if end < 0 else end + (0 if marker == '\n' else 2)
                mask(i, end)
                i = end
            elif code[i] == '<' and operand is True and re.match(r'<(?:[A-Za-z_$]|>)', code[i:]):
                i = jsx(i, depth + 1)
                operand, previous = False, 'literal'
            elif code[i] == '/':
                if operand is None:
                    issues.append('ambiguous slash expression')
                    mask(i, len(code))
                    return len(code)
                if operand:
                    i = regexp(i)
                    operand, previous = False, 'literal'
                else:
                    i += 2 if code[i:i + 2] == '/=' else 1
                    operand, previous = True, '/'
            elif code[i] in closing:
                if interpolation:
                    braces.append(closing[code[i]])
                if code[i] == '(':
                    parens.append(previous in ('if', 'while', 'for', 'with', 'switch', 'catch'))
                operand, previous = True, code[i]
                i += 1
            elif code[i] in ')]}':
                if interpolation and code[i] == '}' and not braces:
                    mask(i, i + 1)
                    return i + 1
                if interpolation and (not braces or braces.pop() != code[i]):
                    issues.append('unbalanced template interpolation')
                    mask(i, len(code))
                    return len(code)
                control = parens.pop() if code[i] == ')' and parens else False
                operand = None if control or code[i] == '}' else False
                previous = code[i]
                i += 1
            elif code[i].isspace():
                i += 1
            elif re.match(r'[A-Za-z_$]', code[i]):
                word = re.match(r'[A-Za-z_$][\w$]*', code[i:]).group()
                operand = word in ('return', 'throw', 'case', 'delete', 'void', 'typeof', 'yield', 'await', 'in', 'of')
                previous, i = word, i + len(word)
            elif code[i].isdigit():
                number = re.match(r'[\w.]+', code[i:]).group()
                operand, previous, i = False, number, i + len(number)
            elif code[i:i + 2] in ('++', '--'):
                previous, i = code[i:i + 2], i + 2
            else:
                operand, previous = True, code[i]
                i += 1
        if interpolation:
            issues.append('unterminated template interpolation')
        return i

    scan(0)
    return ''.join(out)


def _shadow_ranges(code, name):
    ranges = []
    for m in re.finditer(r"\b(?:const|let|var|class|function)\s+" + re.escape(name) + r"\b", code):
        ranges.append(enclosing_block(code, m.start()))
    for m in re.finditer(r"\(([^()]*)\)\s*(?::[^{};=]*)?(?:=>)?\s*\{", code):
        # A control expression has uses, never parameter declarations.
        if re.search(r"\b(?:if|while|for|with|switch)\s*$", code[:m.start()]):
            continue
        if '=>' not in m.group(1) and any(re.match(r"\s*" + re.escape(name) + r"\s*(?:[?:=]|$)", p) for p in m.group(1).split(',')):
            ranges.append((m.start(), match_close(code, m.end() - 1) + 1))
    for m in re.finditer(r"\b" + re.escape(name) + r"\s*=>\s*", code):
        start = m.end()
        if start < len(code) and code[start] == '{':
            end = match_close(code, start) + 1
        else:
            stack, end = [], start
            closing = {'(': ')', '[': ']', '{': '}'}
            while end < len(code):
                c = code[end]
                if not stack and c in ',;)]}':
                    break
                if c in closing:
                    stack.append(closing[c])
                elif c in ')]}':
                    if not stack or stack.pop() != c:
                        break
                end += 1
        ranges.append((m.start(), end))
    return ranges


def projection(code: str, symbol: str, schema: dict, disabled: set[str] | None = None, *, known_zod=False, runtime_names=None,
               enum_literal_values=None) -> dict:
    """What the consumer file uses of the contract: keys read, keys sent (object literals), enum values used."""
    disabled = disabled or set()
    lexical_issues = []
    literals = []
    executable = _executable_text(code, lexical_issues, literals)
    # Keep literal keys/comparison operands but never regexp bodies, comments,
    # or template text. All views preserve offsets for scope attribution.
    literal_code = list(executable)
    for start, end in literals:
        if code[start] != '`':
            literal_code[start:end] = code[start:end]
    code = ''.join(literal_code)
    keys_read: set[str] = set()
    keys_sent: set[str] = set()
    literals_sent = 0
    values: set = set()
    incomplete: list[str] = list(lexical_issues)
    bindings: set[str] = set()
    sym = "(?:" + "|".join(re.escape(n) for n in (runtime_names or [symbol])) + ")"
    type_ref = r"(?:z\.(?:infer|input|output)\s*<\s*typeof\s+)?(?:Readonly<|Partial<|Omit<|Pick<)?\s*" + sym + r"\b(?:\s*>)*"
    literal_bindings: set[str] = set()
    scoped: list[tuple[str, int, int]] = []  # (name, scope_start, scope_end) — a binding is read only inside its own function body
    array_scoped: set[tuple[str, int, int]] = set()
    array_declarations = []
    wrappers: list[tuple[str, int, int]] = []
    wrapper_unresolved = False
    enum_runtime_unresolved = False
    binding_code = executable if schema.get("kind") == "enum" else code
    typed_ref = (r"(?:(?P<array_wrapper>(?:ReadonlyArray|Array))\s*<\s*" + type_ref + r"\s*>|"
                 + type_ref + r"(?P<array_suffix>\s*\[\s*\])?)")
    for m in re.finditer(r"\b(" + IDENT + r")\s*\??\s*:\s*" + typed_ref, binding_code):
        bindings.add(m.group(1))
        scope = (m.group(1), *scope_of(binding_code, m.start(), m.end()))
        scoped.append(scope)
        if m.group('array_wrapper') or m.group('array_suffix'):
            array_scoped.add(scope)
            array_declarations.append(m)
    for m in re.finditer(r"\b(" + IDENT + r")\s*=\s*(?:new\s+" + sym + r"\(|plainToInstance\(\s*" + sym + r"\b|" + sym + r"\.(?:parse|parseAsync)\(|[^;\n]*\bas\s+" + typed_ref + r")", binding_code):
        bindings.add(m.group(1))
        scope = (m.group(1), *enclosing_block(binding_code, m.start()))
        scoped.append(scope)
        if m.group('array_wrapper') or m.group('array_suffix'):
            array_scoped.add(scope)
            array_declarations.append(m)
    if known_zod:
        # safeParse returns a discriminated result, NOT the contract payload.
        # Only a declaration bound directly to the extracted runtime Zod schema
        # establishes a wrapper; arbitrary `.safeParse` methods are not certified.
        schema_shadows = [span for name in (runtime_names or [symbol]) for span in _shadow_ranges(executable, name)]
        proven_calls = set()
        for m in re.finditer(r"\b(?:const|let)\s+(" + IDENT + r")\s*=\s*" + sym + r"\s*\.\s*safeParse\s*\(", executable):
            if any(a <= m.start() < z for a, z in schema_shadows):
                wrapper_unresolved = True
                incomplete.append("runtime Zod schema binding shadowed")
                continue
            b = m.group(1)
            bindings.add(b)
            proven_calls.add(m.end() - 1)
            end = match_close(executable, m.end() - 1) + 1
            wrappers.append((b, end, enclosing_block(executable, m.start())[1]))
        for m in re.finditer(r"\b" + sym + r"\s*\.\s*safeParse(?:Async)?\s*\(", executable):
            if m.end() - 1 not in proven_calls:
                wrapper_unresolved = True
                incomplete.append('safeParse result has no proven local binding')
        if wrappers and schema.get('kind') != 'object':
            wrapper_unresolved = True
            incomplete.append('safeParse payload projection requires an object schema')
    if schema.get("kind") == "object":
        def array_unresolved(reason):
            incomplete.append(reason)
            # The executable projection cannot determine the element usage.
            # Keep the existing fail-first/NM protocol; never certify opacity
            # just because this revision did not change the provider schema.
            lexical_issues.append(reason)

        def array_payload_literal(expr):
            nonlocal literals_sent
            expr = expr.strip()
            if not expr.startswith('{') or match_close(expr, 0) != len(expr) - 1:
                array_unresolved('array element payload is not a bounded literal')
                return
            literals_sent += 1
            for item in split_top(expr[1:-1], ','):
                if not item.strip():
                    continue
                key = re.match(r"^\s*(?:(" + IDENT + r")|['\"]([^'\"]+)['\"])\s*(?::|$)", item)
                if item.startswith('...') or not key:
                    array_unresolved('array element spread/computed key unresolved')
                else:
                    keys_sent.add(key.group(1) or key.group(2))

        for declaration in array_declarations:
            tail = re.match(r'\s*=\s*\[', code[declaration.end():])
            if tail:
                ob = declaration.end() + tail.end() - 1
                cb = match_close(code, ob)
                for item in split_top(code[ob + 1:cb], ','):
                    if item.strip():
                        array_payload_literal(item)
            elif re.search(r'\bas\s+', declaration.group(0)):
                rhs = declaration.group(0).split('=', 1)[1].strip()
                if rhs.startswith('['):
                    cb = match_close(rhs, 0)
                    for item in split_top(rhs[1:cb], ','):
                        if item.strip():
                            array_payload_literal(item)
                else:
                    array_unresolved('asserted array initial payload unresolved')
        # destructured parameters typed with the symbol
        for m in re.finditer(r"\(\s*\{([^{}]*)\}\s*:\s*" + type_ref, code):
            keys_read.update(destructured_keys(m.group(1), incomplete))
        # typed object literals: const x: Sym = { ... } / generic call post<Sym>(url, {...}) / {...} satisfies Sym
        for m in re.finditer(r"(?:\b(" + IDENT + r")\s*)?:\s*" + type_ref + r"(?:\[\])?\s*=\s*\{|<\s*" + type_ref + r"\s*>\s*\([^{)]*\{|satisfies\s+" + type_ref, code):
            ob = code.find("{", m.start()) if not m.group(0).startswith("satisfies") else code.rfind("{", 0, m.start())
            if ob < 0:
                continue
            if m.group(1):
                literal_bindings.add(m.group(1))
            cb = match_close(code, ob)
            for item in split_top(code[ob + 1:cb], ","):
                if item.startswith("..."):
                    incomplete.append("spread in object literal")
                    continue
                km = re.match(r"^\s*(?:(" + IDENT + r")|['\"]([^'\"]+)['\"])\s*(?::|$)", item)
                if km:
                    keys_sent.add(km.group(1) or km.group(2))
            literals_sent += 1
        for b, s0, s1 in sorted(scoped):
            if (b, s0, s1) in array_scoped:
                # T[] / Array<T> bind a CONTAINER. Its members are not fields
                # of T; only actual element payloads contribute provider keys.
                shadowed = [(a, z) for a, z in _shadow_ranges(executable, b)
                            if s0 <= a and z <= s1 and (a, z) != (s0, s1)]
                seg = ''.join(' ' if any(a <= s0 + i < z for a, z in shadowed) else ch
                              for i, ch in enumerate(code[s0:s1]))
                seg_exec = ''.join(' ' if any(a <= s0 + i < z for a, z in shadowed) else ch
                                   for i, ch in enumerate(executable[s0:s1]))
                for member in re.finditer(r"\b" + re.escape(b) + r"\s*\??\.\s*(" + IDENT + r")", seg_exec):
                    name = member.group(1)
                    if name == 'length':
                        continue
                    call = re.match(r'\s*\(', seg_exec[member.end():])
                    if name in ('push', 'unshift') and call:
                        ob = member.end() + call.end() - 1
                        cb = match_close(seg, ob)
                        for arg in split_top(seg[ob + 1:cb], ','):
                            if arg.strip():
                                array_payload_literal(arg)
                    else:
                        array_unresolved(f'array container {b}.{name} element projection unresolved')
                for index in re.finditer(r"\b" + re.escape(b) + r"\s*\[", seg_exec):
                    ob = index.end() - 1
                    cb = match_close(seg, ob)
                    key = re.match(r"\s*\??\.\s*(" + IDENT + r")", seg_exec[cb + 1:])
                    if key:
                        keys_read.add(key.group(1))
                    if not key or not re.fullmatch(r'\s*\d+\s*', seg[ob + 1:cb]):
                        array_unresolved(f'array container {b} computed/whole element use unresolved')
                if re.search(r'[(,]\s*' + re.escape(b) + r'\s*[,)]|\breturn\s+' + re.escape(b) + r'\s*[;}]', seg_exec):
                    array_unresolved(f'array container {b} forwarded as a whole')
                if re.search(r'\.\.\.\s*' + re.escape(b) + r'\b|\bfor\s*\([^)]*\b(?:in|of)\s+' + re.escape(b) + r'\b', seg_exec):
                    array_unresolved(f'array container {b} spread/iteration unresolved')
                continue
            seg = executable[s0:s1]
            for m in re.finditer(r"\b" + re.escape(b) + r"\s*\??\.\s*(" + IDENT + r")", seg):
                keys_read.add(m.group(1))
            for m in re.finditer(r"\{([^{}]*)\}\s*=\s*" + re.escape(b) + r"\b", seg):
                keys_read.update(destructured_keys(m.group(1), incomplete))
            if re.search(r"\.\.\.\s*" + re.escape(b) + r"\b", seg):
                incomplete.append(f"spread of {b}")
            if re.search(r"\b" + re.escape(b) + r"\s*\[", seg):
                incomplete.append(f"computed access on {b}")
            # forwarded as a whole to another call (usage continues elsewhere) — unless we saw its full literal
            if b not in literal_bindings and re.search(r"[(,]\s*" + re.escape(b) + r"\s*[,)]", seg):
                incomplete.append(f"{b} forwarded to a call")
            if re.search(r"\bfor\s*\(\s*(?:const|let)\s+\w+\s+(?:in|of)\s+(?:Object\.\w+\()?" + re.escape(b) + r"\b", seg):
                incomplete.append(f"iteration over {b}")
        for b, s0, s1 in wrappers:
            seg = executable[s0:s1]
            # A nested declaration shadows this binding. Keep only uses in the
            # proven lexical range, rather than treating same-name locals as Zod.
            shadowed = []
            for a, z in _shadow_ranges(executable, b):
                if a >= s0 and z <= s1:
                    shadowed.append((a - s0, z - s0))
            seg = ''.join(' ' if any(a <= i < z for a, z in shadowed) else ch for i, ch in enumerate(seg))
            reassignment = re.search(r"\b" + re.escape(b) + r"\s*=(?!=)", seg)
            if reassignment:
                incomplete.append(f"safeParse binding {b} reassigned")
                wrapper_unresolved = True
                seg = seg[:reassignment.start()]
            for m in re.finditer(r"\b" + re.escape(b) + r"\b", seg):
                tail = seg[m.end():]
                member = re.match(r"\s*\??\.\s*(" + IDENT + r")", tail)
                if member and member.group(1) in {"success", "error"}:
                    continue  # result metadata is not a provider field
                if member and member.group(1) == "data":
                    payload = tail[member.end():]
                    key = re.match(r"\s*\??\.\s*(" + IDENT + r")", payload)
                    if key:
                        keys_read.add(key.group(1))
                        continue
                # Whole result/payload forwarding, computed access and aliases
                # require a downstream projection we have not proven locally.
                incomplete.append(f"safeParse result/payload {b} usage unresolved")
                wrapper_unresolved = True
        if not bindings and not keys_read and not keys_sent:
            incomplete.append("no binding of the contract type found in the consumer")
    elif schema.get("kind") == "enum":
        # A matching literal elsewhere in the file is not evidence about this
        # contract. Attribute comparisons/initializers to its unshadowed bindings,
        # and retain incomplete usage when the value escapes that bounded surface.
        symbol_shadows = [enclosing_block(executable, m.start())
                          for m in re.finditer(r"\b(?:type|interface|enum|class|const|let|var|function)\s+" + sym + r"\b", executable)]
        if known_zod:
            symbol_shadows += schema_shadows
            imports = [(m.start(), m.end()) for m in re.finditer(r'\bimport\b[^;]*;', executable)]
            # Passing the schema itself to a helper is a runtime boundary whose
            # inputs/results are not projected here. Type-only references and
            # imported names do not establish runtime use.
            for m in re.finditer(r'[(,=]\s*(' + sym + r')\b(?!\s*\.)', executable):
                pos = m.start(1)
                if not any(a <= pos < z for a, z in imports + symbol_shadows):
                    incomplete.append('enum runtime schema forwarding unresolved')
                    enum_runtime_unresolved = True
        declarations = list(re.finditer(r"\b(" + IDENT + r")\s*\??\s*:\s*" + type_ref + r"(?:\[\])?", executable))
        for m in re.finditer(r"\b" + sym + r"\s*\.\s*(" + IDENT + r")", code):
            if (known_zod and executable[m.start():m.start() + len(m.group(0))] == m.group(0)
                    and m.group(1) in ('parse', 'parseAsync', 'safeParse', 'safeParseAsync', 'options')
                    and any(a <= m.start() < z for a, z in symbol_shadows)):
                incomplete.append('runtime Zod enum schema binding shadowed')
                enum_runtime_unresolved = True
            if executable[m.start():m.start() + len(m.group(0))] == m.group(0) and not any(a <= m.start() < z for a, z in symbol_shadows):
                if known_zod and m.group(1) in ('parse', 'parseAsync', 'safeParse', 'safeParseAsync', 'options'):
                    incomplete.append('enum runtime options/iteration unresolved' if m.group(1) == 'options'
                                      else 'enum runtime parsing input/result unresolved')
                    enum_runtime_unresolved = True
                else:
                    values.add(m.group(1))
        for m in re.finditer(r"\b(?:const|let)\s+" + IDENT + r"\s*:\s*(?:Readonly<)?Record<\s*" + sym + r"\s*,", executable):
            if any(a <= m.start() < z for a, z in symbol_shadows):
                continue
            # Only literal keys of an explicitly contract-keyed Record count.
            # Computed keys/spreads or an initializer we cannot delimit stay NM.
            tail = re.match(r"[^;=]*=\s*\{", code[m.end():])
            if not tail:
                incomplete.append("enum Record initializer unresolved")
                continue
            ob = m.end() + tail.end() - 1
            cb = match_close(code, ob)
            for item in split_top(code[ob + 1:cb], ","):
                key = re.match(r"\s*(?:([\w$]+)|(['\"])([^'\"]+)\2)\s*:", item)
                if key:
                    values.add(key.group(1) or key.group(3))
                elif item.strip():
                    incomplete.append("enum Record key unresolved")
        for b, s0, s1 in sorted(scoped):
            owned = [m for m in declarations if m.group(1) == b and scope_of(binding_code, m.start(), m.end()) == (s0, s1)]
            if owned and all(any(a <= m.start() < z for a, z in symbol_shadows) for m in owned):
                continue
            seg = code[s0:s1]
            shadowed = [(a, z) for a, z in _shadow_ranges(executable, b)
                        if s0 <= a and z <= s1 and (a, z) != (s0, s1)]
            shadowed += symbol_shadows
            attributed = []
            for m in owned:
                attributed.append((m.start(), m.end()))
                init = re.match(r"\s*=\s*(['\"])([^'\"]+)\1", code[m.end():])
                if init and not any(a <= m.start() < z for a, z in symbol_shadows):
                    values.add(init.group(2))
                    if not re.match(r"\s*(?:[;,]|$)", code[m.end() + init.end():]):
                        incomplete.append(f"enum binding {b} initializer unresolved")
            for m in re.finditer(r"\b" + re.escape(b) + r"\s*[!=]==?\s*(['\"])([^'\"]+)\1|(['\"])([^'\"]+)\3\s*[!=]==?\s*" + re.escape(b) + r"\b", seg):
                binding_start = s0 + (m.start() if m.group(1) else m.end() - len(b))
                if executable[binding_start:binding_start + len(b)] != b or any(a <= binding_start < z for a, z in shadowed):
                    continue
                values.add(m.group(2) or m.group(4))
                attributed.append((binding_start, binding_start + len(b)))
            for m in re.finditer(r"switch\s*\(\s*" + re.escape(b) + r"\s*\)\s*\{", seg):
                binding_start = s0 + seg.index(b, m.start(), m.end())
                if any(a <= binding_start < z for a, z in shadowed):
                    continue
                cb = match_close(seg, m.end() - 1)
                for cm in re.finditer(r"\bcase\s+(['\"])([^'\"]+)\1", seg[m.end():cb]):
                    values.add(cm.group(2))
                attributed.append((binding_start, binding_start + len(b)))
            for m in re.finditer(r"\b" + re.escape(b) + r"\b", executable[s0:s1]):
                pos = s0 + m.start()
                if any(a <= pos < z for a, z in shadowed + attributed):
                    continue
                incomplete.append(f"enum binding {b} usage unresolved")
        if not values:
            incomplete.append("no literal of the enum used in the consumer (exhaustiveness unknown)")
    else:
        incomplete.append(f"projection not defined for schema kind {schema.get('kind')}")
    if "consumer_incomplete" in disabled:
        incomplete = []
    return {"bindings": sorted(bindings), "keys_read": sorted(keys_read), "keys_sent": sorted(keys_sent), "literals_sent": literals_sent,
            "values_used": sort_values(values), "complete": not incomplete, "incomplete_reasons": sorted(set(incomplete)),
            "safeparse_unresolved": wrapper_unresolved, "lexical_projection_unresolved": bool(lexical_issues),
            "enum_runtime_unresolved": enum_runtime_unresolved}


def scope_of(code: str, start: int, end: int) -> tuple[int, int]:
    """Scope of a typed binding: a parameter (`, x: T)` / `(x: T,`) is read inside the function body that follows the
    parameter list; a variable (`const x: T = ...`) inside its enclosing block."""
    j = end
    while j < len(code) and code[j] in " \t":
        j += 1
    if j < len(code) and code[j] in ",)":
        depth = 0
        k = start
        while k < len(code):
            ch = code[k]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            k += 1
        # k = closing paren of the parameter list; the body opens at the next `{` (or `=>` for arrows)
        m = re.compile(r"\s*(?::[^{;=]*)?(?:=>)?\s*\{").match(code, k + 1)
        if m:
            ob = m.end() - 1
            return ob, match_close(code, ob) + 1
        return k, min(len(code), k + 400)
    return enclosing_block(code, start)


def enclosing_block(code: str, pos: int) -> tuple[int, int]:
    depth = 0
    k = pos - 1
    while k >= 0:
        ch = code[k]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                if ch == "{":
                    return k, match_close(code, k) + 1
                depth = 0
            else:
                depth -= 1
        k -= 1
    return 0, len(code)


def destructured_keys(inner: str, incomplete: list[str]) -> set[str]:
    keys = set()
    for part in split_top(inner, ","):
        part = part.strip()
        if part.startswith("..."):
            incomplete.append("rest element in destructuring")
            continue
        m = re.match(r"(" + IDENT + r"|['\"][^'\"]+['\"])", part)
        if m:
            keys.add(m.group(1).strip("'\""))
    return keys


def edge_verdict(proj: dict, head: dict | None, contract_diff: dict, provenance: str, disabled: set[str] | None = None) -> tuple[str, list[str]]:
    """Tri-valued verdict for one consumer edge."""
    d = disabled or set()
    reasons: list[str] = []
    breaking = [c for c in contract_diff["changes"] if c["severity"] == "breaking"]
    if head is None:
        return "failed", ["contract no longer declared at head"]
    schema = head["schema"]
    failed = False
    if schema.get("kind") == "object":
        props = set(schema.get("properties", {}))
        for k in proj["keys_read"]:
            if k not in props and "consumer_keys" not in d:
                failed = True
                reasons.append(f"consumer reads key `{k}` that the provider does not declare")
        for k in proj["keys_sent"]:
            if k not in props and not schema.get("open") and "consumer_keys" not in d:
                failed = True
                reasons.append(f"consumer sends key `{k}` that the provider does not declare")
        if proj["literals_sent"] and proj["complete"] and "consumer_required" not in d:
            for r in schema.get("required", []):
                if r not in proj["keys_sent"]:
                    failed = True
                    reasons.append(f"consumer literal omits required key `{r}`")
        used = set(proj["keys_read"]) | set(proj["keys_sent"])
        for c in breaking:
            top = c["path"].split(".")[0].split("[")[0]
            if top and top in used:
                failed = True
                reasons.append(f"breaking change {c['code']} at `{c['path']}` sits on a key the consumer uses")
    elif schema.get("kind") == "enum":
        vals = {canonical(v) for v in schema.get("values", [])}
        members = set(schema.get("members", {}))
        for v in proj["values_used"]:
            if canonical(v) not in vals and v not in members and "consumer_values" not in d:
                failed = True
                reasons.append(f"consumer uses enum value `{v}` that the provider no longer declares")
    for c in breaking:
        if c["code"] == "CONTRACT_REMOVED":
            failed = True
            reasons.append("contract removed")
    if failed:
        return "failed", reasons
    if proj.get('lexical_projection_unresolved'):
        return 'not_measured', ['executable consumer projection unresolved: ' + '; '.join(proj['incomplete_reasons'])]
    if proj.get("safeparse_unresolved"):
        return "not_measured", ["safeParse result/payload usage not proven: " + "; ".join(proj["incomplete_reasons"])]
    if proj.get("enum_runtime_unresolved"):
        return "not_measured", ["enum runtime parsing usage not proven: " + "; ".join(proj["incomplete_reasons"])]
    if not breaking:
        if provenance != "deterministic" and not proj["complete"]:
            return "not_measured", ["inferred edge and consumer usage not narrowable: " + "; ".join(proj["incomplete_reasons"])]
        return "verified", ["no breaking change; consumer usage ⊆ provider" + ("" if proj["complete"] else
                            " (usage not fully narrowable: " + "; ".join(proj["incomplete_reasons"]) + " — nothing changed to break it)")]
    if not proj["complete"]:
        return "not_measured", ["provider has breaking change(s) and consumer usage is not narrowable: " + "; ".join(proj["incomplete_reasons"])]
    unattributable = [c for c in breaking if c["code"] in ("ENUM_VALUE_ADDED", "ERROR_CODE_CHANGED", "TYPE_WIDENED", "REQUIRED_TO_OPTIONAL")
                      and (schema.get("kind") == "enum" or not c["path"])]
    if unattributable:
        return "not_measured", [f"{c['code']} on a {contract_diff['direction']} contract: consumer exhaustiveness/handling unknown" for c in unattributable]
    return "verified", ["breaking change(s) do not touch the consumer's used surface: " + ", ".join(sorted({c['code'] for c in breaking}))]


# ----------------------------------------------------------------------------------------------- run
def edges_from_graph(graph: dict) -> list[dict]:
    return [e for e in graph["edges"] if e["type"] in ("implements_contract", "consumes_contract") and e["to"].startswith("contract:")]


def discover_edges(ex_h: Extractor, ch: dict, ex_b: Extractor, cb: dict) -> list[dict]:
    """Without a graph: provider = declaring file; consumers = files importing the symbol (deterministic). Consumers of a
    contract that no longer exists at head are taken from the base revision (the import still names it)."""
    edges: dict[tuple, dict] = {}
    for cid, c in {**cb, **ch}.items():
        edges[(c["path"], "implements_contract", cid)] = {"from": f"code_unit:{c['path']}", "type": "implements_contract", "to": cid,
                                                         "provenance": "deterministic", "via": "declaration"}
    for ex, contracts, tag in ((ex_h, ch, "head"), (ex_b, cb, "base")):
        by_path_sym = {(c["path"], c["symbol"]): cid for cid, c in contracts.items()}
        for path, imps in ex.imports.items():
            if tag == "base" and path not in ex_h.tree.files:
                continue
            for local, (spec, imported) in imps.items():
                d = ex.resolve(path, local)
                if d and (d.path, d.symbol) in by_path_sym and d.path != path:
                    key = (path, "consumes_contract", by_path_sym[(d.path, d.symbol)])
                    edges.setdefault(key, {"from": f"code_unit:{path}", "type": "consumes_contract", "to": key[2], "provenance": "deterministic",
                                           "via": "import-symbol" if tag == "head" else "import-symbol@base", "symbol": imported})
    return list(edges.values())


def run_diff(base_tree: build_graph.Tree, head_tree: build_graph.Tree, *, graph: dict | None = None, directions: dict | None = None,
             consumer_keys: dict | None = None, disabled: set[str] | None = None, repo_name: str = "", only: set[str] | None = None,
             metadata_root: Path | None = None, metadata_git_repo: Path | None = None) -> dict:
    disabled = disabled or set()
    ex_b, ex_h = Extractor(base_tree, disabled), Extractor(head_tree, disabled)
    cb, ch = ex_b.contracts(), ex_h.contracts()
    if only:
        cb = {k: v for k, v in cb.items() if k in only or v["symbol"] in only}
        ch = {k: v for k, v in ch.items() if k in only or v["symbol"] in only}
    for src, dst, ex in ((cb, ch, ex_h), (ch, cb, ex_b)):
        for cid, c in src.items():
            if cid in dst:
                continue
            d = ex.decls.get(c["path"], {}).get(c["symbol"])
            if d and d.exported:  # same symbol, no longer (or not yet) a contract kind → diff the shapes
                dst[cid] = {**c, "schema": ex.schema_of(d), "decl_hash": sha_text(norm_ws(d.text)), "kind": c["kind"],
                            "error_code": c.get("error_code") and ex.schema_of(d).get("kind") == "enum", "kind_at_rev": d.kind}
    if not cb and not ch:
        raise Refusal("NO_CONTRACTS", "neither revision declares a contract the extractors understand (zod / class-validator / union / enum)")
    differ = Differ(disabled)
    directions = directions or {}
    contracts = {}
    for cid in sorted(set(cb) | set(ch)):
        o, n = cb.get(cid), ch.get(cid)
        sym = (o or n)["symbol"]
        res = differ.contract(cid, o, n, directions.get(cid) or directions.get(sym))
        contracts[cid] = {"kind": (o or n)["kind"], "path": (o or n)["path"], "symbol": sym, "status": res["status"], "direction": res["direction"],
                          "decl_hash_base": o and o["decl_hash"], "decl_hash_head": n and n["decl_hash"], "changes": res["changes"],
                          "error_code": bool((o or n).get("error_code"))}
    # Native compiler evidence applies to this internal metadata transport only.
    # No caller-supplied proof, direction override or generic enum exception enters here.
    metadata_proof, metadata_covered = None, set()
    if metadata_root is not None:
        import metadata_contract_proof
        target = metadata_contract_proof.CONTRACT
        changed = contracts.get(target, {}).get("changes", [])
        if changed and all(c["code"] == "ENUM_VALUE_ADDED" for c in changed):
            metadata_proof = metadata_contract_proof.observe(head_tree, metadata_root, git_repo=metadata_git_repo)
            observation = (metadata_proof.get("observation") or {}).get("observation", {})
            values = ch.get(target, {}).get("schema", {}).get("values", [])
            if (metadata_proof.get("source_observation_closed") and not metadata_proof["errors"]
                    and set(values) == set(observation.get("union", []))):
                metadata_covered = set(observation.get("covered_consumers", []))
                for change in changed:
                    change["severity"] = "compatible"
                    change["compatibility_basis"] = "native source-bound metadata input and closed consumers"
                contracts[target]["native_metadata_proof"] = metadata_proof
    breaking = [{"contract": cid, **c} for cid, c in contracts.items() for c in c["changes"] if c["severity"] == "breaking"]
    # edges
    edges_in = edges_from_graph(graph) if graph else discover_edges(ex_h, ch, ex_b, cb)
    # `--only` narrows WHAT IS MEASURED, so it has to narrow the OBLIGATIONS with it. Filtering the
    # contract maps alone left every graph edge whose target had just been filtered out still in the
    # run, where it could only land on `not_measured` ("contract node has no extracted schema at
    # either revision") and drive the process exit code to 1 — so "check everything except this one
    # contract" was not expressible at all (measured by A2-274). The number of edges the narrowing
    # dropped is REPORTED, never silent: a narrowed run has to say how much it did not look at.
    out_of_scope = 0
    if only:
        in_scope = [e for e in edges_in if e["to"] in contracts]
        out_of_scope = len(edges_in) - len(in_scope)
        edges_in = in_scope
    edges_out = []
    for e in sorted(edges_in, key=lambda e: (e["to"], e["type"], e["from"])):
        cid = e["to"]
        if cid not in contracts:
            edges_out.append({"edge": e, "verdict": "not_measured", "reasons": ["contract node has no extracted schema at either revision"]})
            continue
        cd = contracts[cid]
        if e["type"] == "implements_contract":
            v = "failed" if any(c["severity"] == "breaking" for c in cd["changes"]) else "verified"
            edges_out.append({"edge": e, "verdict": v, "reasons": [f"provider side: {cd['status']}" + (f", {len([c for c in cd['changes'] if c['severity']=='breaking'])} breaking" if v == "failed" else "")]})
            continue
        frm = e["from"]
        path = frm.split(":", 1)[1]
        headc = ch.get(cid)
        if path in head_tree.files:
            local_names = []
            for local in ex_h.imports.get(path, {}):
                declaration = ex_h.resolve(path, local)
                if declaration and declaration.path == cd['path'] and declaration.symbol == cd['symbol']:
                    local_names.append(local)
            schema = (headc or cb[cid])["schema"]
            # A removed literal remains a consumer obligation: head-only values
            # must not erase its use before edge_verdict checks the head schema.
            enum_literals = sort_values(
                value for candidate in (schema, cb.get(cid, {}).get('schema', {}))
                if candidate.get('kind') == 'enum' for value in candidate.get('values', []))
            proj = projection(head_tree.text(path), cd["symbol"], schema, disabled,
                              known_zod=(headc or cb[cid])["kind"] == "zod", runtime_names=local_names or None,
                              enum_literal_values=enum_literals)
        else:
            proj = {"bindings": [], "keys_read": [], "keys_sent": [], "literals_sent": 0, "values_used": [], "complete": False,
                    "incomplete_reasons": ["consumer file absent at head"]}
        v, reasons = edge_verdict(proj, headc, cd, e.get("provenance", "deterministic"), disabled)
        if metadata_proof and cd.get("native_metadata_proof") is metadata_proof:
            if path in metadata_covered and v != "failed":
                v, reasons = "verified", ["native compiler proved this metadata consumer's symbol-bound handling and closure"]
                proj["native_metadata_observation_sha256"] = metadata_proof["observation_sha256"]
            elif path not in metadata_covered and v != "failed":
                v, reasons = "not_measured", ["metadata consumer is outside the native compiler's proven symbol closure"]
        rec = {"edge": e, "verdict": v, "reasons": reasons, "projection": proj}
        if e.get("provenance") != "deterministic":
            rec["requires_canary"] = True
        edges_out.append(rec)
    for cid, keys in (consumer_keys or {}).items():
        if only and cid not in contracts:
            out_of_scope += 1   # a declared external consumer of a contract this run does not measure
            continue
        if cid not in contracts:
            edges_out.append({"edge": {"from": keys["from"], "type": "consumes_contract", "to": cid, "provenance": "observed"}, "verdict": "not_measured",
                              "reasons": ["declared external consumer, contract not extracted"]})
            continue
        proj = {"bindings": ["<external>"], "keys_read": [], "keys_sent": sorted(keys["keys"]), "literals_sent": 1, "values_used": [], "complete": True,
                "incomplete_reasons": []}
        v, reasons = edge_verdict(proj, ch.get(cid), contracts[cid], "observed", disabled)
        edges_out.append({"edge": {"from": keys["from"], "type": "consumes_contract", "to": cid, "provenance": "observed", "via": "declared-consumer-keys"},
                          "verdict": v, "reasons": reasons, "projection": proj})
    statuses = {}
    for c in contracts.values():
        statuses[c["status"]] = statuses.get(c["status"], 0) + 1
    verdicts = {}
    for e in edges_out:
        verdicts[e["verdict"]] = verdicts.get(e["verdict"], 0) + 1
    codes = {}
    for c in contracts.values():
        for chg in c["changes"]:
            codes[chg["code"]] = codes.get(chg["code"], 0) + 1
    return {"schema": OUT_SCHEMA, "tool": TOOL, "tool_version": VERSION, "repo": repo_name or base_tree.meta.get("source_repo"),
            "base": {"commit": base_tree.meta["source_commit"], "rev": base_tree.meta.get("rev"), "tree": base_tree.meta.get("source_tree")},
            "head": {"commit": head_tree.meta["source_commit"], "rev": head_tree.meta.get("rev"), "tree": head_tree.meta.get("source_tree"),
                     "dirty": head_tree.meta.get("dirty", False)},
            "graph": {"source_commit": graph["manifest"]["source_commit"], "graph_digest": graph["manifest"].get("graph_digest")} if graph else None,
            "edge_source": "graph" if graph else "discovered-by-import",
            "contracts": contracts, "breaking": breaking, "edges": edges_out,
            **({"native_metadata_proof": metadata_proof} if metadata_proof is not None else {}),
            "limitations": sorted(set(ex_b.limitations + ex_h.limitations)),
            "summary": {"contracts_base": len(cb), "contracts_head": len(ch), "statuses": dict(sorted(statuses.items())), "codes": dict(sorted(codes.items())),
                        "breaking": len(breaking), "edges": len(edges_out), "edge_verdicts": dict(sorted(verdicts.items())),
                        **({"only": {"contracts": sorted(only), "edges_out_of_scope": out_of_scope}} if only else {})}}


def exit_code_for(result: dict) -> int:
    ev = result["summary"]["edge_verdicts"]
    return 1 if result["summary"]["breaking"] or ev.get("failed") or ev.get("not_measured") else 0


def human(result: dict) -> str:
    lines = [f"contract-diff {result['base']['commit'][:12]} → {result['head']['commit'][:12]}: {result['summary']['contracts_base']} → "
             f"{result['summary']['contracts_head']} contracts; statuses {result['summary']['statuses']}; breaking {result['summary']['breaking']}; "
             f"edges {result['summary']['edges']} {result['summary']['edge_verdicts']}"]
    narrowed = result["summary"].get("only")
    if narrowed:
        lines.append(f"  NARROWED by --only to {len(narrowed['contracts'])} contract id/symbol(s): "
                     f"{', '.join(narrowed['contracts'][:6])}; {narrowed['edges_out_of_scope']} edge(s) "
                     f"out of scope and NOT measured by this run")
    for cid, c in result["contracts"].items():
        if c["status"] in ("unchanged",):
            continue
        lines.append(f"  {c['status']:<9} {cid} [{c['kind']}, {c['direction']}]")
        for ch in c["changes"]:
            lines.append(f"    {ch['severity']:<10} {ch['code']:<22} {ch['path'] or '-':<30} {ch['detail']}")
    for e in result["edges"]:
        if e["verdict"] != "verified":
            lines.append(f"  edge {e['verdict']:<12} {e['edge']['from']} → {e['edge']['to']}: {'; '.join(e['reasons'])}")
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------------- selftest
def fixture_battery(disabled: set[str]) -> list[dict]:
    exp = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    checks = []
    for pair in exp["pairs"]:
        d = FIXTURE_DIR / pair["dir"]
        try:
            res = run_diff(load_tree_dir(d / "base"), load_tree_dir(d / "head"), disabled=disabled, directions=pair.get("directions"),
                           consumer_keys=pair.get("consumer_keys"))
        except Refusal as r:
            checks.append({"name": f"{pair['dir']}: diff runs", "ok": False, "refusal": r.code, "detail": r.detail})
            continue
        got_breaking = sorted({b["code"] for b in res["breaking"]})
        exp_breaking = sorted(pair.get("breaking", []))
        fn = sorted(set(exp_breaking) - set(got_breaking))
        fp = sorted(set(got_breaking) - set(exp_breaking))
        label = pair["dir"].split("-", 1)[1].split("-")[0]
        checks.append({"name": f"{pair['dir']}: breaking codes exactly {exp_breaking}", "ok": not fn and not fp, "got": got_breaking,
                       "false_negative": fn, "false_positive": fp, "label": label})
        got_codes = sorted({c["code"] for c in res["contracts"].values() for c in c["changes"]})
        exp_comp = sorted(pair.get("compatible", []))
        if exp_comp:
            checks.append({"name": f"{pair['dir']}: compatible/info codes ⊇ {exp_comp}", "ok": set(exp_comp) <= set(got_codes), "got": got_codes, "label": label})
        for cid, st in pair.get("statuses", {}).items():
            got = res["contracts"].get(cid, {}).get("status")
            checks.append({"name": f"{pair['dir']}: {cid} status {st}", "ok": got == st, "got": got, "label": label})
        for key, want in pair.get("edges", {}).items():
            frm, to = key.split("→")
            got = [e for e in res["edges"] if e["edge"]["from"] == frm and e["edge"]["to"] == to]
            gv = got[0]["verdict"] if got else None
            checks.append({"name": f"{pair['dir']}: edge {key} verdict {want}", "ok": gv == want, "got": gv,
                           "reasons": got[0]["reasons"] if got else ["edge not found"], "label": label})
    return checks


def selftest(receipt_out: Path | None, pilot: Path | None, pilot_graph: Path | None, pilot_out: Path | None) -> int:
    t0 = time.monotonic()
    checks = fixture_battery(set())
    exp = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    n_pairs = len(exp["pairs"])
    fn_total = sum(len(c.get("false_negative", [])) for c in checks)
    fp_total = sum(len(c.get("false_positive", [])) for c in checks)
    checks.append({"name": f"acceptance: ≥ 30 fixture pairs ({n_pairs})", "ok": n_pairs >= 30, "pairs": n_pairs})
    checks.append({"name": f"acceptance: 0 false negatives on breaking changes (got {fn_total})", "ok": fn_total == 0, "false_negatives": fn_total})
    checks.append({"name": f"acceptance: ≤ 1 false positive (got {fp_total})", "ok": fp_total <= 1, "false_positives": fp_total})
    # determinism
    d0 = FIXTURE_DIR / exp["pairs"][0]["dir"]
    r1 = dump(run_diff(load_tree_dir(d0 / "base"), load_tree_dir(d0 / "head")))
    r2 = dump(run_diff(load_tree_dir(d0 / "base"), load_tree_dir(d0 / "head")))
    checks.append({"name": "determinism: the same pair diffed twice is byte-identical", "ok": r1 == r2})
    # identity
    ri = run_diff(load_tree_dir(d0 / "head"), load_tree_dir(d0 / "head"))
    checks.append({"name": "identity: head vs head → 0 changes, every contract unchanged, every edge verified or not_measured-by-projection",
                   "ok": ri["summary"]["breaking"] == 0 and set(ri["summary"]["statuses"]) == {"unchanged"}})
    # every taxonomy code is exercised by ≥ 1 fixture
    seen = set()
    for pair in exp["pairs"]:
        seen.update(pair.get("breaking", []))
        seen.update(pair.get("compatible", []))
    missing = sorted(set(TAXONOMY) - seen)
    checks.append({"name": "every taxonomy code has ≥ 1 fixture", "ok": not missing, "missing": missing, "taxonomy": TAXONOMY})
    # ts-mini coverage: every contract node of the builder's graph has a schema-lite
    ts_mini = ROOT / "contracts" / "graph-verified-change" / "fixtures" / "ts-mini"
    try:
        g = build_graph.build(ts_mini, worktree=True, built_at="2026-09-05T00:00:00Z")
        gc = {n["id"] for n in g["nodes"] if n["type"] == "contract"}
        ex = Extractor(build_graph.load_tree_worktree(ts_mini)).contracts()
        miss = sorted(gc - set(ex))
        checks.append({"name": f"ts-mini: every contract node of the builder graph ({len(gc)}) has an extracted schema-lite", "ok": not miss, "missing": miss,
                       "extracted": len(ex)})
    except Exception as e:  # noqa: BLE001
        checks.append({"name": "ts-mini: extraction over the builder fixture tree", "ok": False, "error": repr(e)})
    # negative control
    ctrl_ok = False
    try:
        bad = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
        bad["pairs"][0]["breaking"] = ["FIELD_REMOVED", "TYPE_CHANGED", "ENUM_VALUE_REMOVED"]
        tmp = EXPECTED_PATH.with_name("EXPECTED.negative-control.tmp.json")
        orig = EXPECTED_PATH
        try:
            globals()["EXPECTED_PATH"] = tmp
            tmp.write_bytes(dump(bad))
            ctrl = fixture_battery(set())
            ctrl_ok = any(not c["ok"] and c["name"].startswith(bad["pairs"][0]["dir"]) for c in ctrl)
        finally:
            globals()["EXPECTED_PATH"] = orig
            tmp.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    checks.append({"name": "selftest negative control: a wrong expectation is reported red", "ok": ctrl_ok})
    n_ok = sum(1 for c in checks if c["ok"])
    print(f"fixture battery: {n_ok}/{len(checks)} checks ({n_pairs} pairs, FN {fn_total}, FP {fp_total})")
    for c in checks:
        if not c["ok"]:
            print("  FAIL", c["name"], {k: v for k, v in c.items() if k not in ("name", "ok")})
    # mutation battery
    mutants = {}
    for rule in RULES:
        red = [c["name"] for c in fixture_battery({rule}) if not c["ok"]]
        mutants[rule] = {"killed": bool(red), "killed_by": red[:4], "n_red": len(red)}
    survived = [r for r, m in mutants.items() if not m["killed"]]
    checks.append({"name": f"mutation battery: disabling each of the {len(RULES)} rules turns ≥ 1 expectation red (0 mutants survived)",
                   "ok": not survived, "survived": survived})
    print(f"mutation battery: {len(RULES) - len(survived)}/{len(RULES)} mutants killed" + (f"; SURVIVED {survived}" if survived else ""))
    receipt = {"schema": "ReadinessReceipt/v1", "portion_id": "AUP-GRAPH-004:contract-diff0", "tool": TOOL, "tool_version": VERSION,
               "captured_at_utc": now_iso(), "host": os.uname().nodename, "python": sys.version.split()[0],
               "checks": checks, "mutation_battery": {"rules": RULES, "results": mutants, "survived": survived},
               "fixtures": {"pairs": n_pairs, "expected": str(EXPECTED_PATH.relative_to(ROOT)), "false_negatives": fn_total, "false_positives": fp_total,
                            "labels": dict(sorted(count_labels(exp).items()))},
               "taxonomy": {"breaking_always": sorted(BREAKING_ALWAYS), "breaking_unless_input": sorted(BREAKING_UNLESS_INPUT),
                            "compatible": sorted(COMPATIBLE), "info": sorted(INFO)},
               "limitations": ["TypeScript compiler not used: regex/AST-lite extraction (comment- and string-aware); generics, conditional and mapped "
                               "types beyond Partial/Pick/Omit/Record, computed keys and schema factories reduce to `any`/`ref`",
                               "class-validator: decorators are the validation truth; custom validators (@Validate, @ValidateIf, @ValidateBy) are not modelled",
                               "zod: refinements/transforms are not part of the schema-lite (they change accepted values but not the wire shape)",
                               "consumer projection is per file (no data-flow across files); a forwarded / spread object makes the edge not_measured under a breaking change",
                               "cross-repo enums are checked only against consumers reachable in the given tree or declared with --consumer-keys"]}
    pilot_ok = True
    if pilot:
        pres = run_pilot(pilot, pilot_graph, pilot_out)
        receipt["pilot"] = pres
        pilot_ok = all(c["ok"] for c in pres["checks"])
        print(f"pilot: {sum(1 for c in pres['checks'] if c['ok'])}/{len(pres['checks'])} checks")
        for c in pres["checks"]:
            if not c["ok"]:
                print("  PILOT FAIL", c["name"], {k: v for k, v in c.items() if k not in ("name", "ok")})
    all_ok = all(c["ok"] for c in checks) and pilot_ok
    receipt["summary"] = {"checks_ok": sum(1 for c in checks if c["ok"]), "checks_total": len(checks), "mutants_killed": len(RULES) - len(survived),
                          "mutants_total": len(RULES), "pairs": n_pairs, "false_negatives": fn_total, "false_positives": fp_total,
                          "pilot_checks_ok": sum(1 for c in receipt.get("pilot", {}).get("checks", []) if c["ok"]),
                          "pilot_checks_total": len(receipt.get("pilot", {}).get("checks", [])), "seconds": round(time.monotonic() - t0, 1)}
    receipt["verdict"] = "PASS" if all_ok else "FAIL"
    receipt["not_measured"] = ["Auth Arcana ↔ clients: no clone of Auth Arcana or of its clients on this host — the cross-repo half of the pilot clause is NOT MEASURED",
                               "OpenAPI-generated schemas: Muneral has no OpenAPI emitter at the pilot commit — kind `openapi` NOT MEASURED"]
    if receipt_out:
        receipt_out.parent.mkdir(parents=True, exist_ok=True)
        receipt_out.write_bytes(dump(receipt))
        print(f"receipt: {receipt_out}")
    print(f"SELFTEST {receipt['verdict']} ({receipt['summary']['checks_ok']}/{receipt['summary']['checks_total']} checks, "
          f"{receipt['summary']['mutants_killed']}/{receipt['summary']['mutants_total']} mutants killed, {n_pairs} pairs FN {fn_total} FP {fp_total}"
          + (f", pilot {receipt['summary']['pilot_checks_ok']}/{receipt['summary']['pilot_checks_total']}" if pilot else "") + ")")
    return 0 if all_ok else 1


def count_labels(exp: dict) -> dict:
    out = {}
    for p in exp["pairs"]:
        lab = p["dir"].split("-", 2)[1]
        out[lab] = out.get(lab, 0) + 1
    return out


# ----------------------------------------------------------------------------------------------- pilot
def run_pilot(pilot: Path, pilot_graph: Path | None, out_dir: Path | None) -> dict:
    checks: list[dict] = []
    top = Path(git(["rev-parse", "--show-toplevel"], pilot).strip())
    head = git(["rev-parse", "HEAD"], top).strip()
    porcelain = git(["status", "--porcelain"], top).strip()
    checks.append({"name": "pilot clone is clean and untouched (git status --porcelain empty)", "ok": porcelain == "", "head": head})
    graph = None
    if pilot_graph:
        graph = json.loads(pilot_graph.read_text(encoding="utf-8"))
        viol = schema_check.check_graph(graph, schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH))
        checks.append({"name": "pilot graph loads and is RelationshipGraph/v1 conformant", "ok": not viol, "violations": viol[:3],
                       "source_commit": graph["manifest"]["source_commit"]})
        checks.append({"name": "pilot graph source_commit == clone HEAD (contract edges are read from the graph)", "ok": graph["manifest"]["source_commit"] == head})
    head_tree = build_graph.load_tree_git(top, head, "")
    ex_head = Extractor(head_tree)
    ch = ex_head.contracts()
    result = {"head": head, "contracts_at_head": len(ch), "kinds": {}}
    for c in ch.values():
        result["kinds"][c["kind"]] = result["kinds"].get(c["kind"], 0) + 1
    if graph:
        gc = {n["id"]: n for n in graph["nodes"] if n["type"] == "contract"}
        miss = sorted(set(gc) - set(ch))
        extra = sorted(set(ch) - set(gc))
        checks.append({"name": f"coverage: every contract node of the pilot graph ({len(gc)}) has an extracted schema-lite", "ok": not miss, "missing": miss,
                       "extra_extracted_not_in_graph": extra})
        result["coverage"] = {"graph_contracts": len(gc), "extracted": len(ch), "missing": miss, "extra": extra}
        kinds_ok = all(gc[i]["kind"] == ch[i]["kind"] for i in gc if i in ch)
        checks.append({"name": "coverage: contract kinds agree with the graph (class_validator_dto / type_alias_union / zod)", "ok": kinds_ok})
    pairs_out = []
    # P1: the last feature commits — MUN-0040/0041 migration import surface
    P = []
    hist = [l.split(" ", 1) for l in git(["log", "--format=%H %s", "--", "*.dto.ts", "*.types.ts", "packages/types/src/index.ts", "*schema*.ts"], top).strip().splitlines()]
    result["contract_commits"] = [{"commit": h[:12], "subject": s} for h, s in hist]
    if hist:
        P.append(("P1-last-contract-commit-to-head", hist[0][0] + "^", head, hist[0][1]))
        P.append(("P2-first-contract-commit-to-head", hist[-1][0], head, "whole contract history"))
        for h, s in hist:
            P.append((f"P3-replay-{h[:8]}", h + "^", h, s))
    for pid, base, hd, subject in P:
        try:
            bt = build_graph.load_tree_git(top, base, "")
            ht = build_graph.load_tree_git(top, hd, "")
            res = run_diff(bt, ht, graph=graph if ht.meta["source_commit"] == head else None, repo_name=build_graph.source_repo_name(top))
            res2 = run_diff(bt, ht, graph=graph if ht.meta["source_commit"] == head else None, repo_name=build_graph.source_repo_name(top))
            rec = {"id": pid, "base": bt.meta["source_commit"][:12], "head": ht.meta["source_commit"][:12], "subject": subject, "summary": res["summary"],
                   "breaking": res["breaking"], "reproducible": dump(res) == dump(res2),
                   "added": sorted(k for k, c in res["contracts"].items() if c["status"] == "added"),
                   "removed": sorted(k for k, c in res["contracts"].items() if c["status"] == "removed"),
                   "changed": {k: [x["code"] for x in c["changes"]] for k, c in res["contracts"].items() if c["status"] in ("changed", "text_only")}}
            pairs_out.append(rec)
            if out_dir:
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / f"{pid}.json").write_bytes(dump(res))
        except (Refusal, subprocess.CalledProcessError) as e:
            pairs_out.append({"id": pid, "base": base, "head": hd, "subject": subject, "refusal": str(e)})
    result["pairs"] = pairs_out
    p1 = next((p for p in pairs_out if p["id"].startswith("P1")), None)
    if p1:
        # published change: the commit that added the migration DTOs (git diff --name-status A under */dto/)
        added_files = [l.split("\t")[1] for l in git(["diff", "--name-status", p1["base"], p1["head"]], top).splitlines() if l.startswith("A") and "/dto/" in l]
        added_paths = sorted({k.split(":", 1)[1].split("#")[0] for k in p1["added"]})
        checks.append({"name": "P1 reproduces the published change: every DTO file added between the revisions yields ≥ 1 added contract, 0 breaking",
                       "ok": set(added_files) <= set(added_paths) and p1["summary"]["breaking"] == 0 and len(added_files) > 0,
                       "added_dto_files": added_files, "added_contracts": p1["added"], "subject": p1["subject"]})
        checks.append({"name": "P1 is reproducible (two runs byte-identical)", "ok": p1.get("reproducible", False)})
    replays = [p for p in pairs_out if p["id"].startswith("P3") and "refusal" not in p]
    checks.append({"name": f"P3 replay over every commit touching a contract file ({len(replays)}): each run computes (no refusal), reproducible",
                   "ok": len(replays) == len([p for p in P if p[0].startswith("P3")]) and all(p["reproducible"] for p in replays),
                   "per_commit": [{"commit": p["head"], "subject": p["subject"][:60], "breaking": p["summary"]["breaking"], "added": len(p["added"]),
                                   "changed": p["changed"]} for p in replays]})
    # independent cross-check of the replay: git numstat deletions on contract files per commit vs breaking found
    cross = []
    for p in replays:
        ns = git(["diff", "--numstat", p["base"], p["head"], "--", "*.dto.ts", "*.types.ts", "packages/types/src/index.ts"], top).strip().splitlines()
        deletions = sum(int(l.split("\t")[1]) for l in ns if l.split("\t")[1].isdigit())
        cross.append({"commit": p["head"], "deletions_in_contract_files": deletions, "breaking": p["summary"]["breaking"],
                      "consistent": not (deletions == 0 and p["summary"]["breaking"] > 0)})
    checks.append({"name": "P3 cross-check: a commit with 0 deleted lines in contract files never yields a breaking change (additive ⇒ compatible)",
                   "ok": all(c["consistent"] for c in cross), "rows": cross})
    # P4: synthetic rewind canary on the real tree (in memory; the clone is never written)
    canary = None
    dto_path = "apps/api/src/tasks/dto/create-task.dto.ts"
    if dto_path in head_tree.files:
        src = head_tree.text(dto_path)
        mutated = re.sub(r"\n(\s*@[^\n]*\n)*\s*sprintId\?\??:\s*string;\n", "\n", src, count=1)
        mutated = mutated.replace("@IsIn(['critical', 'high', 'medium', 'low'])", "@IsIn(['critical', 'high', 'medium'])")
        files = dict(head_tree.files)
        files[dto_path] = mutated.encode()
        mt = build_graph.Tree(files, {**head_tree.meta, "source_commit": "f" * 40, "source_tree": "in-memory-mutant", "rev": "canary"})
        try:
            res = run_diff(head_tree, mt, graph=None, repo_name=build_graph.source_repo_name(top))
            cid = f"contract:{dto_path}#CreateTaskDto"
            codes = sorted({c["code"] for c in res["contracts"].get(cid, {}).get("changes", [])})
            svc = [e for e in res["edges"] if e["edge"]["from"] == "code_unit:apps/api/src/tasks/tasks.service.ts" and e["edge"]["to"] == cid]
            ctl = [e for e in res["edges"] if e["edge"]["from"] == "code_unit:apps/api/src/tasks/tasks.controller.ts" and e["edge"]["to"] == cid]
            canary = {"mutation": "CreateTaskDto: field sprintId removed; priority enum loses 'low'", "codes": codes,
                      "service_edge": svc[0]["verdict"] if svc else None, "service_reasons": svc[0]["reasons"] if svc else None,
                      "controller_edge": ctl[0]["verdict"] if ctl else None, "controller_reasons": ctl[0]["reasons"] if ctl else None,
                      "breaking": res["summary"]["breaking"], "other_contracts_unchanged": all(c["status"] == "unchanged" for k, c in res["contracts"].items() if k != cid)}
            if out_dir:
                (out_dir / "P4-canary.json").write_bytes(dump(res))
            checks.append({"name": "P4 canary on the real tree: removing a used DTO field + narrowing an enum is detected (FIELD_REMOVED, ENUM_VALUE_REMOVED), "
                                   "the service that reads dto.sprintId fails, the forwarding controller is not_measured, every other contract unchanged",
                           "ok": {"FIELD_REMOVED", "ENUM_VALUE_REMOVED"} <= set(codes) and canary["service_edge"] == "failed" and canary["controller_edge"] == "not_measured"
                           and canary["other_contracts_unchanged"], **canary})
        except Refusal as e:
            checks.append({"name": "P4 canary on the real tree", "ok": False, "refusal": str(e)})
    result["canary"] = canary
    # P5: consumer ⊆ provider over every contract edge at head (no diff) — real drift findings
    try:
        res = run_diff(head_tree, head_tree, graph=graph, repo_name=build_graph.source_repo_name(top))
        failed = [e for e in res["edges"] if e["verdict"] == "failed"]
        nm = [e for e in res["edges"] if e["verdict"] == "not_measured"]
        result["edges_at_head"] = {"summary": res["summary"]["edge_verdicts"], "failed": [{"from": e["edge"]["from"], "to": e["edge"]["to"], "reasons": e["reasons"]} for e in failed],
                                   "not_measured": [{"from": e["edge"]["from"], "to": e["edge"]["to"], "reasons": e["reasons"]} for e in nm],
                                   "projection_complete": sum(1 for e in res["edges"] if e.get("projection", {}).get("complete")),
                                   "consumer_edges": sum(1 for e in res["edges"] if e["edge"]["type"] == "consumes_contract")}
        if out_dir:
            (out_dir / "P5-edges-at-head.json").write_bytes(dump(res))
        checks.append({"name": "P5 consumer ⊆ provider over every graph contract edge at HEAD: every edge has a tri-valued verdict; failed edges are reported as drift findings (not hidden)",
                       "ok": len(res["edges"]) == len(edges_from_graph(graph)) if graph else True, "verdicts": res["summary"]["edge_verdicts"], "failed": len(failed)})
    except Refusal as e:
        checks.append({"name": "P5 edges at head", "ok": False, "refusal": str(e)})
    # P6: cross-repo consumer — the program repo's importer sends CreateWorkItemDto bodies (Python dict literal keys)
    imp = ROOT / "tools" / "importer" / "legacy_import.py"
    if imp.exists():
        text = imp.read_text(encoding="utf-8")
        m = re.search(r"body\s*=\s*\{", text)
        keys = []
        if m:
            ob = m.end() - 1
            cb = match_close(text, ob)
            keys = sorted({m.group(1) for item in split_top(text[ob + 1:cb], ",") for m in [re.match(r"\s*[\"'](\w+)[\"']\s*:", item)] if m})
        cid = "contract:apps/api/src/migration/dto/create-work-item.dto.ts#CreateWorkItemDto"
        try:
            res = run_diff(head_tree, head_tree, graph=None, repo_name=build_graph.source_repo_name(top), only={cid},
                           consumer_keys={cid: {"from": "code_unit:Arcanada-one/arcanada-universal-program/tools/importer/legacy_import.py", "keys": keys}})
            ext = [e for e in res["edges"] if e["edge"].get("via") == "declared-consumer-keys"]
            result["cross_repo"] = {"consumer": str(imp.relative_to(ROOT)), "keys": keys, "verdict": ext[0]["verdict"] if ext else None,
                                    "reasons": ext[0]["reasons"] if ext else None}
            checks.append({"name": "P6 cross-repo consumer (program importer → Muneral CreateWorkItemDto, keys observed from the Python body literal): verdict computed",
                           "ok": bool(ext) and bool(keys), **result["cross_repo"]})
        except Refusal as e:
            checks.append({"name": "P6 cross-repo consumer", "ok": False, "refusal": str(e)})
    checks.append({"name": "pilot clone still clean after the run (never written)", "ok": git(["status", "--porcelain"], top).strip() == ""})
    result["checks"] = checks
    result["repo"] = build_graph.source_repo_name(top)
    return result


# ----------------------------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", type=Path)
    ap.add_argument("--base", help="base revision")
    ap.add_argument("--head", help="head revision (default HEAD; --worktree uses the working tree)")
    ap.add_argument("--worktree", action="store_true")
    ap.add_argument("--subdir", default="")
    ap.add_argument("--graph", help="RelationshipGraph/v1 whose contract edges are verified (must be built at head), or 'auto' to build it at head from git objects — the same word verify.py takes")
    ap.add_argument("--direction", action="append", default=[], help="SYM_or_id=input|output|bidirectional")
    ap.add_argument("--consumer-keys", action="append", default=[], help="contract_id=from_id:key1,key2 (external consumer)")
    ap.add_argument("--only", action="append", default=[], help="restrict to these contract ids / symbols")
    ap.add_argument("--extract", action="store_true", help="dump the schema-lite of every contract at --rev")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--receipt", type=Path)
    ap.add_argument("--pilot", type=Path)
    ap.add_argument("--pilot-graph", type=Path)
    ap.add_argument("--pilot-out", type=Path)
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest(a.receipt, a.pilot, a.pilot_graph, a.pilot_out)
    if not a.repo:
        ap.error("--repo is required")
    try:
        if a.extract:
            tree = build_graph.load_tree_worktree(a.repo) if a.worktree else build_graph.load_tree_git(a.repo, a.rev, a.subdir)
            ex = Extractor(tree)
            doc = {"schema": "ContractSchemaLite/v1", "tool": TOOL, "commit": tree.meta["source_commit"], "contracts": ex.contracts(), "limitations": ex.limitations}
            sys.stdout.buffer.write(dump(doc))
            return 0
        if not a.base:
            ap.error("--base is required")
        try:
            base_tree = build_graph.load_tree_git(a.repo, a.base, a.subdir)
            head_tree = build_graph.load_tree_worktree(a.repo) if a.worktree else build_graph.load_tree_git(a.repo, a.head or "HEAD", a.subdir)
        except subprocess.CalledProcessError as e:
            raise Refusal("UNKNOWN_REV", (e.stderr or str(e)).strip()) from e
        graph = None
        if a.graph:
            # `auto` builds the graph at HEAD — the only revision a contract diff may bind it to.
            # With --worktree that is the working tree, so the commit check below still compares
            # like with like. See build_graph.graph_is_auto for why the word lives in one place.
            graph = build_graph.graph_for(a.graph, a.repo, rev=(a.head or "HEAD"), subdir=a.subdir,
                                          worktree=a.worktree)
            viol = schema_check.check_graph(graph, schema_check.load_schema(schema_check.GRAPH_SCHEMA_PATH))
            if viol:
                raise Refusal("GRAPH_INVALID", "; ".join(v["code"] for v in viol[:5]))
            if graph["manifest"]["source_commit"] != head_tree.meta["source_commit"]:
                raise Refusal("GRAPH_COMMIT_MISMATCH", f"graph built at {graph['manifest']['source_commit'][:12]}, head is {head_tree.meta['source_commit'][:12]} — rebuild the graph at head")
        directions = {}
        for d in a.direction:
            k, v = d.split("=", 1)
            directions[k] = v
        ck = {}
        for c in a.consumer_keys:
            cid, rest = c.split("=", 1)
            frm, keys = rest.split(":", 1)
            ck[cid] = {"from": frm, "keys": [k for k in keys.split(",") if k]}
        res = run_diff(base_tree, head_tree, graph=graph, directions=directions, consumer_keys=ck, repo_name=build_graph.source_repo_name(a.repo),
                       only=set(a.only) or None)
    except Refusal as r:
        doc = {"schema": OUT_SCHEMA, "tool": TOOL, "refusal": {"code": r.code, "detail": r.detail}}
        if a.json or a.out:
            (a.out.write_bytes(dump(doc)) if a.out else sys.stdout.buffer.write(dump(doc)))
        print(f"REFUSED {r.code}: {r.detail}", file=sys.stderr)
        return 2
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_bytes(dump(res))
    if a.json and not a.out:
        sys.stdout.buffer.write(dump(res))
    else:
        print(human(res))
    return exit_code_for(res)


if __name__ == "__main__":
    sys.exit(main())

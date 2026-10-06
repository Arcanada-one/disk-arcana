"""Bounded, non-executing Bash/Bats source analysis; dynamic closure is unknown.

Syntax runs bash -n on captured bytes only. Bats test declarations are translated
to functions for that syntax check; this never sources a test, hook, helper or CI job.
Behavior remains a separate mandatory, source-bound fixture evidence obligation.
"""
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

KINDS = {"bash_source", "bats_test"}


def kind(path, raw, mode=None):
    if path.endswith(".bats"):
        return "bats_test"
    if path.endswith((".sh", ".bash")):
        return "bash_source"
    if mode != "100755":
        return None
    first = raw.splitlines()[0].decode("utf-8", errors="replace") if raw else ""
    if mode == "100755" and re.fullmatch(r"#!\s*(?:/bin/bash|/usr/bin/bash|/usr/bin/env\s+bash)\s*", first):
        return "bash_source"
    return None


def analyse(path, raw, paths, *, root_cwd=False, cwd=None):
    text = raw.decode("utf-8", errors="replace")
    unknown, references, inventory = [], [], []
    cwd = "." if root_cwd else cwd
    # A bounded scanner cannot prove branch/subshell directory transitions.
    # Invalidate the entire block before extracting any deterministic caller.
    if re.search(r"\b(?:cd|pushd|popd)\b", text):
        cwd = None
        root_cwd = False
        unknown.append("directory transition has unresolved execution cwd")
    if text.encode("utf-8") != raw:
        unknown.append("non-UTF-8 source is not parsed losslessly")
    first = text.splitlines()[0] if text else ""
    if first.startswith("#!") and not re.search(r"\bbash\b|\bbats\b", first):
        unknown.append("declared non-Bash interpreter dialect is not measured by bash syntax")
    translated = []
    heredoc, quoted = None, None
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if heredoc:
            translated.append(line)
            if stripped == heredoc:
                heredoc = None
            continue  # heredoc contents are data, never extracted as shell callers
        if quoted:
            translated.append(line)
            if re.search(r"(?<!\\)" + re.escape(quoted), line):
                quoted = None
            continue
        if stripped.startswith("@test"):
            m = re.fullmatch(r'''\s*@test\s+(["'])(.+)\1\s*\{\s*(?:#.*)?''', line)
            if not m or any(x in (m[2] if m else "") for x in ("$", "`")):
                unknown.append(f"line {lineno}: unsupported/dynamic Bats registration")
                translated.append(line)
            else:
                inventory.append(m[2])
                translated.append(f"__graph_bats_test_{len(inventory)}() {{")
            continue
        translated.append(line)
        if not stripped or stripped.startswith("#"):
            if re.search(r"bats.*\bfocus\b", stripped):
                unknown.append(f"line {lineno}: focused Bats selection")
            continue
        if root_cwd and re.match(r"^(?:-\s*)?run:", stripped):
            line = re.sub(r"^(?:-\s*)?run:", "", stripped).strip()
            if len(line) >= 2 and line[0] == line[-1] and line[0] in "\"'":
                line = line[1:-1]
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|(){}")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            tokens = list(lexer)
        except ValueError:
            # Multiline quotes/heredocs are not safely resolved by this bounded scanner.
            unknown.append(f"line {lineno}: multiline/opaque shell statement")
            quoted = lexer.state if lexer.state in ("'", '"') else None
            continue
        here = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
        if here:
            heredoc = here[2]
            unknown.append(f"line {lineno}: heredoc data/generation closure not measured")
        statements, current = [], []
        for token in tokens + [";"]:
            if token and all(c in ";&|{}" for c in token):
                if current:
                    statements.append(current)
                current = []
            else:
                current.append(token)
        for words in statements:
            while words and (words[0] in ("then", "do", "else", "if", "elif", "!", "exec", "run", "env")
                             or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0])):
                words = words[1:]
            if len(words) > 1 and words[0] == "command" and not words[1].startswith("-"):
                words = words[1:]
            if words and words[0] in ("timeout", "nice", "sudo"):
                unknown.append(f"line {lineno}: wrapper execution scope/options unresolved")
                continue
            if not words or words[0] in ("fi", "done", "esac", "}", "function"):
                continue
            if words[0].startswith("-"):
                unknown.append(f"line {lineno}: wrapper options/child command unresolved")
                continue
            if len(words) > 1 and words[1] == "(":  # function declaration, not a call
                continue
            command = words[0]
            if command in ("eval", "alias", "unalias") or "$" in command or "`" in command:
                unknown.append(f"line {lineno}: dynamic command/alias/eval")
                continue
            if command == "skip":
                unknown.append(f"line {lineno}: Bats skip may omit a required test")
            loader = command in ("source", ".", "load", "bash", "/bin/bash", "bats")
            target = words[1] if loader and len(words) > 1 else command
            if loader and (len(words) < 2 or target.startswith("-")):
                unknown.append(f"line {lineno}: unsupported loader/interpreter options")
                continue
            bats_dir = target.startswith(("$BATS_TEST_DIRNAME/", "${BATS_TEST_DIRNAME}/"))
            if bats_dir:
                target = target.split("/", 1)[1]
            if "$" in target or "`" in target or "$(" in line or "<(" in line:
                if loader or "$(" in line or "<(" in line:
                    unknown.append(f"line {lineno}: dynamic load/substitution")
                continue
            if not loader and "/" not in target and target not in paths:
                continue  # a literal external utility/function, not a guessed repository call
            if target.startswith("/"):
                if loader:
                    unknown.append(f"line {lineno}: external absolute source/command")
                continue
            candidates = [os.path.normpath(os.path.join(cwd, target))] if cwd is not None else [
                os.path.normpath(os.path.join(os.path.dirname(path), target)), os.path.normpath(target)]
            if bats_dir or command == "load":
                candidates = candidates[:1]
            if command == "load":
                candidates = [c for p in candidates for c in (p + ".bash", p)]
            resolved = sorted({p for p in candidates if p in paths and ".." not in PurePosixPath(p).parts})
            if len(resolved) != 1:
                if loader or target.startswith("."):
                    unknown.append(f"line {lineno}: missing/ambiguous literal helper {target}")
                continue
            certain_cwd = cwd is not None or bats_dir or command == "load"
            references.append({"path": resolved[0], "type": "imports" if command in ("source", ".", "load") else "calls",
                               "line": lineno, "provenance": "deterministic" if certain_cwd else "inferred"})
            if not certain_cwd:
                unknown.append(f"line {lineno}: relative execution cwd is not declared")
    if path.endswith(".bats") and not inventory:
        unknown.append("Bats inventory is empty or unmeasured")
    if len(inventory) != len(set(inventory)):
        unknown.append("Bats inventory has ambiguous duplicate names")
    if path.endswith(".bats"):
        for body in re.split(r"(?m)^\s*@test\s+", text)[1:]:
            body = re.split(r"(?m)^\s*}\s*$", body, maxsplit=1)[0]
            statements = [s.strip() for s in body.splitlines()[1:] if s.strip() and not s.lstrip().startswith("#")]
            assertion = r'''(?:\[|\[\[|test)\s+["']?\$(?:status|\{status\})["']?\s+(?:-eq|==|=|!=|-ne)\s+\d+\s*(?:\]|\]\])?\s*(?:#.*)?'''
            for i, statement in enumerate(statements):
                if statement.startswith("run ") and (i + 1 == len(statements)
                                                       or not re.fullmatch(assertion, statements[i+1])):
                    unknown.append("Bats run lacks an immediate unconditional child status assertion")
            if any(re.match(r"(?:if|for|while|until|case)\b", s) for s in statements):
                unknown.append("Bats conditional execution membership is not statically resolved")
    return {"references": references, "unknown": sorted(set(unknown)), "tests": inventory,
            "syntax_source": "\n".join(translated) + "\n"}


def workflow(path, raw, paths):
    """Only literal Bash step contexts yield deterministic repository calls.

    PyYAML is optional: absence/opaque representation retains unknown closure,
    rather than falling back to treating arbitrary YAML lines as root commands.
    Unknown closure selects conservative inferred shell callers in the builder.
    """
    refs, unknown = [], []
    try:
        import yaml
        text = raw.decode("utf-8")
        if any(type(t).__name__ in ("AliasToken", "AnchorToken", "TagToken", "DirectiveToken")
               for t in yaml.scan(text)):
            raise ValueError("aliased/tagged workflow context")
        node = yaml.compose(text, Loader=yaml.BaseLoader)
        def unique(n):
            if isinstance(n, yaml.MappingNode):
                keys = [k.value for k, _ in n.value]
                if len(keys) != len(set(keys)):
                    raise ValueError("duplicate workflow context keys")
                for _, v in n.value:
                    unique(v)
            elif isinstance(n, yaml.SequenceNode):
                for v in n.value:
                    unique(v)
        unique(node)
        data = yaml.load(text, Loader=yaml.BaseLoader)
        if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
            raise ValueError("workflow jobs context is not a mapping")
        def defaults(scope):
            d = scope.get("defaults", {})
            if not isinstance(d, dict) or not isinstance(d.get("run", {}), dict):
                raise ValueError("opaque workflow run defaults")
            return d.get("run", {})
        root = defaults(data)
        for name, job in data["jobs"].items():
            if not isinstance(job, dict) or "uses" in job or not isinstance(job.get("steps"), list):
                unknown.append(f"job {name}: reusable/opaque shell context")
                continue
            inherited = {**root, **defaults(job)}
            for index, step in enumerate(job["steps"]):
                if not isinstance(step, dict):
                    unknown.append(f"job {name} step {index}: opaque step")
                    continue
                if "run" not in step:
                    if str(step.get("uses", "")).startswith("./") or (step.get("with") or {}).get("path"):
                        unknown.append(f"job {name} step {index}: local action/checkout path scope unresolved")
                    continue
                shell = step.get("shell", inherited.get("shell", "bash"))
                wd = step.get("working-directory", inherited.get("working-directory", "."))
                context = f"job {name} step {index}"
                valid = (isinstance(wd, str) and bool(wd) and not wd.startswith("/")
                         and not any(c in wd for c in "$`~\\")
                         and ".." not in PurePosixPath(wd).parts)
                if not valid or shell != "bash" or "windows" in str(job.get("runs-on", "")).lower() or "container" in job:
                    unknown.append(context + ": dynamic/unsupported shell or working-directory")
                    cwd = None
                else:
                    cwd = os.path.normpath(wd)
                run = step["run"]
                if not isinstance(run, str):
                    unknown.append(context + ": opaque run body")
                    continue
                analysis = analyse(path, run.encode("utf-8"), paths, cwd=cwd)
                if cwd is None or analysis["unknown"]:
                    for ref in analysis["references"]:
                        ref["provenance"] = "inferred"
                refs.extend(analysis["references"])
                unknown.extend(context + ": " + s for s in analysis["unknown"])
    except (ImportError, ValueError, UnicodeError, TypeError, AttributeError, RecursionError) as ex:
        unknown.append("workflow shell context not measured: " + str(ex))
    except Exception as ex:
        # YAML parser failures remain a scoped unknown; never invoke a shell.
        unknown.append("workflow shell context not measured: " + type(ex).__name__)
    return {"references": refs, "unknown": sorted(set(unknown))}


def tap_membership(raw, inventory):
    """An exit-zero/filtered/skipped TAP stream never replaces actual complete membership."""
    text = raw.decode("utf-8", errors="strict")
    plans = re.findall(r"(?m)^1\.\.(\d+)\s*$", text)
    rows = re.findall(r"(?m)^(ok|not ok) (\d+) (.+)$", text)
    if (not inventory or plans != [str(len(inventory))] or len(rows) != len(inventory)
            or [int(r[1]) for r in rows] != list(range(1, len(inventory)+1))
            or [r[2] for r in rows] != inventory or any(r[0] != "ok" for r in rows)
            or re.search(r"(?i)#\s*(?:skip|todo)|bail out!", text)):
        return False
    return True


def syntax(path, raw, paths):
    try:
        analysis = analyse(path, raw, paths)
        if any("Bats registration" in s for s in analysis["unknown"]):
            return "not_measured", {**analysis, "exit_code": 125}
        with tempfile.TemporaryDirectory(prefix="graph-shell-syntax-") as td:
            p = Path(td) / "source.bash"
            p.write_text(analysis["syntax_source"])
            run = subprocess.run(["bash", "--noprofile", "--norc", "-n", str(p)],
                                 capture_output=True, timeout=15)
        verdict = "failed" if run.returncode else ("not_measured" if analysis["unknown"] else "verified")
        return verdict, {**analysis, "exit_code": run.returncode,
                         "stderr": run.stderr.decode("utf-8", errors="replace")}
    except (ValueError, OSError, subprocess.SubprocessError) as ex:
        return "not_measured", {"unknown": [str(ex)], "exit_code": 127}

"""Source-bound compiler observations for the one internal metadata contract.

This module executes the producer's observer. It never accepts a caller-supplied
proof, verdict, count, or executable. Contract admission integration is separate.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import build_graph

CONTRACT = "contract:apps/api/src/auth/agent-scope.decorator.ts#AgentScopeKind"
REPO = "Arcanada-one/muneral"
# Exact binaries used by the native positive and causal-control measurements.
EXPECTED_NODE_RUNTIMES = {
    "v24.20.0": "89af8424dd53e560b1933f87ba650d8bf57c83ca5a04600eefb31f416aabbae7",
    "v24.21.0": "7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c",
}
OBSERVER = Path(__file__).with_name("metadata_contract_observer.cjs")
TARGET_SOURCE_FILES = ("apps/api/src/auth/agent-scope.decorator.ts",
                       "apps/api/src/auth/guards/agent-task-scope.guard.ts")
# Measured SDK/compiler scope from independently sealed Security v7 inputs.
EXPECTED_DEPENDENCIES = {'apps/api/node_modules/typescript/lib/typescript.js': '3ae902c92cc44dace175c0e69e13a4b0899f6983c6121d76b9ab8dd5795e7675', 'apps/api/node_modules/typescript/package.json': '822ef7ca6452205657b6288b066481ecf508bfbf43455d715cf7d3ec457561e6', 'apps/api/node_modules/@nestjs/common/decorators/core/set-metadata.decorator.d.ts': 'eefafec7c059f07b885b79b327d381c9a560e82b439793de597441a4e68d774a', 'apps/api/node_modules/@nestjs/common/decorators/core/set-metadata.decorator.js': '3ad740a6bad3c92685ea0b47e96470140258bed18fd2810f80bcd265e1f25ec7', 'apps/api/node_modules/@nestjs/core/services/reflector.service.d.ts': 'eed40a963fe55142d62b9da657ecbb31a0b7ce745f9304c92ed6a00be6db3cb2', 'apps/api/node_modules/@nestjs/core/services/reflector.service.js': '102030b3983eb599efe259c5473a28189af211ff842b43e53af019afc729e631'}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compiler_project_binding(tree) -> tuple[dict | None, list[str]]:
    """Choose the nearest tracked primary config; native TS must prove membership.

    No synthetic config, caller-selected project, dependency relocation or inferred
    include/exclude membership is accepted. Missing inputs remain unmeasured.
    """
    targets = [Path(name) for name in TARGET_SOURCE_FILES]
    if any(name not in tree.files for name in TARGET_SOURCE_FILES):
        return None, ["METADATA_PROJECT_TARGET_MISSING"]
    candidates = []
    for name, data in tree.files.items():
        config = Path(name)
        if config.name != "tsconfig.json" or config.is_absolute() or ".." in config.parts:
            continue
        if all(target.is_relative_to(config.parent) for target in targets):
            candidates.append((len(config.parent.parts), name, data))
    if not candidates:
        return None, ["METADATA_PROJECT_CONFIG_MISSING"]
    depth = max(candidate[0] for candidate in candidates)
    closest = [candidate for candidate in candidates if candidate[0] == depth]
    if len(closest) != 1:
        return None, ["METADATA_PROJECT_CONFIG_AMBIGUOUS"]
    _, name, data = closest[0]
    return {"path": name, "sha256": digest(data),
            "targets": list(TARGET_SOURCE_FILES)}, []


def source_binding(tree, root: Path) -> tuple[list[dict], list[str]]:
    """Bind all tracked input bytes, including config/lock and non-API source."""
    files, errors = [], []
    for name, data in sorted(tree.files.items()):
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts or not name:
            errors.append("UNSAFE_SOURCE_PATH")
            continue
        path = root / rel
        if not path.resolve().is_relative_to(root.resolve()):
            errors.append("SOURCE_PATH_ESCAPES_ROOT")
            continue
        try:
            actual = path.read_bytes()
        except OSError:
            errors.append("SOURCE_BYTES_MISSING")
            continue
        if actual != data:
            errors.append("SOURCE_BYTES_MISMATCH")
        files.append({"path": name, "sha256": digest(data)})
    return files, sorted(set(errors))


def observation_problems(doc: dict, binding: dict) -> list[str]:
    """Validate the actual subprocess observation, without believing closed=true."""
    errors = []
    if not isinstance(doc, dict) or doc.get("schema") != "NativeMetadataContractObservation/v1":
        return ["OBSERVATION_SCHEMA_INVALID"]
    for key in ("head", "repo", "contract"):
        if doc.get(key) != binding[key]:
            errors.append("OBSERVATION_SUBJECT_MISMATCH")
    if (not isinstance(binding.get("compiler_project"), dict)
            or doc.get("compiler_project") != binding["compiler_project"]):
        errors.append("OBSERVATION_COMPILER_PROJECT_MISMATCH")
    if doc.get("source_files") != binding["files"]:
        errors.append("OBSERVATION_SOURCE_INVENTORY_MISMATCH")
    obs = doc.get("observation")
    if not isinstance(obs, dict):
        return errors + ["OBSERVATION_BODY_INVALID"]
    for key in ("errors", "unknown_kind_reads", "context_escapes",
                "request_container_flows", "container_escape_positions", "raw_metadata_escapes", "diagnostics"):
        if obs.get(key) != []:
            errors.append("OBSERVATION_NOT_CLOSED:" + key)
    values, cases = obs.get("union"), obs.get("cases")
    if (not isinstance(values, list) or not isinstance(cases, list)
            or not values or any(not isinstance(x, str) for x in values + cases)
            or len(set(values)) != len(values) or len(set(cases)) != len(cases)
            or set(values) != set(cases)):
        errors.append("OBSERVATION_CASE_SET_INVALID")
    dependencies = doc.get("dependencies")
    if not isinstance(dependencies, list) or len(dependencies) != 6:
        errors.append("OBSERVATION_DEPENDENCIES_INCOMPLETE")
    elif any(not isinstance(x, dict) or not isinstance(x.get("path"), str)
             or not re.fullmatch(r"[0-9a-f]{64}", str(x.get("sha256", "")))
             for x in dependencies):
        errors.append("OBSERVATION_DEPENDENCIES_INVALID")
    elif {x["path"]: x["sha256"] for x in dependencies} != EXPECTED_DEPENDENCIES:
        errors.append("OBSERVATION_DEPENDENCY_SCOPE_MISMATCH")
    if doc.get("typescript") != "5.9.3":
        errors.append("COMPILER_VERSION_OUTSIDE_MEASURED_SCOPE")
    return sorted(set(errors))


def observe(tree, root: Path, *, node: str = "node", git_repo: Path | None = None) -> dict:
    """Execute bounded producer code against the source revision's exact bytes.

    Missing compiler/dependencies, dirty sources and unclosed observations are
    measurements that refuse adoption. They never fall back to supplied evidence.
    """
    root = root.resolve()
    head = tree.meta.get("source_commit")
    binding = {"repo": tree.meta.get("source_repo"), "head": head,
               "contract": CONTRACT}
    errors = []
    if binding["repo"] != REPO or tree.meta.get("source_tree") != "git-objects" or tree.meta.get("dirty"):
        errors.append("SUBJECT_OUTSIDE_MEASURED_SCOPE")
    if not re.fullmatch(r"[0-9a-f]{40}", str(head)):
        errors.append("HEAD_BINDING_INVALID")
    if not errors:
        try:
            actual = build_graph.load_tree_git(git_repo or root, head, "")
            if actual.files != tree.files or actual.meta.get("source_repo") != REPO:
                errors.append("GIT_SOURCE_BINDING_MISMATCH")
        except (OSError, subprocess.CalledProcessError, ValueError):
            errors.append("GIT_SOURCE_BINDING_UNAVAILABLE")
    for name, expected in EXPECTED_DEPENDENCIES.items():
        try:
            if digest((root / name).read_bytes()) != expected:
                errors.append("DEPENDENCY_OUTSIDE_MEASURED_SCOPE")
        except OSError:
            errors.append("DEPENDENCY_BYTES_MISSING")
    project, project_errors = compiler_project_binding(tree)
    binding["compiler_project"] = project
    errors.extend(project_errors)
    files, source_errors = source_binding(tree, root)
    binding["files"] = files
    errors.extend(source_errors)
    result = {"schema": "NativeMetadataContractProof/v1", "subject": binding,
              "issuer_sha256": digest(OBSERVER.read_bytes()),
              "adoption": "not_measured", "runtime_authorized": False}
    # Node must not execute caller-controlled preload hooks or module search paths.
    native_env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ")
                  if key in os.environ}
    executable = shutil.which(node)
    if not executable:
        errors.append("NODE_RUNTIME_UNAVAILABLE")
    else:
        try:
            version = subprocess.run([executable, "--version"], capture_output=True,
                                     text=True, timeout=10, check=True, env=native_env).stdout.strip()
            result["runtime"] = {"version": version,
                                 "executable_sha256": digest(Path(executable).read_bytes())}
            if EXPECTED_NODE_RUNTIMES.get(version) != result["runtime"]["executable_sha256"]:
                errors.append("NODE_RUNTIME_OUTSIDE_MEASURED_SCOPE")
        except (OSError, subprocess.SubprocessError):
            errors.append("NODE_RUNTIME_UNAVAILABLE")
    if errors:
        return {**result, "errors": sorted(set(errors))}
    payload = {**binding, "root": str(root)}
    try:
        proc = subprocess.run([executable, str(OBSERVER)], input=json.dumps(payload),
                              text=True, capture_output=True, timeout=60, cwd=root, env=native_env)
        doc = json.loads(proc.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {**result, "errors": ["NATIVE_OBSERVATION_UNAVAILABLE"]}
    errors = observation_problems(doc, binding)
    if not isinstance(doc, dict):
        return {**result, "errors": errors}
    if proc.returncode != 0:
        errors.append("NATIVE_OBSERVER_REFUSED")
    # Recheck actual source/dependency bytes after the observation (TOCTOU).
    _, changed = source_binding(tree, root)
    errors.extend(changed)
    if digest(Path(executable).read_bytes()) != result["runtime"]["executable_sha256"]:
        errors.append("NODE_RUNTIME_BYTES_CHANGED")
    for dep in doc.get("dependencies", []):
        if not isinstance(dep, dict) or not isinstance(dep.get("path"), str):
            continue
        path = Path(dep["path"])
        if path.is_absolute() or ".." in path.parts:
            errors.append("DEPENDENCY_PATH_INVALID")
            continue
        try:
            if digest((root / path).read_bytes()) != dep.get("sha256"):
                errors.append("DEPENDENCY_BYTES_CHANGED")
        except OSError:
            errors.append("DEPENDENCY_BYTES_MISSING")
    return {**result, "errors": sorted(set(errors)), "observation": doc,
            "observation_sha256": digest(proc.stdout.encode()),
            # A closed observation is not yet a reviewed native admission rule.
            "adoption": "not_measured", "source_observation_closed": not errors}

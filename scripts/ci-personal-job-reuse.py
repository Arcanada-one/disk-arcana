#!/usr/bin/env python3
"""Receive one completed personal job; never run or redefine a FULL suite.

Unknown source, tools, environment or canonical evidence always selects execute.
There are intentionally NO tracked-path exclusions. Inert evidence changes also
miss until an independently qualified canonical exclusion protocol is supplied.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Arcanada-one/disk-arcana"
DEP = "crates/disk-personal"
COMMAND = ["python3", "../../scripts/full-test-group.py", "disk-personal"]
MODES = ["--no-default-features", "--all-features"]
CANDIDATE = "receipts/graph/persist3b78-personal-provider/full-suite.json"
# Independently qualified cddb release; current receiving admission is separate.
# A newer consumer needs reviewed adoption, never a latest-green lookup or a
# caller-provided executable.
PROGRAM = "cddbc7c105f5df0064d7af40cf293b75eea22973"
BUNDLE_SHA = "fb316c0bb645df15b7b20945ce20a2f7ab60a31f726d57607cede3ebd71305f5"
KNOWN_ENV = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SHELL",
             "USER", "LOGNAME", "PWD", "OLDPWD", "SHLVL", "_", "TMPDIR",
             "CARGO_HOME", "RUSTUP_HOME", "CARGO_BUILD_JOBS", "CARGO_TERM_COLOR",
             "RUST_BACKTRACE", "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_TARGET_DIR",
             "CC", "CXX", "AR", "RANLIB", "CI_LINKER_BOOTSTRAP", "CI",
             "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"}
EPHEMERAL = {"GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STEP_SUMMARY",
             "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_SHA",
             "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_REF_TYPE", "GITHUB_HEAD_REF",
             "GITHUB_BASE_REF", "GITHUB_EVENT_PATH", "GITHUB_WORKFLOW_REF",
             "GITHUB_WORKFLOW_SHA", "GITHUB_ACTION", "GITHUB_ACTION_PATH",
             "GITHUB_ACTION_REPOSITORY", "GITHUB_ACTION_REF", "GITHUB_ACTIONS",
             "GITHUB_ACTOR", "GITHUB_ACTOR_ID", "GITHUB_TRIGGERING_ACTOR",
             "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER",
             "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_WORKFLOW", "GITHUB_EVENT_NAME",
             "GITHUB_WORKSPACE", "GITHUB_SERVER_URL", "GITHUB_API_URL",
             "GITHUB_GRAPHQL_URL", "RUNNER_TEMP", "PERSONAL_REUSE_DIR",
             "PERSONAL_REUSE_STEPS_JSON"}
REQUIRED_EXECUTE = ["isolate", "toolchain", "resolution", "execute"]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], timeout=15)


def closure(repo, rev):
    """Hash every tracked path byte, mode and object; no Unicode/path filtering."""
    rows = []
    for row in git(repo, "ls-tree", "-r", "-z", "--full-tree", rev).split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise ValueError("unsupported tracked entry; no symlink/submodule exemption")
        rows.append((path, metadata + b"\t" + path + b"\0"))
    if not rows or len({p for p, _ in rows}) != len(rows):
        raise ValueError("empty or duplicate tracked input closure")
    objects = b"".join(row.split(b"\t", 1)[0].split()[2] + b"\n" for _, row in rows)
    check = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch-check"],
                           input=objects, capture_output=True, timeout=15, check=True)
    if any(b" missing" in line for line in check.stdout.splitlines()) or len(check.stdout.splitlines()) != len(rows):
        raise ValueError("tracked closure contains missing Git object")
    raw = b"".join(row for _, row in sorted(rows))
    return {"sha256": sha(raw), "count": len(rows), "bytes": len(raw),
            "encoding": "sorted NUL(path bytes, mode, Git blob OID); all tracked files",
            "excluded_paths": []}, raw


def tool_identity(command):
    path = shutil.which(command)
    if not path:
        raise ValueError("required tool absent: " + command)
    resolved = Path(path).resolve(strict=True)
    if command in ("cargo", "rustc"):
        rustup = tool_identity("rustup")["path"]
        resolved = Path(subprocess.check_output([rustup, "which", "--toolchain", "1.97.1", command], timeout=15).decode().strip()).resolve(strict=True)
    # Read existing protected tools only; never install or repair them here.
    for parent in (resolved, *resolved.parents):
        info = parent.stat()
        if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not
                (parent.is_dir() and info.st_mode & 0o1000)):
            raise ValueError("unprotected tool identity: " + command)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("tool is not an executable regular file")
    version = subprocess.check_output([str(resolved), "--version"], stderr=subprocess.STDOUT, timeout=15)
    return {"path": str(resolved), "sha256": sha(resolved.read_bytes()), "version_sha256": sha(version)}


def environment_binding():
    """Never serialize credential values or turn unknown env into equivalence."""
    unknown = sorted(key for key in os.environ if key not in KNOWN_ENV | EPHEMERAL
                     and not key.startswith("RUNNER_"))
    # RUNNER_* identities are NOT dropped: compare them, including runner name.
    values = {key: value for key, value in os.environ.items()
              if key in KNOWN_ENV or key.startswith("RUNNER_") and key != "RUNNER_TEMP"}
    secret = [key for key in values if re.search("TOKEN|SECRET|PASSWORD|KEY", key)]
    if secret:
        raise ValueError("unqualified protected environment reference")
    return {"complete": not unknown, "unknown_keys": unknown,
            "non_secret_environment_sha256": sha(canonical_json(values))}



def dependency_identity(tools, external):
    """Bounded, read-only ELF dependency inventory; ambiguity stays unknown."""
    files, unknown = {}, []
    try:
        reader = tool_identity("readelf")["path"]
        cache_tool = tool_identity("ldconfig")["path"]
        cache = subprocess.check_output([cache_tool, "-p"], timeout=15).decode()
        candidates = {}
        for name, path in re.findall(r"^\s*(\S+)\s+[^\n]*=> (\S+)$", cache, re.MULTILINE):
            candidates.setdefault(name, set()).add(path)
        pending = [Path(t["path"]) for t in tools.values()]
        pending += [Path(p) for p in external["python"].get("extension_files", {})]
        while pending:
            path = pending.pop().resolve(strict=True)
            if str(path) in files:
                continue
            if len(files) >= 128 or path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("dependency identity bound exceeded")
            for parent in (path, *path.parents):
                info = parent.stat()
                if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                    raise ValueError("dependency path is not protected")
            raw = path.read_bytes()
            if not raw.startswith(b"\x7fELF"):
                raise ValueError("tool dependency is not supported ELF")
            files[str(path)] = sha(raw)
            dynamic = subprocess.check_output([reader, "-d", "-l", str(path)], timeout=15).decode()
            if re.search(r"\((?:RPATH|RUNPATH)\)", dynamic):
                raise ValueError("runtime search path needs qualified reference")
            for name in re.findall(r"Shared library: \[([^\]]+)\]", dynamic):
                choices = candidates.get(name, set())
                if len(choices) != 1:
                    raise ValueError("dependency library is absent or ambiguous: " + name)
                pending.append(Path(next(iter(choices))))
            for loader in re.findall(r"Requesting program interpreter: ([^\]]+)\]", dynamic):
                pending.append(Path(loader))
        for config in ("/etc/os-release", "/etc/ld.so.cache", "/etc/ld.so.conf"):
            path = Path(config)
            if path.is_file():
                files[config] = sha(path.read_bytes())
        if not external["complete"]:
            unknown.extend(external["unknown"])
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        unknown.append(str(exc))
    return {"complete": not unknown and external["complete"], "files": files,
            "external": external, "unknown": unknown}


def snapshot(repo):
    if git(repo, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ValueError("current source/index is dirty")
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    inventory, raw = closure(repo, head)
    environment = environment_binding()
    tools, errors = {}, []
    for name in ("python3", "cargo", "rustc", "rustup", "cc", "c++", "ar", "ld", "strace"):
        try:
            tools[name] = tool_identity(name)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
    external_spec = importlib.util.spec_from_file_location("personal_external_inputs", repo / "scripts/ci_personal_inputs.py")
    external_module = importlib.util.module_from_spec(external_spec)
    external_spec.loader.exec_module(external_module)
    external = external_module.qualify_external(repo, tools)
    dependency_binding = dependency_identity(tools, external)
    binding = {"environment": environment, "tools": tools, "dependencies": dependency_binding,
               "system": platform.system(), "machine": platform.machine(),
               "kernel": platform.release(), "complete": not errors and environment["complete"] and dependency_binding["complete"],
               "unknown_tools": errors}
    policy = sha((repo / "scripts/ci-personal-job-reuse.py").read_bytes())
    return {"repository": REPOSITORY, "head": head,
            "tree": git(repo, "rev-parse", "HEAD^{tree}").decode().strip(),
            "closure": inventory, "tool_environment_binding": binding,
            "receiver_policy_sha256": policy,
            "workflow_sha256": sha(git(repo, "show", head + ":.github/workflows/ci.yml")),
            "declared_argv": COMMAND, "cwd": DEP, "features": MODES,
            "timeout_seconds": 1800}, raw


def validate_reuse(current, manifest, evidence, canonical, capability=None):
    """Pure receiver controls; production evidence is authenticated separately."""
    if manifest.get("schema") != "PersonalJobExecution/v1" or manifest.get("tests_executed_now") is not True:
        raise ValueError("unknown or non-executed prior manifest")
    if manifest.get("suite_exit") != 0 or manifest.get("current_steps_success") is not True:
        raise ValueError("prior job/suite failed, skipped or incomplete")
    if not isinstance(manifest.get("tool_environment_binding"), dict):
        raise ValueError("malformed prior tool/environment binding")
    if not current["tool_environment_binding"]["complete"] or not manifest["tool_environment_binding"].get("complete"):
        raise ValueError("unknown old/current tool/environment; cold execution required")
    for key in ("repository", "closure", "tool_environment_binding", "receiver_policy_sha256",
                "workflow_sha256", "declared_argv", "cwd", "features", "timeout_seconds"):
        if current[key] != manifest.get(key):
            raise ValueError("reuse input changed: " + key)
    if evidence.get("schema") != "GitHubFullSuiteEvidence/v1" or evidence.get("scope") != "global_fallback_full_suite":
        raise ValueError("unknown prior record")
    if evidence.get("repository") != REPOSITORY or evidence.get("deployable") != DEP or evidence.get("command") != COMMAND:
        raise ValueError("wrong prior repository/scope/command")
    for key in ("source_commit", "checkout_commit", "run_id", "job_id", "run_attempt"):
        if manifest.get("prior_identity", {}).get(key) != evidence.get(key):
            raise ValueError("prior manifest identity mismatch: " + key)
    if manifest.get("head") != evidence.get("source_commit") or evidence.get("checkout_commit") != evidence.get("source_commit"):
        raise ValueError("manifest source/checkout differs from authentic prior record")
    if canonical.get("verdict") != "verified" or canonical.get("errors"):
        raise ValueError("owner-qualified canonical FULL/record-delta refused or absent")
    for key in ("source_commit", "checkout_commit", "run_id", "job_id", "run_attempt"):
        if canonical.get(key) != evidence.get(key):
            raise ValueError("canonical identity mismatch: " + key)
    if canonical.get("log_sha256") != evidence.get("log", {}).get("sha256"):
        raise ValueError("canonical log bytes differ")
    if capability is not None and not valid_guard(capability, current["head"]):
        raise ValueError("fresh current confinement capability unavailable")


def read_prior(repo, current):
    """Read only the explicitly committed candidate and fixed named CI artifact."""
    record = json.loads(git(repo, "show", current["head"] + ":" + CANDIDATE))
    run = record["run_id"]
    if type(run) is not int or run <= 0 or record.get("repository") != REPOSITORY:
        raise ValueError("invalid explicit candidate identity")
    # No arbitrary URL, latest-green selection, token lookup or account mutation.
    def api(route):
        return subprocess.check_output(["gh", "api", "repos/" + REPOSITORY + "/" + route],
                                       timeout=30)
    # gh's existing scoped authentication is the supported read-only route.
    artifacts = json.loads(api(f"actions/runs/{run}/artifacts?per_page=100"))["artifacts"]
    expected = f"personal-job-reuse-{run}-{record['run_attempt']}"
    matches = [a for a in artifacts if a["name"] == expected and not a["expired"]]
    if len(matches) != 1:
        raise ValueError("prior reviewed tool/environment manifest absent or retention-stale")
    # Archive bytes must match the authenticated artifact digest. No extraction
    # or execution: only one fixed manifest member is read in bounded memory.
    artifact = matches[0]
    if artifact["size_in_bytes"] > 4 * 1024 * 1024:
        raise ValueError("oversized manifest artifact")
    archive = api(f"actions/artifacts/{artifact['id']}/zip")
    if len(archive) > 4 * 1024 * 1024 or "sha256:" + sha(archive) != artifact.get("digest"):
        raise ValueError("manifest archive digest/size mismatch")
    import io
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        members = [i for i in zipped.infolist() if i.filename == "manifest.json"]
        if len(members) != 1 or members[0].file_size > 1024 * 1024:
            raise ValueError("manifest artifact missing or ambiguous")
        manifest = json.loads(zipped.read(members[0]))
    commit = json.loads(api("git/commits/" + record["source_commit"]))
    if manifest.get("head") != commit.get("sha") or manifest.get("tree") != commit.get("tree", {}).get("sha"):
        raise ValueError("prior manifest source/tree not authenticated")
    log = api(f"actions/jobs/{record['job_id']}/logs")
    if "sha256:" + sha(log) != record["log"]["sha256"]:
        raise ValueError("prior raw log does not match candidate digest")
    marker = "PERSONAL_JOB_EXECUTION_MANIFEST=" + canonical_json(manifest).decode()
    if sum(line.partition(" ")[2] == marker for line in log.decode().splitlines()) != 1:
        raise ValueError("manifest is not bound to the actual prior job output")
    identity = manifest.get("prior_identity", {})
    if identity.get("job_id") is not None:
        raise ValueError("manifest supplied an unauthenticated job ID")
    manifest["prior_identity"] = {**identity, "job_id": record["job_id"]}
    return record, manifest


def canonical_proof(repo, current, evidence):
    """Load only exact released byte pins; an absent install is a cache miss."""
    bundle = repo / ".arcana/graph-gate"
    manifest = bundle / "BUNDLE.json"
    if not manifest.is_file() or sha(manifest.read_bytes()) != BUNDLE_SHA:
        raise ValueError("qualified pinned canonical consumer not installed")
    data = json.loads(manifest.read_text())
    if data.get("program_ref") != PROGRAM:
        raise ValueError("canonical source pin differs")
    # Exact manifest digest above is independently signature-qualified cddb.
    # Validate every member BEFORE importing any code, never a PR override.
    for item in data["files"]:
        path = bundle / item["path"]
        if path.is_symlink() or sha(path.read_bytes()) != item["sha256"].removeprefix("sha256:"):
            raise ValueError("canonical member bytes differ")
    folder = bundle / "tools/graph"
    saved = list(sys.path)
    try:
        sys.path.insert(0, str(folder))
        spec = importlib.util.spec_from_file_location("personal_reuse_canonical", folder / "full_suite_ci.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.consume(repo, current["head"], REPOSITORY, DEP, COMMAND, CANDIDATE)
    finally:
        sys.path[:] = saved


def select(repo, prior_reader=read_prior, proof_reader=canonical_proof):
    decision = {"schema": "PersonalJobReuse/v1", "mode": "execute",
                "reason": "cold execution", "current": None}
    try:
        current, raw = snapshot(repo)
        decision["current"] = current
        if not current["tool_environment_binding"]["complete"]:
            raise ValueError("current tool/environment unknown")
        evidence, manifest = prior_reader(repo, current)
        proof = proof_reader(repo, current, evidence)
        validate_reuse(current, manifest, evidence, proof)
        decision.update(mode="reuse", reason="authenticated prior complete job and exact inputs",
                        prior=evidence, manifest=manifest, canonical=proof)
    except (ValueError, KeyError, TypeError, AttributeError, OSError, ImportError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        decision["reason"] = str(exc)
    return decision


def valid_guard(guard, head):
    return (guard.get("schema") == "PersonalCurrentCapability/v1" and guard.get("head") == head
            and guard.get("success") is True and guard.get("errno") == 0
            and guard.get("resolve") == 13 and guard.get("syscall") == 437
            and guard.get("system") == "Linux" and guard.get("machine") in ("x86_64", "aarch64")
            and guard.get("job") == "personal-provider"
            and guard.get("run_id") == os.environ.get("GITHUB_RUN_ID")
            and guard.get("attempt") == os.environ.get("GITHUB_RUN_ATTEMPT"))


def current_guard(repo):
    observation = {"schema": "PersonalCurrentCapability/v1", "head": git(repo, "rev-parse", "HEAD").decode().strip(),
                   "run_id": os.environ.get("GITHUB_RUN_ID"), "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                   "job": os.environ.get("GITHUB_JOB"), "system": platform.system(), "machine": platform.machine(),
                   "syscall": 437, "resolve": 13, "success": False, "errno": None}
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64"):
        return observation
    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
    libc = ctypes.CDLL(None, use_errno=True)
    root_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY)
    try:
        how = OpenHow(os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0, 13)
        ctypes.set_errno(0)
        fd = libc.syscall(437, root_fd, b".", ctypes.byref(how), ctypes.sizeof(how))
        observation.update(success=fd >= 0, errno=ctypes.get_errno())
        if fd >= 0:
            os.close(fd)
    finally:
        os.close(root_fd)
    return observation


def final_status(decision, guard, steps, reused=None, suite_exit=None):
    if decision.get("schema") != "PersonalJobReuse/v1" or decision.get("mode") not in ("execute", "reuse"):
        raise ValueError("malformed selector decision")
    def succeeded(name):
        return steps.get(name, {}).get("outcome") == "success"
    if not succeeded("selector") or not succeeded("guard") or not valid_guard(guard, decision.get("current", {}).get("head")):
        raise ValueError("selector/current guard failed, cancelled or unknown")
    if decision["mode"] == "execute":
        if suite_exit != 0 or not all(succeeded(k) for k in REQUIRED_EXECUTE) or steps.get("reuse", {}).get("outcome") not in (None, "skipped"):
            raise ValueError("actual original execution incomplete, skipped, cancelled or failed")
    else:
        if not succeeded("reuse") or not reused or reused.get("schema") != "PersonalJobReuse/v1" or reused.get("mode") != "REUSED_PRIOR_COMPLETED_JOB" or reused.get("tests_executed_now") is not False:
            raise ValueError("receiving verifier refused or missing")
        if (reused.get("current_head") != decision["current"]["head"]
                or reused.get("current_closure_sha256") != decision["current"]["closure"]["sha256"]
                or reused.get("current_capability_observation") != guard
                or reused.get("canonical_record_delta_verdict") != "verified"):
            raise ValueError("receiving record is not bound to current decision/guard")
        for key, source_key in (("prior_source_commit", "source_commit"), ("prior_checkout_commit", "checkout_commit"),
                                ("prior_run_id", "run_id"), ("prior_job_id", "job_id"), ("prior_run_attempt", "run_attempt")):
            if reused.get(key) != decision["prior"].get(source_key):
                raise ValueError("receiving record prior identity differs")
        if any(steps.get(k, {}).get("outcome") != "skipped" for k in REQUIRED_EXECUTE):
            raise ValueError("reuse cannot conceal execution/setup failure")


def execution_equivalence(before, after):
    """A successful cold job never erases changed/unknown external inputs."""
    complete = before.get("complete") is True and after.get("complete") is True
    equal = before == after
    return {"schema": "PersonalExecutionInputEquivalence/v1", "complete": complete and equal,
            "before_sha256": sha(canonical_json(before)), "after_sha256": sha(canonical_json(after)),
            "equal": equal, "reason": "qualified unchanged inputs" if complete and equal
            else "changed or unknown pre/post tool/environment; execution remains non-reusable"}


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("select", "guard", "verify", "record"))
    args = parser.parse_args()
    if args.operation == "select":
        parent = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        if "\n" in str(parent) or "\r" in str(parent):
            raise ValueError("job-owned state path cannot contain a protocol newline")
        directory = Path(tempfile.mkdtemp(prefix="personal-reuse.", dir=parent))
        decision = select(ROOT)
        if decision["current"] is None:
            raise ValueError("cannot bind current source; selector refuses")
        write(directory / "decision.json", decision)
        _, raw = closure(ROOT, decision["current"]["head"])
        (directory / "tracked-inputs.nul").write_bytes(raw)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            stream.write("mode=" + decision["mode"] + "\n")
        with Path(os.environ["GITHUB_ENV"]).open("a") as stream:
            stream.write("PERSONAL_REUSE_DIR=" + str(directory) + "\n")
        print(json.dumps({"mode": decision["mode"], "reason": decision["reason"]}))
        return
    directory = Path(os.environ["PERSONAL_REUSE_DIR"]).resolve(strict=True)
    if directory.parent != Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) or not directory.name.startswith("personal-reuse."):
        raise ValueError("state is not in this job-owned directory")
    decision = json.loads((directory / "decision.json").read_text())
    if args.operation == "guard":
        guard = current_guard(ROOT)
        write(directory / "guard.json", guard)
        print(json.dumps(guard))
        if not guard["success"]:
            raise SystemExit(127)
        return
    guard = json.loads((directory / "guard.json").read_text())
    if args.operation == "verify":
        fresh = select(ROOT)
        current = fresh["current"]
        if fresh["mode"] != "reuse" or fresh != decision:
            raise ValueError("final reuse binding changed; refuse without success")
        validate_reuse(current, fresh["manifest"], fresh["prior"], fresh["canonical"], guard)
        prior = fresh["prior"]
        receiving = {"schema": "PersonalJobReuse/v1", "mode": "REUSED_PRIOR_COMPLETED_JOB",
                     "repository": REPOSITORY, "current_head": current["head"],
                     "current_closure_sha256": current["closure"]["sha256"],
                     "prior_source_commit": prior["source_commit"], "prior_checkout_commit": prior["checkout_commit"],
                     "prior_run_id": prior["run_id"], "prior_job_id": prior["job_id"],
                     "prior_run_attempt": prior["run_attempt"], "prior_log_sha256": prior["log"]["sha256"],
                     "workflow_sha256": current["workflow_sha256"], "declared_argv": COMMAND,
                     "cwd": DEP, "features": MODES, "tool_environment_binding": current["tool_environment_binding"],
                     "receiver_policy_sha256": current["receiver_policy_sha256"],
                     "current_capability_observation": guard, "canonical_record_delta_verdict": "verified",
                     "verification_reason": fresh["reason"], "tests_executed_now": False}
        write(directory / "receiving.json", receiving)
        print(json.dumps(receiving))
        return
    steps = json.loads(os.environ["PERSONAL_REUSE_STEPS_JSON"])
    receiving = json.loads((directory / "receiving.json").read_text()) if (directory / "receiving.json").exists() else None
    exit_path = directory / "suite-exit.txt"
    suite_exit = int(exit_path.read_text()) if exit_path.exists() else None
    final_status(decision, guard, steps, receiving, suite_exit)
    if decision["mode"] == "execute":
        current, raw = snapshot(ROOT)
        if current["head"] != decision["current"]["head"] or current["closure"] != decision["current"]["closure"]:
            raise ValueError("source input closure changed during execution")
        before = decision["current"]["tool_environment_binding"]
        after = current["tool_environment_binding"]
        equivalence = execution_equivalence(before, after)
        # Keep the actual after inventory, but refuse reuse if either captured
        # stage was unknown or the original setup altered effective inputs.
        current["tool_environment_binding"] = {**after, "complete": equivalence["complete"]}
        receiving = {**current, "input_equivalence": equivalence,
                     "before_tool_environment_binding": before,
                     "schema": "PersonalJobExecution/v1", "tests_executed_now": True,
                     "suite_exit": suite_exit, "current_steps_success": True,
                     "full_log_sha256": sha((directory / "full.log").read_bytes()),
                     "prior_identity": {"source_commit": current["head"], "checkout_commit": current["head"],
                                        "run_id": int(os.environ["GITHUB_RUN_ID"]),
                                        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                                        "job_id": None},
                     "job_id_binding": "Requires authentic completed GitHub job GET before reuse",
                     "current_capability_observation": guard}
        # The final step does not know its completed numeric job ID. Never
        # manufacture one: the receiver binds it through authenticated metadata.
    write(directory / "manifest.json", receiving)
    if decision["mode"] == "execute":
        print("PERSONAL_JOB_EXECUTION_MANIFEST=" + canonical_json(receiving).decode(), flush=True)
    print(json.dumps({"mode": receiving.get("mode", "EXECUTED_CURRENT_JOB"),
                      "tests_executed_now": receiving["tests_executed_now"], "receiving_checks": "success"}))


if __name__ == "__main__":
    main()

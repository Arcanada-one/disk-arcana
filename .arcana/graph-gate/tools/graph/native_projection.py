"""Independently consume native physical/compiler evidence; never grant admission.

Only authenticated Muneral evidence, Git objects and physical bytes are inputs.
Producer commands are recorded but never executed. An explicitly requested
STD_KERNEL_ONLY replay uses a fixed compiler command in owned scratch space.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import urllib.request


INPUTS = ("dev-tools/jevbench/native/build.py", "dev-tools/jevbench/native/patchset.json",
          "dev-tools/jevbench/native/codex-offline-send.patch")
KERNEL = "codex-rs/http-client/src/bench_accounting.rs"
API = "https://api.muneral.com/api/v1"
GIT = "/usr/bin/git"
GRAPH_KINDS = ("native_patch_manifest", "native_patch_payload")


def graph_inputs(tree):
    """Recognize exact manifest schema and its physical sibling, never node prefixes."""
    inputs = []
    for path in tree.paths:
        if not path.endswith(".json"):
            continue
        try:
            doc = decode(tree.files[path])
        except (ValueError, UnicodeError):
            continue
        if not isinstance(doc, dict) or doc.get("schema") != "BenchNativePatchset/v1":
            continue
        inputs.append((path, GRAPH_KINDS[0]))
        payload = str(Path(path).parent / Path(INPUTS[2]).name)
        if payload in tree.files:
            inputs.append((payload, GRAPH_KINDS[1]))
    return inputs


def verify_graph_binding(repo, head, tree, entities, declaration, scratch, key):
    """Canonical verifier hook; missing declaration/auth remains NOT_MEASURED."""
    paths = {item["path"] for item in entities}
    recognized = {p for p, _ in graph_inputs(tree)}
    if not paths <= recognized:
        raise ValueError("entity is not a physical schema-bound native input")
    if not declaration or not key:
        return None
    fields = {"projection", "uri", "task_id", "upstream_repository", "physical_root"}
    if not isinstance(declaration, dict) or set(declaration) != fields:
        raise ValueError("native binding declaration must have exact supported fields")
    if paths - set(INPUTS[1:]):
        raise ValueError("this projection contract does not cover the selected physical paths")
    receipt = consume(Path(declaration["projection"]), declaration["uri"], declaration["task_id"], key,
                      repo, head, Path(declaration["upstream_repository"]),
                      Path(declaration["physical_root"]), scratch)
    for name in INPUTS:
        equal(tree.files[name].hex(), physical(repo, name)[0].hex(),
              "measured native source differs from canonical selected HEAD tree")
    return receipt


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite JSON value")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def equal(actual, expected, reason):
    if canonical(actual) != canonical(expected):
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def relative(value):
    if not isinstance(value, str):
        raise ValueError("unsafe relative path")
    p = Path(value)
    if p.is_absolute() or ".." in p.parts or p.as_posix() != value:
        raise ValueError("unsafe relative path")
    return p


def physical(root, name, mode=None):
    path = root / relative(name)
    if path.parent.resolve(strict=True) != path.parent:
        raise ValueError("symlink ancestry")
    if mode == "120000":
        if not path.is_symlink():
            raise ValueError("symlink mode mismatch")
        return os.fsencode(os.readlink(path)), mode
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        actual = "100755" if metadata.st_mode & stat.S_IXUSR else "100644"
        if not stat.S_ISREG(metadata.st_mode) or (mode and actual != mode):
            raise ValueError("regular file/mode mismatch")
        return stream.read(), actual


def git(repo, *arguments, env=None, data=None):
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"}
    environment.update(env or {})
    return subprocess.run([GIT, "--no-optional-locks", "-c", "core.fsmonitor=false",
                           "-c", "core.hooksPath=/dev/null", *arguments], cwd=repo,
                          env=environment, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=60, check=True).stdout


def source_binding(repo, head):
    equal(git(repo, "rev-parse", "HEAD").decode().strip(), head, "current producer HEAD differs")
    if git(repo, "status", "--porcelain"):
        raise ValueError("producer source is dirty")
    rows = []
    for name in INPUTS:
        entries = git(repo, "ls-tree", "-z", head, "--", name).decode().split("\0")[:-1]
        if len(entries) != 1:
            raise ValueError("producer input absent")
        metadata, path = entries[0].split("\t")
        mode, kind, blob = metadata.split()
        if path != name or kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("producer input is not a regular Git blob")
        raw, _ = physical(repo, name, mode)
        equal(raw.hex(), git(repo, "cat-file", "blob", blob).hex(), "producer physical/Git mismatch")
        rows.append({"path": name, "mode": mode, "git_blob": blob, "sha256": sha(raw)})
    return {"repository_root": str(repo), "source_commit": head, "inputs": rows}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def native_get(task, key):
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", task):
        raise ValueError("native task must be a UUID")
    if not key:
        raise ValueError("authenticated native evidence is unavailable")
    request = urllib.request.Request(API + "/tasks/" + task + "/evidence",
                                     headers={"Authorization": "Bearer " + key,
                                              "User-Agent": "aup-orchestrator/1.0"}, method="GET")
    with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
        return decode(response.read())["evidence"]


def native_binding(raw, task, uri, rows):
    exact = [row for row in rows if row.get("task_id") == task and row.get("uri") == uri
             and row.get("sha256") == sha(raw) and row.get("content_type") == "application/json"]
    if len(exact) != 1 or not exact[0].get("evidence_id"):
        raise ValueError("native exact task/URI/digest/media binding absent or ambiguous")
    return exact[0]


def rederive_patch(repo, root, manifest, patch, scratch):
    if git(repo, "rev-parse", "--show-object-format").strip() != b"sha1":
        raise ValueError("unsupported upstream object format")
    source = manifest["upstream"]["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("upstream must be an immutable commit")
    objects = git(repo, "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip()
    with tempfile.TemporaryDirectory(dir=scratch, prefix="native-consumer-") as temporary:
        tmp = Path(temporary)
        (tmp / "objects").mkdir()
        env = {"GIT_INDEX_FILE": str(tmp / "index"), "GIT_OBJECT_DIRECTORY": str(tmp / "objects"),
               "GIT_ALTERNATE_OBJECT_DIRECTORIES": objects}
        def run(*args, data=None):
            return git(repo, *args, env=env, data=data)
        upstream_tree = run("rev-parse", source + "^{tree}").decode().strip()
        run("read-tree", source)
        run("apply", "--cached", "-", data=patch)
        changed = run("diff", "--cached", "--name-status", "--no-renames", "-z", source).decode().split("\0")[:-1]
        changes = [{"status": changed[i], "path": changed[i + 1]} for i in range(0, len(changed), 2)]
        if any(row["status"] not in ("A", "M") for row in changes):
            raise ValueError("deletions/renames/type changes require a different contract")
        expected = manifest["source_files"]
        paths = [x["path"] for x in expected]
        if len(set(paths)) != len(paths) or set(paths) != {x["path"] for x in changes}:
            raise ValueError("patch/manifest path membership differs")
        tree = run("write-tree").decode().strip()
        entries = run("ls-tree", "-r", "-z", tree).decode().split("\0")[:-1]
        digest, all_paths, by_path = hashlib.sha256(), set(), {}
        for entry in entries:
            metadata, name = entry.split("\t")
            mode, kind, blob = metadata.split()
            if kind != "blob" or mode not in ("100644", "100755", "120000"):
                raise ValueError("unsupported physical Git entry")
            raw, _ = physical(root, name, mode)
            if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != blob:
                raise ValueError("physical applied blob mismatch: " + name)
            row = [mode, blob, name, sha(raw)]
            digest.update(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
            all_paths.add(name)
            by_path[name] = {"path": name, "git_blob": blob, "mode": mode,
                             "sha256": sha(raw), "physical_sha256": sha(raw)}
        actual_paths = set()
        for folder, directories, files in os.walk(root, followlinks=False):
            if Path(folder) == root and ".git" in directories:
                directories.remove(".git")
            for name in list(directories):
                if (Path(folder) / name).is_symlink():
                    files.append(name)
                    directories.remove(name)
            actual_paths.update((Path(folder) / name).relative_to(root).as_posix() for name in files
                                if not (Path(folder) == root and name == ".git"))
        if all_paths != actual_paths:
            raise ValueError("complete physical membership differs (missing/extra/ignored)")
        pins = []
        for item in expected:
            equal(by_path[item["path"]]["sha256"], item["sha256"], "manifest/applied blob digest differs")
            pins.append(by_path[item["path"]])
        return {"upstream_tree": upstream_tree, "applied_tree": tree, "path_changes": changes,
                "source_files": pins, "complete_physical_tree": {
                    "sha256": digest.hexdigest(), "entries": len(entries),
                    "algorithm": "SHA256 of Git ls-tree -r -z order JSONL [mode,blob,path,file_sha256]; ensure_ascii=true, compact separators"}}


def compiler_binding(claim, pins, root, scratch, rustc):
    if claim.get("scope") != "STD_KERNEL_ONLY" or claim.get("verdict") != "verified":
        raise ValueError("unsupported compiler scope/verdict")
    actual = [row for row in pins if row["path"] == KERNEL]
    if len(actual) != 1:
        raise ValueError("kernel is not an applied source member")
    equal(claim["inputs"], actual, "compiled membership/input differs from applied source")
    if claim["output"].get("kind") != "LOCAL_STD_TEST_HARNESS_NOT_NATIVE_CLI":
        raise ValueError("unsupported compiler output")
    output = Path(claim["output"]["path"])
    raw, _ = physical(output.parent, output.name)
    equal({"sha256": sha(raw), "bytes": len(raw)},
          {k: claim["output"][k] for k in ("sha256", "bytes")}, "compiler output bytes differ")
    commands = [[claim["tool"]["path"], "--edition", "2024", "--test", str(root / KERNEL), "-o", str(output)],
                [str(output)]]
    equal([s["command"] for s in claim["steps"]], commands, "compiler recorded command/input/output differs")
    for step in claim["steps"]:
        if type(step["exit_code"]) is not int or step["exit_code"] != 0:
            raise ValueError("compiler raw exit is not zero")
        p = Path(step["log"])
        log, _ = physical(p.parent, p.name)
        equal(sha(log), step["log_sha256"], "compiler log digest differs")
    tool = Path(claim["tool"]["path"])
    raw, _ = physical(tool.parent, tool.name)
    equal(sha(raw), claim["tool"]["sha256"], "compiler tool digest differs")
    result = {"scope": "STD_KERNEL_ONLY", "compiled_membership": [KERNEL],
              "other_applied_files": [p["path"] for p in pins if p["path"] != KERNEL],
              "other_files_compiler_verdict": "not_measured", "replay": "not_measured"}
    if rustc is None:
        return result
    equal(str(rustc), str(tool), "operator compiler differs from measured tool")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch), "LANG": "C.UTF-8"}
    version = subprocess.check_output([str(rustc), "--version"], env=env, timeout=20).decode().strip()
    equal(version, claim["version"], "compiler version differs")
    replay = Path(tempfile.mkdtemp(dir=scratch, prefix="compiler-replay-"))
    binary = replay / "independent-std-kernel"
    commands = [[str(rustc), "--edition", "2024", "--test", str(root / KERNEL), "-o", str(binary)], [str(binary)]]
    steps = []
    for index, command in enumerate(commands):
        ran = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        log = replay / ("independent-compiler-" + str(index) + ".log")
        log.write_bytes(ran.stdout)
        steps.append({"command": command, "exit_code": ran.returncode, "log": str(log), "sha256": sha(ran.stdout)})
        if ran.returncode:
            raise ValueError("independent compiler/test replay failed; raw log preserved")
    result.update(replay="verified", steps=steps, tool_sha256=claim["tool"]["sha256"])
    equal(sha(physical(tool.parent, tool.name)[0]), claim["tool"]["sha256"],
          "compiler tool changed during replay")
    output_raw = physical(output.parent, output.name)[0]
    equal({"sha256": sha(output_raw), "bytes": len(output_raw)},
          {k: claim["output"][k] for k in ("sha256", "bytes")},
          "original compiler artifact changed during replay")
    for step in claim["steps"]:
        p = Path(step["log"])
        equal(sha(physical(p.parent, p.name)[0]), step["log_sha256"],
              "original compiler log changed during replay")
    return result


def consume(path, uri, task, key, repo, head, upstream, physical_root, scratch, rustc=None):
    """Return physical/compiler evidence. Does not emit a CAR or graph verdict."""
    raw, _ = physical(path.parent, path.name)
    native = native_binding(raw, task, uri, native_get(task, key))
    doc = decode(raw)
    if doc.get("schema") != "BenchNativePhysicalProjection/v1":
        raise ValueError("projection schema invalid")
    if doc.get("runtime_admission") is not False or doc.get("graph_admission") != "not_measured":
        raise ValueError("unsigned projection cannot grant runtime/graph admission")
    if doc.get("authentication") != "UNSIGNED_OFFLINE_MEASUREMENT" or doc.get("source_before_after_equal") is not True:
        raise ValueError("unsupported authentication/source observation")
    if doc.get("stage") != "accounting-tests":
        raise ValueError("only bounded STD kernel measurement is supported")
    if scratch.resolve(strict=True) != scratch or scratch.stat().st_uid != os.getuid():
        raise ValueError("scratch must be an existing owned directory without symlink ancestry")
    before = source_binding(repo, head)
    equal(doc["producer"], before, "producer Git/physical input binding differs")
    manifest_raw, _ = physical(repo, INPUTS[1])
    patch, _ = physical(repo, INPUTS[2])
    manifest = decode(manifest_raw)
    if (manifest.get("runtime_admission") is not False or manifest.get("production_authority_public_key") is not None
            or manifest.get("qualified_native_bounds_build_pin") is not None):
        raise ValueError("source manifest cannot grant activation or build authority")
    equal(sha(canonical(manifest)), doc["canonical_manifest_sha256"], "canonical manifest differs")
    equal(sha(patch), manifest["patch_sha256"], "patch digest differs")
    equal(doc["upstream"], manifest["upstream"], "upstream manifest differs")
    equal(git(upstream, "remote", "get-url", "origin").decode().strip(),
          manifest["upstream"]["repository"], "upstream origin differs")
    derived = rederive_patch(upstream, physical_root, manifest, patch, scratch)
    applied = doc["applied_source"]
    if (applied.get("schema") != "BenchAppliedPatchProjection/v2" or applied.get("runtime_admission") is not False
            or applied.get("graph_admission") != "not_measured" or applied.get("original_git_store_written") is not False):
        raise ValueError("unsupported applied projection/authority claim")
    for field, value in derived.items():
        equal(applied[field], value, "independent applied projection differs: " + field)
    equal(applied["count"], len(derived["source_files"]), "applied count differs")
    equal(applied["upstream_sha"], manifest["upstream"]["sha"], "upstream source commit differs")
    equal(applied["patch_sha256"], sha(patch), "applied patch digest differs")
    application = applied["patch_application"]
    equal(application["tool_path"], GIT, "unsupported patch tool")
    equal(application["tool_sha256"], sha(Path(GIT).read_bytes()), "Git tool bytes differ")
    equal(application["git_version"], git(upstream, "--version").decode().strip(), "Git version differs")
    equal(application["algorithm"], "git read-tree upstream; git apply --cached; git write-tree", "application algorithm differs")
    compiled = compiler_binding(doc["compiler"], derived["source_files"], physical_root, scratch, rustc)
    equal(source_binding(repo, head), before, "producer changed during independent consumption")
    equal(rederive_patch(upstream, physical_root, manifest, patch, scratch), derived,
          "physical projection changed during independent consumption")
    equal(sha(physical(path.parent, path.name)[0]), sha(raw), "native artifact changed during consumption")
    return {"schema": "NativePhysicalBindingReceipt/v1", "native_evidence": native,
            "producer": before, "independent_applied_source": derived, "compiler": compiled,
            "physical_binding": "verified", "graph_admission": "not_measured",
            "runtime_admission": False, "production_authority": False}

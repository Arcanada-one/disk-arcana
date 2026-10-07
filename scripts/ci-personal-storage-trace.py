#!/usr/bin/env python3
"""Bounded synthetic storage syscall evidence; no startup or runtime authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def executable(path):
    path = Path(path)
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or not os.access(path, os.X_OK):
        raise ValueError("executable must be a regular non-symlink file")
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError("current Linux build must be ELF")
    return {"path": str(path.resolve()), "sha256": digest(path)}


def source(repo, expected):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", expected) or git("rev-parse", "HEAD") != expected:
        raise ValueError("current checkout differs from expected exact source")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("source checkout is dirty")
    return {"head": expected, "tree": git("rev-parse", "HEAD^{tree}")}


def inspect_trace(raw, root):
    """-yy annotates descriptor-relative operations with actual fd paths.

    Children inherit no root descriptor, start outside the owned root, and any
    change of cwd refuses attribution. Unknown/incomplete syscall lines refuse.
    This observes one exclusive synthetic root, not whole-host confinement.
    """
    if not raw or not re.fullmatch(r"/[A-Za-z0-9_./-]+", root):
        raise ValueError("missing trace or unsupported exact root spelling")
    calls, exits, accesses, pending = 0, 0, [], {}
    for line in raw.splitlines():
        unfinished = re.match(r"(\d+)\s+(.+) <unfinished \.\.\.>$", line)
        resumed = re.match(r"(\d+)\s+<\.\.\. ([a-z0-9_]+) resumed>(.*)$", line)
        if unfinished:
            if unfinished[1] in pending:
                raise ValueError("duplicate unfinished syscall")
            pending[unfinished[1]] = unfinished[2]
            continue
        if resumed:
            prefix = pending.pop(resumed[1], None)
            if prefix is None or not prefix.startswith(resumed[2] + "("):
                raise ValueError("unpaired or mismatched resumed syscall")
            line = resumed[1] + " " + prefix + resumed[3]
        if re.fullmatch(r"\d+\s+\+\+\+ exited with 0 \+\+\+", line):
            exits += 1
            continue
        if re.match(r"\d+\s+--- SIG", line):
            continue
        match = re.match(r"\d+\s+([a-z0-9_]+)\(.*\)\s+=\s+.+$", line)
        if not match or match[1] in ("chdir", "fchdir", "chroot", "pivot_root"):
            raise ValueError("unknown trace record or changed path resolution")
        calls += 1
        if match[1] == "execve":
            # The owned root is an argv value, not the executable pathname.
            filename = re.match(r'\d+\s+execve\("([^"\\]+)"', line)
            if not filename:
                raise ValueError("unattributable executable pathname")
            if filename[1] == root or filename[1].startswith(root + "/"):
                accesses.append(line)
            continue
        if match[1] == "execveat":
            raise ValueError("descriptor-relative exec needs separate attribution")
        # Exact root, descendants and fd annotations; sibling prefixes do not match.
        if re.search(re.escape(root) + r'(?=[/">])', line):
            accesses.append(line)
    if pending or not calls or not exits:
        raise ValueError("trace lacks actual calls or successful process termination")
    return {"syscall_count": calls, "process_exits": exits,
            "storage_calls": accesses, "storage_call_count": len(accesses),
            "successful_storage_call_count": sum(not re.search(r"\)\s+=\s+-1\b", s)
                                                 for s in accesses)}


def judge(name, result, stdout, root_exists):
    if name.startswith("denied"):
        if stdout != b"STARTUP_UNAVAILABLE\n" or result["storage_call_count"] != 0:
            raise ValueError("startup denial touched storage or reported false success")
        if name == "denied-fresh" and root_exists:
            raise ValueError("denied startup created storage root")
    elif not root_exists or result["successful_storage_call_count"] == 0:
        raise ValueError("positive control did not observe actual storage calls")


def capture(command, prefix, timeout):
    with prefix.with_suffix(".stdout").open("wb") as out, prefix.with_suffix(".stderr").open("wb") as err:
        proc = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True,
                                close_fds=True)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise ValueError("bounded trace process timed out; raw output retained") from None
    if code != 0:
        raise ValueError("trace/worker process refused; raw failure retained")


def measure(args):
    repo, output = Path(args.repo).resolve(), Path(args.output).resolve()
    if output.is_relative_to(repo):
        raise ValueError("trace evidence must be outside the clean source checkout")
    binding = source(repo, args.expected_head)
    worker = executable(args.worker)
    tracer_path = shutil.which("strace")
    if not tracer_path:
        raise ValueError("strace unavailable; storage IO is NOT_MEASURED")
    tracer = executable(tracer_path)
    output.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": "PersonalStorageSyscallEvidence/v1", "source": binding,
               "worker": worker, "tracer": tracer, "run_id": args.run_id,
               "run_attempt": args.attempt, "probes": [], "verdict": "NOT_MEASURED",
               "runtime_authorized": False, "scope": "exclusive synthetic root only"}
    target = Path(tempfile.mkdtemp(prefix="personal-storage-trace-", dir=output))
    root = target / "fixture"
    try:
        previous = None
        for name, mode in [("denied-fresh", "denied"), ("seed", "seed"),
                           ("read", "read"), ("denied-existing", "denied")]:
            prefix = output / name
            trace = prefix.with_suffix(".trace")
            command = [tracer["path"], "-f", "-yy", "-s", "4096", "-o", str(trace),
                       "-e", "trace=%file,read,write,close,fsync,fdatasync,getdents64,fstat",
                       worker["path"], mode, str(root),
                       "10000000-0000-4000-8000-000000000001",
                       "20000000-0000-4000-8000-000000000001", "a"]
            capture(command, prefix, args.timeout)
            result = inspect_trace(trace.read_text(), str(root))
            stdout = prefix.with_suffix(".stdout").read_bytes()
            judge(name, result, stdout, root.exists())
            if mode == "seed":
                previous = stdout
                if not isinstance(json.loads(stdout), dict):
                    raise ValueError("positive receipt is not a JSON object")
            if mode == "read" and stdout != previous:
                raise ValueError("new-process read changed original receipt bytes")
            receipt["probes"].append({"name": name, "command": command, "exit": 0,
                                      **result, "raw": {suffix: digest(prefix.with_suffix(suffix))
                                                        for suffix in (".trace", ".stdout", ".stderr")}})
        if source(repo, args.expected_head) != binding or executable(args.worker) != worker:
            raise ValueError("source or executable changed during measurement")
        if executable(tracer_path) != tracer:
            raise ValueError("trace tool changed during measurement")
        receipt["verdict"] = "VERIFIED"
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        receipt["reason"] = str(error)
        raise
    finally:
        shutil.rmtree(target)  # Only this invocation's exclusively allocated fixture.
        (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("repo", "worker", "output", "expected-head", "run-id", "attempt"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120 or not re.fullmatch(r"[1-9][0-9]*", args.run_id) or not re.fullmatch(r"[1-9][0-9]*", args.attempt):
        parser.error("120-second maximum and genuine positive run/attempt IDs required")
    measure(args)


if __name__ == "__main__":
    main()

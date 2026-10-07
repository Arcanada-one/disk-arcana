"""Causal controls for trace attribution; these are not Disk runtime evidence."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "personal_trace", Path(__file__).parents[1] / "ci-personal-storage-trace.py")
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)

ROOT = "/owned/fixture"
EXIT = "123 +++ exited with 0 +++\n"
CONTROL = '123 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 3\n'


class TraceControls(unittest.TestCase):
    def test_direct_and_descriptor_relative_storage_are_observed(self):
        raw = ('123 openat(AT_FDCWD, "/owned/fixture", O_RDONLY) = 3</owned/fixture>\n'
               '123 openat(3</owned/fixture>, "inventory.sqlite", O_RDWR) = 4\n'
               '123 fsync(4</owned/fixture/inventory.sqlite>) = 0\n' + EXIT)
        self.assertEqual(trace.inspect_trace(raw, ROOT)["storage_call_count"], 3)

    def test_sibling_prefix_is_not_the_root(self):
        raw = '123 openat(AT_FDCWD, "/owned/fixture-sibling", O_RDONLY) = 3\n' + EXIT
        self.assertEqual(trace.inspect_trace(raw, ROOT)["storage_call_count"], 0)

    def test_interleaved_syscalls_require_exact_pid_and_name_pair(self):
        raw = ('123 read(4</owned/fixture/object>,  <unfinished ...>\n'
               + CONTROL.replace("123", "124")
               + '123 <... read resumed>"abc", 3) = 3\n' + EXIT)
        self.assertEqual(trace.inspect_trace(raw, ROOT)["storage_call_count"], 1)
        for changed in (raw.replace("123 <...", "125 <..."),
                        raw.replace("read resumed", "write resumed")):
            with self.assertRaises(ValueError):
                trace.inspect_trace(changed, ROOT)

    def test_exec_root_argument_is_not_executable_file_access(self):
        raw = '123 execve("/bin/worker", ["worker", "/owned/fixture"], 0x0) = 0\n' + EXIT
        self.assertEqual(trace.inspect_trace(raw, ROOT)["storage_call_count"], 0)
        changed = raw.replace('execve("/bin/worker"', 'execve("/owned/fixture/worker"')
        self.assertEqual(trace.inspect_trace(changed, ROOT)["storage_call_count"], 1)

    def test_missing_truncated_unknown_and_cwd_changes_refuse(self):
        for raw in ("", CONTROL, EXIT, CONTROL + "123 +++ killed by SIGKILL +++\n",
                    '123 openat(3, "x", O_RDWR <unfinished ...>\n' + EXIT,
                    '123 fchdir(3) = 0\n' + EXIT, "unknown\n" + EXIT):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                trace.inspect_trace(raw, ROOT)

    def test_storage_call_or_wrong_output_breaks_denied_control(self):
        result = trace.inspect_trace(CONTROL + EXIT, ROOT)
        trace.judge("denied-fresh", result, b"STARTUP_UNAVAILABLE\n", False)
        for output, exists in ((b"success\n", False), (b"STARTUP_UNAVAILABLE\n", True)):
            with self.assertRaises(ValueError):
                trace.judge("denied-fresh", result, output, exists)
        mutated = trace.inspect_trace('123 stat("/owned/fixture", {}) = -1 ENOENT\n' + EXIT, ROOT)
        with self.assertRaises(ValueError):
            trace.judge("denied-fresh", mutated, b"STARTUP_UNAVAILABLE\n", False)

    def test_unobserved_positive_control_refuses(self):
        with self.assertRaises(ValueError):
            trace.judge("seed", trace.inspect_trace(CONTROL + EXIT, ROOT), b"{}\n", True)
        failed = trace.inspect_trace('123 stat("/owned/fixture", {}) = -1 ENOENT\n' + EXIT, ROOT)
        with self.assertRaises(ValueError):
            trace.judge("seed", failed, b"{}\n", True)

    def test_executable_symlink_and_wrong_source_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link"
            link.symlink_to(sys.executable)
            with self.assertRaises(ValueError):
                trace.executable(link)
        with self.assertRaises(ValueError):
            trace.source(Path(__file__).parents[2], "wrong-source")

    def test_actual_harmless_tracer_positive_and_negative(self):
        # No Disk binary or storage service is executed. This observes only one
        # disposable text file to prove the parser against the real tracer.
        tool = shutil.which("strace")
        self.assertIsNotNone(tool, "strace control cannot silently skip")
        with tempfile.TemporaryDirectory(prefix="personal-trace-control-") as directory:
            root = Path(directory) / "fixture"
            log = Path(directory) / "trace"
            prefix = Path(directory) / "process"
            for code, expected in [("pass", 0), ("open(__import__('sys').argv[1], 'w').write('abc')", 1)]:
                trace.capture([tool, "-f", "-yy", "-s", "4096", "-o", str(log),
                               "-e", "trace=%file,read,write,close,fsync,fdatasync,getdents64,fstat",
                               sys.executable, "-c", code, str(root)], prefix, 10)
                measured = trace.inspect_trace(log.read_text(), str(root))
                self.assertEqual(measured["storage_call_count"] > 0, bool(expected))


if __name__ == "__main__":
    unittest.main()

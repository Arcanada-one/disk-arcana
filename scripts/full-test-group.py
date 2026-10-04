#!/usr/bin/env python3
"""Execute declared complete groups. Never consume prior CI logs or verdicts."""
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CRATES = tuple(Path(p).name for p in tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['members'])


class Unmeasured(Exception):
    """A required environment or positive test execution is missing."""


def check_unittest(output):
    counts = re.findall(r'^Ran (\d+) tests? in .+$', output, re.MULTILINE)
    ending = re.search(r'^OK(?: \(skipped=(\d+)\))?\s*\Z', output, re.MULTILINE)
    if not counts or int(counts[-1]) == 0 or not ending:
        raise Unmeasured('unittest discovery has no completed positive inventory')
    if int(ending[1] or 0):
        raise Unmeasured('unittest discovery left skipped tests unexecuted')


def vitest_inventory(report, plugin):
    if report.get('success') is not True or report.get('numFailedTests') != 0:
        raise Unmeasured('Vitest report is unsuccessful or incomplete')
    inventory = {}
    for suite in report.get('testResults', []):
        try:
            path = Path(suite['name']).resolve().relative_to(plugin.resolve()).as_posix()
        except (KeyError, ValueError) as exc:
            raise Unmeasured('Vitest file is outside the plugin inventory') from exc
        for case in suite.get('assertionResults', []):
            key = (path, case.get('fullName'))
            status = case.get('status')
            if not key[1] or key in inventory or status not in ('passed', 'skipped', 'pending'):
                raise Unmeasured('Vitest duplicate, todo, failed or unknown case')
            inventory[key] = status
    passed = sum(v == 'passed' for v in inventory.values())
    skipped = len(inventory) - passed
    if not passed or report.get('numTotalTests') != len(inventory):
        raise Unmeasured('Vitest empty/wholly skipped or inconsistent inventory')
    if (report.get('numPassedTests') != passed or report.get('numPendingTests') != skipped
            or report.get('numTodoTests') != 0):
        raise Unmeasured('Vitest summary disagrees with executed/skipped inventory')
    return inventory


def check_plugin_pair(ordinary, paired, plugin):
    base = vitest_inventory(ordinary, plugin)
    integration = vitest_inventory(paired, plugin)
    skipped = {k for k, status in base.items() if status != 'passed'}
    if any(k[0] != 'test/daemon-integration.test.ts' for k in skipped):
        raise Unmeasured('ordinary Vitest run has an unaccounted skipped test')
    if any(status != 'passed' for status in integration.values()) or set(integration) != skipped:
        raise Unmeasured('daemon integration did not execute the exact deferred inventory')


def lock_state():
    return {name: (ROOT / name).read_bytes() for name in
            ('Cargo.lock', 'fuzz/Cargo.lock', 'plugins/obsidian/package-lock.json')}


def run(command, cwd=ROOT, positive=False, suite=None, env=None):
    """Preserve raw output and failure; zero/wholly skipped tests are not evidence."""
    print('+ ' + ' '.join(command), flush=True)
    locks = lock_state()
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                env={**os.environ, **(env or {})})
    except FileNotFoundError as exc:
        raise Unmeasured(f'missing executable: {command[0]}') from exc
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', file=sys.stderr, flush=True)
    mutated = any(not (ROOT / name).is_file() or (ROOT / name).read_bytes() != data
                  for name, data in locks.items())
    if mutated:
        print('Source lockfile changed during command; preserve raw mutation evidence', file=sys.stderr)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command)
    if mutated:
        raise Unmeasured('source lockfile changed during command')
    if suite == 'unittest':
        check_unittest(result.stderr)
    if positive and not re.search(r'\b[1-9]\d* passed\b', result.stdout):
        raise Unmeasured('runner completed without a positive test count')
    if positive and re.search(r'\b[1-9]\d* ignored\b', result.stdout):
        raise Unmeasured('runner left ignored tests unexecuted')
    return result.stdout + result.stderr


def personal_preflight():
    """Probe the required syscall, without weakening provider confinement."""
    if sys.platform != 'linux' or os.uname().machine not in ('x86_64', 'aarch64'):
        raise Unmeasured('personal full suite requires supported Linux openat2')
    class OpenHow(ctypes.Structure):
        _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]
    libc = ctypes.CDLL(None, use_errno=True)
    with tempfile.TemporaryDirectory(prefix='disk-personal-full-preflight-') as directory:
        how = OpenHow(os.O_RDONLY | os.O_DIRECTORY, 0, 0)
        fd = libc.syscall(437, -100, directory.encode(), ctypes.byref(how), ctypes.sizeof(how))
        if fd < 0:
            raise Unmeasured(f'openat2 preflight errno={ctypes.get_errno()}')
        os.close(fd)


def storage_preflight():
    # Credential presence is NOT authorization. Callers need an independently
    # authorized disposable sandbox and must explicitly opt into these writes.
    if os.environ.get('DISK_FULL_TEST_REMOTE_SANDBOX') != 'authorized':
        raise Unmeasured('complete storage includes ignored B2/R2 live-bucket tests; separate sandbox authority required')
    # No authenticated disposable account/bucket grant consumer is wired here.
    # An opt-in or credentials cannot prove scope, exclusive smoke/demo.bin
    # cleanup custody, or current revocation status. Keep the full group closed
    # until the existing authority owner supplies a verifiable binding and its
    # consumer is implemented/reviewed. Never invent a local grant format.
    raise Unmeasured('storage authority consumer unavailable: authenticated B2/R2 '
                     'account/bucket, scoped grant, cleanup custody and current '
                     'revocation binding are not verified; opt-in is insufficient')


def crate(name):
    if name == 'disk-personal':
        personal_preflight()
    if name == 'disk-storage':
        storage_preflight()
    for features in (['--no-default-features'], ['--all-features']):
        run(['cargo', 'test', '-p', name, '--locked', *features, '--', '--include-ignored'], positive=True)


def fuzz():
    if os.environ.get('CI_LINKER_BOOTSTRAP') == 'zig':
        raise Unmeasured('full fuzz requires native sanitizer-capable linker; zig skip is not success')
    # cargo-fuzz does not expose Cargo's --locked flag. Refuse stale lockfiles
    # before it can resolve/build, then check that the tool kept the lock intact.
    run(['cargo', '+nightly', 'metadata', '--locked', '--format-version', '1',
         '--manifest-path', 'fuzz/Cargo.toml'])
    lock = (ROOT / 'fuzz/Cargo.lock').read_bytes()
    run(['cargo', '+nightly', 'fuzz', '--version'], ROOT / 'fuzz')
    targets = tomllib.loads((ROOT / 'fuzz/Cargo.toml').read_text())['bin']
    if not targets:
        raise Unmeasured('no fuzz targets declared')
    for target in targets:
        output = run(['cargo', '+nightly', 'fuzz', 'run', target['name'], '--', '-max_total_time=600'], ROOT / 'fuzz')
        if (ROOT / 'fuzz/Cargo.lock').read_bytes() != lock:
            raise Unmeasured('cargo-fuzz changed the locked source; preserve mutation evidence')
        if not re.search(r'Done [1-9]\d* runs in', output):
            raise Unmeasured(f"fuzzer did not report actual execution: {target['name']}")
    print(f'{len(targets)} passed (all declared fuzz targets, 600 seconds each)')


def plugin_tests():
    plugin = ROOT / 'plugins/obsidian'
    with tempfile.TemporaryDirectory(prefix='disk-plugin-accounting-') as directory:
        base, paired = (Path(directory) / n for n in ('ordinary.json', 'integration.json'))
        run(['npm', 'test', '--', '--reporter=json', f'--outputFile={base}'], plugin,
            env={'DISK_PLUGIN_INTEGRATION': '0'})
        run(['bash', 'scripts/test-obsidian-integration.sh', str(paired)])
        try:
            ordinary, integration = json.loads(base.read_text()), json.loads(paired.read_text())
        except (OSError, ValueError) as exc:
            raise Unmeasured('missing or invalid fresh Vitest inventory') from exc
        print(json.dumps({'ordinary': ordinary, 'paired_integration': integration}))
        check_plugin_pair(ordinary, integration, plugin)


def root():
    # Check known missing prerequisites before any broad work; never spend a
    # partial run and report it as a complete repository measurement.
    personal_preflight()
    storage_preflight()
    for name in CRATES:
        crate(name)
    run(['python3', '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-p', 'test_*.py'], suite='unittest')
    run(['python3', 'scripts/audit-metadb-selftest.py'])
    for test in sorted((ROOT / 'deploy/linux/tests').glob('test-*.sh')):
        run(['bash', str(test)])
    plugin = ROOT / 'plugins/obsidian'
    run(['npm', 'run', 'typecheck'], plugin)
    run(['node', 'node_modules/typescript/bin/tsc', '-p', 'tsconfig.generated.json', '--noEmit'], plugin)
    run(['node', str(plugin / 'node_modules/typescript/bin/tsc'), '-p', 'scripts/tsconfig.json', '--noEmit'])
    plugin_tests()
    run(['bash', 'scripts/load-test-harness.sh', 'all'])
    fuzz()


def main(args):
    if len(args) != 1 or args[0] not in (*CRATES, 'root', 'fuzz'):
        print('expected root, fuzz, or one workspace crate', file=sys.stderr)
        return 2
    try:
        group = args[0]
        root() if group == 'root' else fuzz() if group == 'fuzz' else crate(group)
        return 0
    except Unmeasured as exc:
        print(f'FULL_FALLBACK_TEST_NOT_MEASURED: {exc}', file=sys.stderr)
        return 127
    except subprocess.CalledProcessError as exc:
        return exc.returncode if exc.returncode > 0 else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Export the current CI build; never recover another job's retained files."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

MACHINES = {'x86_64-unknown-linux-gnu': 62, 'aarch64-unknown-linux-gnu': 183}
FIXTURE_WORKER = 'disk-capture-fixture-worker'


def known_cargo_links(binary, info):
    if info.st_nlink == 1:
        return True
    # Cargo links release/<name> to release/deps/<crate>-<hash>. Account for
    # every link; an extra alias elsewhere must still refuse the export.
    deps = binary.parent / 'deps'
    if binary.name not in ('disk-arcana-server', 'disk', FIXTURE_WORKER) or binary.parent.name not in ('release', 'debug'):
        return False
    if deps != deps.resolve(strict=True):
        return False
    directory = deps.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or directory.st_mode & 0o022:
        return False
    aliases = 0
    for candidate in deps.glob(binary.name.replace('-', '_') + '-*'):
        entry = candidate.lstat()
        if stat.S_ISREG(entry.st_mode) and (entry.st_dev, entry.st_ino) == (info.st_dev, info.st_ino):
            aliases += 1
    return aliases == 1 and info.st_nlink == 2


def export_binary(binary, private_root, target, provenance, name="disk-arcana-server"):
    if name not in ("disk-arcana-server", "disk", "it_local_e2e_writeback", FIXTURE_WORKER):
        raise ValueError("invalid_export_name")
    if target not in MACHINES:
        raise ValueError('unsupported_target')
    root = Path(private_root)
    binary = Path(binary).absolute()
    if any(char in str(root) for char in '\r\n') or binary != binary.resolve(strict=True):
        raise ValueError('indirect_or_invalid_export_path')
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('unowned_private_root')
    if root != root.resolve(strict=True):
        raise ValueError('indirect_private_root')
    fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
    output = None
    try:
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not known_cargo_links(binary, info):
                raise ValueError('unowned_binary')
            if not info.st_mode & 0o111 or not 64 <= info.st_size <= 268435456:
                raise ValueError('invalid_binary_bounds')
            header = source.read(64)
            if (header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != MACHINES[target]
                    or int.from_bytes(header[16:18], 'little') not in (2, 3)):
                raise ValueError('not_matching_linux_elf')
            source.seek(0)
            output = Path(tempfile.mkdtemp(prefix='server-export.', dir=root))
            digest = hashlib.sha256()
            copied = 0
            with (output / name).open('xb') as dest:
                while chunk := source.read(1048576):
                    copied += len(chunk)
                    if copied > info.st_size:
                        raise ValueError('binary_grew_during_export')
                    digest.update(chunk)
                    dest.write(chunk)
            final = os.fstat(source.fileno())
            if copied != info.st_size or (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns, final.st_nlink):
                raise ValueError('binary_changed_during_export')
        (output / name).chmod(0o700)
        manifest = dict(provenance, schema='DiskLinuxBuildExport/v1', target=target,
                        binary=name, binary_sha256=digest.hexdigest(), bytes=info.st_size)
        (output / 'BUILD.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        (output / 'BUILD.json').chmod(0o600)
        return output
    except Exception:
        if output is not None:
            shutil.rmtree(output)
        raise



def export_cli(log, target_root, root, provenance):
    """Select both outputs from the existing successful Cargo invocation."""
    selected = {}
    finished = []
    for line in Path(log).read_text().splitlines():
        if not line.startswith('{'):
            continue  # libtest output shares Cargo's stdout
        row = json.loads(line)
        if row.get('reason') == 'build-finished':
            finished.append(row.get('success'))
        if row.get('reason') != 'compiler-artifact' or not row.get('executable'):
            continue
        target = row.get('target', {})
        name = target.get('name')
        expected = {'disk': ['bin'], 'it_local_e2e_writeback': ['test']}
        if name not in expected:
            continue
        if target.get('kind') != expected[name] or row.get('profile', {}).get('test') != (name != 'disk'):
            continue
        src = Path(target['src_path']).resolve(strict=True)
        workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
        source = {'disk': 'crates/disk-cli/src/main.rs',
                  'it_local_e2e_writeback': 'crates/disk-cli/tests/it_local_e2e_writeback.rs'}[name]
        if src != workspace / source or name in selected:
            raise ValueError('ambiguous_or_foreign_cargo_target')
        binary = Path(row['executable'])
        expected_parent = target_root / 'debug' / ('deps' if name != 'disk' else '')
        if binary.parent != expected_parent or (name == 'disk' and binary.name != 'disk'):
            raise ValueError('foreign_cargo_output')
        if name != 'disk' and not binary.name.startswith(name + '-'):
            raise ValueError('wrong_driver_output')
        selected[name] = (binary, row)
    if finished != [True] or set(selected) != {'disk', 'it_local_e2e_writeback'}:
        raise ValueError('missing_successful_cargo_outputs')
    outputs = []
    try:
        for name, (binary, row) in selected.items():
            binding = dict(provenance, cargo_artifact=row,
                           cargo_argv=['cargo', 'test', '--workspace', '--all-features', '--message-format=json'],
                           original_daemon_path=str(selected['disk'][0]),
                           relocation='Driver embeds original_daemon_path; export does not authorize restoring foreign paths')
            outputs.append(export_binary(binary, root, 'x86_64-unknown-linux-gnu', binding, name))
        return outputs
    except Exception:
        for output in outputs:
            shutil.rmtree(output)
        raise


def export_fixture(log, target_root, root, provenance):
    """Separate synthetic worker artifact; existing CLI pair stays unchanged."""
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    selected, finished = [], []
    for line in Path(log).read_text().splitlines():
        if not line.startswith('{'):
            continue
        row = json.loads(line)
        if row.get('reason') == 'build-finished':
            finished.append(row.get('success'))
        target = row.get('target', {})
        if row.get('reason') != 'compiler-artifact' or target.get('name') != FIXTURE_WORKER:
            continue
        if row.get('profile', {}).get('test') is True:
            continue  # libtest harness is not the fixture executable.
        if (row.get('profile', {}).get('test') is not False or target.get('kind') != ['bin']
                or not isinstance(row.get('features'), list)
                or 'synthetic-fixtures' not in row['features']
                or target.get('required-features') != ['synthetic-fixtures']):
            raise ValueError('wrong_fixture_cargo_target')
        if (Path(target['src_path']).resolve(strict=True) != workspace / 'crates/disk-personal/src/bin/disk-capture-fixture-worker.rs'
                or Path(row['manifest_path']).resolve(strict=True) != workspace / 'crates/disk-personal/Cargo.toml'):
            raise ValueError('foreign_fixture_source')
        binary = Path(row['executable'])
        if binary != target_root / 'debug' / FIXTURE_WORKER or selected:
            raise ValueError('ambiguous_or_foreign_fixture_output')
        selected.append((binary, row))
    if finished != [True] or len(selected) != 1:
        raise ValueError('missing_successful_fixture_output')
    binary, row = selected[0]
    binding = dict(provenance, cargo_artifact=row,
                   cargo_argv=['cargo', 'test', '--workspace', '--all-features', '--message-format=json'],
                   scope='synthetic_fixture_only', runtime_authorized=False)
    return export_binary(binary, root, 'x86_64-unknown-linux-gnu', binding, FIXTURE_WORKER)


def main(argv=()):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux':
        raise ValueError('native_linux_ci_required')
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    expected = os.environ['EXPECTED_BUILD_SHA']
    head = subprocess.check_output(['git', '-C', str(workspace), 'rev-parse', 'HEAD'], text=True).strip()
    tree = subprocess.check_output(['git', '-C', str(workspace), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    if head != expected or len(head) != 40 or any(c not in '0123456789abcdef' for c in head):
        raise ValueError('checkout_source_mismatch')
    subprocess.run(['git', '-C', str(workspace), 'diff', '--exit-code', '--quiet', 'HEAD', '--'], check=True)
    root = Path(os.environ['CI_ISOLATED_RUST_ROOT'])
    target_root = Path(os.environ.get('CARGO_TARGET_DIR', str(workspace / 'target'))).resolve(strict=True)
    if target_root not in (workspace / 'target', root / 'target'):
        raise ValueError('foreign_target_root')
    target = os.environ['BUILD_TARGET']
    if target not in MACHINES:
        raise ValueError('unsupported_target')
    provenance = {'checkout_sha': head, 'checkout_tree': tree,
                  'repository': os.environ['GITHUB_REPOSITORY'], 'run_id': os.environ['GITHUB_RUN_ID'],
                  'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'job_key': os.environ['GITHUB_JOB'],
                  'runner_name': os.environ['RUNNER_NAME']}
    if len(argv) == 2 and argv[0] in ('--cli', '--fixture'):
        provenance.update(rustc_verbose=subprocess.check_output(['rustc', '-vV'], text=True),
                          cargo_version=subprocess.check_output(['cargo', '-V'], text=True),
                          cargo_lock_sha256=hashlib.sha256((workspace / 'Cargo.lock').read_bytes()).hexdigest(),
                          cargo_messages_sha256=hashlib.sha256(Path(argv[1]).read_bytes()).hexdigest())
        if argv[0] == '--cli':
            outputs = export_cli(argv[1], target_root, root, provenance)
        else:
            if target != 'x86_64-unknown-linux-gnu':
                raise ValueError('unsupported_fixture_target')
            outputs = [export_fixture(argv[1], target_root, root, provenance)]
    elif not argv:
        outputs = [export_binary(target_root / target / 'release/disk-arcana-server', root, target, provenance)]
    else:
        raise ValueError('invalid_export_arguments')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as values:
        for index, output in enumerate(outputs):
            key = 'directory' if len(outputs) == 1 else 'directory' + str(index)
            values.write(key + '=' + str(output) + '\n')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception:
        print('Linux build export refused; no foreign build or credentials accessed', file=sys.stderr)
        sys.exit(1)

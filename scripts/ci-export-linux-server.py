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


def known_cargo_links(binary, info):
    if info.st_nlink == 1:
        return True
    # Cargo links release/<name> to release/deps/<crate>-<hash>. Account for
    # every link; an extra alias elsewhere must still refuse the export.
    deps = binary.parent / 'deps'
    if binary.name != 'disk-arcana-server' or binary.parent.name != 'release':
        return False
    if deps != deps.resolve(strict=True):
        return False
    directory = deps.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or directory.st_mode & 0o022:
        return False
    aliases = 0
    for candidate in deps.glob('disk_arcana_server-*'):
        entry = candidate.lstat()
        if stat.S_ISREG(entry.st_mode) and (entry.st_dev, entry.st_ino) == (info.st_dev, info.st_ino):
            aliases += 1
    return aliases == 1 and info.st_nlink == 2


def export_binary(binary, private_root, target, provenance):
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
            if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != MACHINES[target]:
                raise ValueError('not_matching_linux_elf')
            source.seek(0)
            output = Path(tempfile.mkdtemp(prefix='server-export.', dir=root))
            digest = hashlib.sha256()
            copied = 0
            with (output / 'disk-arcana-server').open('xb') as dest:
                while chunk := source.read(1048576):
                    copied += len(chunk)
                    if copied > info.st_size:
                        raise ValueError('binary_grew_during_export')
                    digest.update(chunk)
                    dest.write(chunk)
            final = os.fstat(source.fileno())
            if copied != info.st_size or (info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns, final.st_nlink):
                raise ValueError('binary_changed_during_export')
        (output / 'disk-arcana-server').chmod(0o700)
        manifest = dict(provenance, schema='DiskLinuxBuildExport/v1', target=target,
                        binary='disk-arcana-server', binary_sha256=digest.hexdigest(), bytes=info.st_size)
        (output / 'BUILD.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        (output / 'BUILD.json').chmod(0o600)
        return output
    except Exception:
        if output is not None:
            shutil.rmtree(output)
        raise


def main():
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
    output = export_binary(target_root / target / 'release/disk-arcana-server', root, target, provenance)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as values:
        values.write('directory=' + str(output) + '\n')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Linux build export refused; no foreign build or credentials accessed', file=sys.stderr)
        sys.exit(1)

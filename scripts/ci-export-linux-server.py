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


def strict_path(path, kind):
    """Resolve a path that must exist; a miss names only the kind of path."""
    try:
        return Path(path).resolve(strict=True)
    except FileNotFoundError:
        raise FileNotFoundError('missing_' + kind) from None


def private_directory(directory):
    """True for a real directory owned by this user and not writable by others."""
    try:
        entry = directory.lstat()
        if directory != directory.resolve(strict=True):
            return False
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(entry.st_mode) and entry.st_uid == os.getuid() and not entry.st_mode & 0o022


def cargo_alias_directories(profile_dir):
    """Directories where cargo may hard-link a binary: deps/ (up to cargo 1.99)
    or build/<pkg>/<hash>/out/ (cargo 1.100 build-dir layout). Only private,
    unindirected directories are returned; anything else is not searched.
    The flag says whether the plain binary name (no -<hash> suffix) is an
    allowed alias name there (also with underscores for a crate name with
    dashes); cargo 1.100 links target/<profile>/<name> to
    build/<pkg>/<hash>/out/<name>."""
    found = []
    deps = profile_dir / 'deps'
    if private_directory(deps):
        found.append((deps, False))
    build = profile_dir / 'build'
    if private_directory(build):
        for package in sorted(build.iterdir()):
            if not private_directory(package):
                continue
            for unit in sorted(package.iterdir()):
                out = unit / 'out'
                if private_directory(unit) and private_directory(out):
                    found.append((out, True))
    return found


def known_cargo_links(binary, info):
    if info.st_nlink == 1:
        return True
    # Cargo links release/<name> to its unit output (deps/<crate>-<hash> or, with
    # cargo 1.100, build/<pkg>/<hash>/out/<crate>-<hash>). Account for every
    # link; an extra alias elsewhere must still refuse the export.
    if binary.name not in ('disk-arcana-server', 'disk') or binary.parent.name not in ('release', 'debug'):
        return False
    aliases = 0
    for directory, plain_name in cargo_alias_directories(binary.parent):
        patterns = [binary.name.replace('-', '_') + '-*'] + ([binary.name, binary.name.replace('-', '_')] if plain_name else [])
        for candidate in sorted({c for pattern in patterns for c in directory.glob(pattern)}):  # a set: no file counts twice
            entry = candidate.lstat()
            if stat.S_ISREG(entry.st_mode) and (entry.st_dev, entry.st_ino) == (info.st_dev, info.st_ino):
                aliases += 1
    return aliases == 1 and info.st_nlink == 2


def export_binary(binary, private_root, target, provenance, name="disk-arcana-server"):
    if name not in ("disk-arcana-server", "disk", "it_local_e2e_writeback"):
        raise ValueError("invalid_export_name")
    if target not in MACHINES:
        raise ValueError('unsupported_target')
    root = Path(private_root)
    binary = Path(binary).absolute()
    if any(char in str(root) for char in '\r\n') or binary != strict_path(binary, 'binary'):
        raise ValueError('indirect_or_invalid_export_path')
    try:
        info = root.lstat()
    except FileNotFoundError:
        raise FileNotFoundError('missing_private_root') from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('unowned_private_root')
    if root != strict_path(root, 'private_root'):
        raise ValueError('indirect_private_root')
    try:
        fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise FileNotFoundError('missing_binary') from None
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



def cargo_output_location_ok(binary, target_root, name):
    """True when a cargo-reported executable sits where this workspace's cargo puts it.

    The daemon binary is target/debug/disk. A test driver is target/debug/deps/<file>
    (cargo up to 1.99) or target/debug/build/<pkg>/<hash>/out/<file> (cargo 1.100
    build-dir layout). Anything else, including any path outside target_root/debug,
    is foreign.
    """
    try:
        parts = binary.relative_to(target_root / 'debug').parts
    except ValueError:
        return False
    if name == 'disk':
        return len(parts) == 1
    if len(parts) == 2 and parts[0] == 'deps':
        return True
    return len(parts) == 5 and parts[0] == 'build' and parts[3] == 'out' and '' not in parts


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
        src = strict_path(target['src_path'], 'source_file')
        workspace = strict_path(os.environ['GITHUB_WORKSPACE'], 'workspace')
        source = {'disk': 'crates/disk-cli/src/main.rs',
                  'it_local_e2e_writeback': 'crates/disk-cli/tests/it_local_e2e_writeback.rs'}[name]
        if src != workspace / source or name in selected:
            raise ValueError('ambiguous_or_foreign_cargo_target')
        binary = Path(row['executable'])
        if not cargo_output_location_ok(binary, target_root, name) or (name == 'disk' and binary.name != 'disk'):
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


def main(argv=()):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux':
        raise ValueError('native_linux_ci_required')
    workspace = strict_path(os.environ['GITHUB_WORKSPACE'], 'workspace')
    expected = os.environ['EXPECTED_BUILD_SHA']
    head = subprocess.check_output(['git', '-C', str(workspace), 'rev-parse', 'HEAD'], text=True).strip()
    tree = subprocess.check_output(['git', '-C', str(workspace), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    if head != expected or len(head) != 40 or any(c not in '0123456789abcdef' for c in head):
        raise ValueError('checkout_source_mismatch')
    subprocess.run(['git', '-C', str(workspace), 'diff', '--exit-code', '--quiet', 'HEAD', '--'], check=True)
    root = Path(os.environ['CI_ISOLATED_RUST_ROOT'])
    target_root = strict_path(os.environ.get('CARGO_TARGET_DIR', str(workspace / 'target')), 'target_root')
    if target_root not in (workspace / 'target', root / 'target'):
        raise ValueError('foreign_target_root')
    target = os.environ['BUILD_TARGET']
    if target not in MACHINES:
        raise ValueError('unsupported_target')
    provenance = {'checkout_sha': head, 'checkout_tree': tree,
                  'repository': os.environ['GITHUB_REPOSITORY'], 'run_id': os.environ['GITHUB_RUN_ID'],
                  'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'job_key': os.environ['GITHUB_JOB'],
                  'runner_name': os.environ['RUNNER_NAME']}
    if len(argv) == 2 and argv[0] == '--cli':
        provenance.update(rustc_verbose=subprocess.check_output(['rustc', '-vV'], text=True),
                          cargo_version=subprocess.check_output(['cargo', '-V'], text=True),
                          cargo_lock_sha256=hashlib.sha256((workspace / 'Cargo.lock').read_bytes()).hexdigest(),
                          cargo_messages_sha256=hashlib.sha256(Path(argv[1]).read_bytes()).hexdigest())
        outputs = export_cli(argv[1], target_root, root, provenance)
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
    except Exception as error:
        # Name the refusal condition: ValueError messages are fixed reason codes;
        # for any other error only the class name is printed, never its text.
        named = isinstance(error, ValueError) or (isinstance(error, FileNotFoundError) and error.args[:1] and str(error.args[0]).startswith('missing_') and len(error.args) == 1)
        reason = str(error) if named else type(error).__name__
        print('Linux build export refused (' + reason + '); no foreign build or credentials accessed', file=sys.stderr)
        sys.exit(1)

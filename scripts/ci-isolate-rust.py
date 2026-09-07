#!/usr/bin/env python3
"""Isolate Rust CI state without installing or repairing runner-wide tools.

Leave these job-owned directories until runner cleanup after cache post-actions.
Unique CARGO/RUST homes intentionally retain the cache action's complete env hash;
fresh toolchain downloads and cold cache misses are the cost of this isolation.
"""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

PROXIES = ('cargo', 'rustc', 'rustdoc', 'rustfmt', 'cargo-fmt', 'clippy-driver', 'cargo-clippy')


def protected_executable(path):
    path = path.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise ValueError('rustup is not an executable regular file')
    for item in (path, *path.parents):
        info = item.stat()
        if info.st_uid not in (0, os.getuid()):
            raise ValueError('rustup path has an unexpected owner')
        if info.st_mode & 0o022 and not (item.is_dir() and info.st_mode & stat.S_ISVTX):
            raise ValueError('rustup path is writable by another account')
    return path


def prepare():
    parent = Path(os.environ['RUNNER_TEMP'])
    if not parent.is_absolute() or not parent.is_dir():
        raise ValueError('RUNNER_TEMP must be an existing absolute directory')
    # Never invoke rustup-init or override HOME. PATH may omit the standard proxy directory.
    candidates = [shutil.which('rustup'), str(Path.home() / '.cargo/bin/rustup')]
    existing = None
    for candidate in candidates:
        if not candidate:
            continue
        try:
            existing = protected_executable(Path(candidate))
            break
        except (OSError, ValueError):
            continue
    if existing is None:
        raise ValueError('A protected existing rustup executable is required; no installer fallback')
    root = Path(tempfile.mkdtemp(prefix='disk-rust.', dir=parent)).resolve()
    cargo, rustup = root / 'cargo', root / 'rustup'
    for directory in (cargo, rustup, cargo / 'bin'):
        directory.mkdir(mode=0o700)
    shutil.copyfile(existing, cargo / 'bin/rustup')
    (cargo / 'bin/rustup').chmod(0o700)
    for name in PROXIES:
        (cargo / 'bin' / name).symlink_to('rustup')
    values = {'CI_ISOLATED_RUST_ROOT': str(root), 'CARGO_HOME': str(cargo), 'RUSTUP_HOME': str(rustup), 'CARGO_INSTALL_ROOT': str(cargo)}
    env = dict(os.environ, **values)
    subprocess.run([str(cargo / 'bin/rustup'), '--version'], env=env, check=True)
    for value in values.values():
        if '\n' in value or '\r' in value:
            raise ValueError('Invalid path for workflow environment')
    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as output:
        output.writelines(f'{key}={value}\n' for key, value in values.items())
    with open(os.environ['GITHUB_PATH'], 'a', encoding='utf-8') as output:
        output.write(str(cargo / 'bin') + '\n')
    print(f'Isolated Rust CI state: {root}')


def verify(toolchain):
    root = Path(os.environ['CI_ISOLATED_RUST_ROOT']).resolve(strict=True)
    cargo, rustup = root / 'cargo', root / 'rustup'
    for key, expected in [('CARGO_HOME', cargo), ('CARGO_INSTALL_ROOT', cargo), ('RUSTUP_HOME', rustup)]:
        if Path(os.environ[key]).resolve() != expected:
            raise ValueError(f'{key} escaped isolated state')
    for name in ('rustup', *PROXIES):
        command = shutil.which(name)
        if not command or Path(command).absolute().parent != cargo / 'bin':
            raise ValueError(f'{name} resolves outside isolated proxy directory')
    actual = subprocess.check_output(['rustup', 'show', 'home'], text=True).strip()
    if Path(actual).resolve() != rustup:
        raise ValueError('rustup selected a different home')
    for name in ('cargo', 'rustc'):
        binary = Path(subprocess.check_output(['rustup', 'which', '--toolchain', toolchain, name], text=True).strip()).resolve(strict=True)
        if not binary.is_relative_to(rustup / 'toolchains'):
            raise ValueError(f'{name} toolchain escaped isolated home')
        subprocess.run([str(binary), '--version'], check=True)


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['prepare']:
            prepare()
        elif len(sys.argv) == 3 and sys.argv[1] == 'verify':
            verify(sys.argv[2])
        else:
            raise ValueError('usage: ci-isolate-rust.py prepare | verify TOOLCHAIN')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(f'Rust CI isolation prerequisite failed: {error}')

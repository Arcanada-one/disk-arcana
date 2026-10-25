#!/usr/bin/env python3
"""Isolate Rust CI state without installing or repairing runner-wide tools.

Leave these job-owned directories until runner cleanup after cache post-actions.
Unique CARGO/RUST homes intentionally retain the cache action's complete env hash;
fresh toolchain downloads and cold cache misses are the cost of this isolation.
"""
import os
import hashlib
import platform
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

PROXIES = ('cargo', 'rustc', 'rustdoc', 'rustfmt', 'cargo-fmt', 'clippy-driver', 'cargo-clippy')
# Version and digest independently pinned from the official archive checksum:
# https://static.rust-lang.org/rustup/archive/1.29.1/x86_64-unknown-linux-gnu/rustup-init.sha256
# Flags and write destinations reviewed at rust-lang/rustup commit
# d95a37b6ab92cc1e455d1576039333c97ca3e2c5 (tag 1.29.1), src/cli/setup_mode.rs
# and self_update.rs / self_update/{unix,shell}.rs. No moving installer script.
RUSTUP_INIT_URL = 'https://static.rust-lang.org/rustup/archive/1.29.1/x86_64-unknown-linux-gnu/rustup-init'
RUSTUP_INIT_SHA256 = 'dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71'


def bootstrap(root, env):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('Pinned bootstrap supports only Linux x86_64 CI runners')
    installer = root / 'rustup-init'
    # curl cannot use a user curlrc, a shell installer, or an unpinned checksum.
    with installer.open('xb'):
        pass
    installer.chmod(0o600)
    subprocess.run(['curl', '--disable', '--fail', '--silent', '--show-error',
                    '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
                    '--connect-timeout', '15', '--max-time', '120',
                    '--max-filesize', '33554432', '--output', str(installer), RUSTUP_INIT_URL],
                   env=env, cwd=root, timeout=150, check=True)
    if hashlib.sha256(installer.read_bytes()).hexdigest() != RUSTUP_INIT_SHA256:
        raise ValueError('Pinned rustup-init SHA256 mismatch; installer was not executed')
    installer.chmod(0o700)
    subprocess.run([str(installer), '--no-modify-path', '--default-toolchain', 'none',
                    '--profile', 'minimal', '-y'], env=env, cwd=root, timeout=60, check=True)
    protected_executable(Path(env['CARGO_HOME']) / 'bin/rustup')
    print('Bootstrapped pinned rustup 1.29.1 into job-owned homes')


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
    # Prefer copying a protected existing tool; PATH may omit its standard directory.
    candidates = [('PATH', shutil.which('rustup')),
                  ('standard cargo directory', str(Path.home() / '.cargo/bin/rustup'))]
    existing = None
    for label, candidate in candidates:
        if not candidate:
            print(f'Existing rustup candidate ({label}): not found')
            continue
        try:
            existing = protected_executable(Path(candidate))
            break
        except OSError as error:
            print(f'Existing rustup candidate ({label}): unavailable (errno {error.errno})')
            continue
        except ValueError as error:
            print(f'Existing rustup candidate ({label}): rejected ({error})')
            continue
    root = Path(tempfile.mkdtemp(prefix='disk-rust.', dir=parent)).resolve()
    cargo, rustup = root / 'cargo', root / 'rustup'
    for directory in (cargo, rustup, cargo / 'bin'):
        directory.mkdir(mode=0o700)
    values = {'CI_ISOLATED_RUST_ROOT': str(root), 'CARGO_HOME': str(cargo), 'RUSTUP_HOME': str(rustup), 'CARGO_INSTALL_ROOT': str(cargo)}
    env = dict(os.environ, **values)
    for value in values.values():
        if '\n' in value or '\r' in value:
            raise ValueError('Invalid path for workflow environment')
    if existing is not None:
        shutil.copyfile(existing, cargo / 'bin/rustup')
        (cargo / 'bin/rustup').chmod(0o700)
        for name in PROXIES:
            (cargo / 'bin' / name).symlink_to('rustup')
    else:
        bootstrap(root, env)
    subprocess.run([str(cargo / 'bin/rustup'), '--version'], env=env, check=True, timeout=30)
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

"""Read-only, bounded external input qualification for the personal CI receiver.

This is metadata capture, not a permission, installer, cache repair or runner.
Unsupported hooks/configuration/cache layouts remain explicitly incomplete.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import sysconfig
import tarfile
import time
import tomllib

MAX_FILES = 12000
MAX_BYTES = 192 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
CODE_SUFFIXES = {'.py', '.pyi', '.pyc', '.so', '.zip', '.txt', '.json', '.pem'}
# Certificates are not secrets when they are system CA data, but private keys
# are never read. This pilot refuses PEM altogether rather than guessing.
CODE_SUFFIXES.remove('.pem')


class Unknown(ValueError):
    """Only fixed diagnostic codes leave this module; never config values."""


class Inventory:
    def __init__(self):
        self.files = {}
        self.bytes = 0
        self.deadline = time.monotonic() + 45

    def protected(self, path):
        path = Path(path).absolute()
        for part in (path, *path.parents):
            s = part.lstat()
            if stat.S_ISLNK(s.st_mode):
                raise Unknown('symlink input requires separate qualification')
            if s.st_uid not in (0, os.getuid()) or (s.st_mode & 0o022 and not
                    (stat.S_ISDIR(s.st_mode) and s.st_mode & stat.S_ISVTX)):
                raise Unknown('external input is writable by another identity')
        return path

    def read(self, path):
        if time.monotonic() > self.deadline or len(self.files) >= MAX_FILES:
            raise Unknown('external input inventory budget exceeded')
        path = self.protected(path)
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise Unknown('external input is not a bounded regular file')
        if self.bytes + before.st_size > MAX_BYTES:
            raise Unknown('external input byte budget exceeded')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(MAX_FILE + 1)
                after = os.fstat(stream.fileno())
        finally:
            # fdopen owns fd; no writes, follows, extraction or execution.
            pass
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(raw) > MAX_FILE or stamp(before) != stamp(after) or stamp(after) != stamp(path.stat()):
            raise Unknown('external input changed during capture')
        self.bytes += len(raw)
        return raw

    def capture(self, path, raw=None):
        path = Path(path).absolute()
        raw = self.read(path) if raw is None else raw
        self.files[str(path)] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'mode': stat.S_IMODE(path.stat().st_mode)}
        return raw

    def tree(self, root):
        root = self.protected(root)
        entries = 0
        for folder, dirs, names in os.walk(root, followlinks=False):
            entries += len(dirs) + len(names)
            if entries > MAX_FILES or time.monotonic() > self.deadline:
                raise Unknown('external directory/time budget exceeded')
            self.protected(Path(folder))
            if len(dirs) + len(names) > MAX_FILES:
                raise Unknown('external directory budget exceeded')
            for name in sorted(dirs):
                self.protected(Path(folder) / name)
            for name in sorted(names):
                yield Path(folder) / name


def python_inputs(inventory, paths=None, prefixes=None):
    """Capture supported CPython search roots, including existing bytecode."""
    if sys.implementation.name != 'cpython' or sys.platform != 'linux':
        raise Unknown('unsupported Python implementation/platform')
    if sys.prefix != sys.base_prefix or sys.exec_prefix != sys.base_exec_prefix:
        raise Unknown('virtual Python environment requires separate qualification')
    if any(key.startswith('PYTHON') and key not in
           {'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED'} for key in os.environ):
        raise Unknown('unqualified Python startup environment')
    roots = prefixes if prefixes is not None else {
        Path(sysconfig.get_path('stdlib')), Path(sysconfig.get_path('platstdlib')),
        Path(sysconfig.get_path('purelib')), Path(sysconfig.get_path('platlib')),
    }
    roots = {Path(p).absolute() for p in roots}
    entries = [Path(p).absolute() for p in (sys.path if paths is None else paths) if p]
    # Script path is source-bound elsewhere, not a site import override.
    source_scripts = Path(__file__).absolute().parent
    allowed_missing_zip = Path(sys.base_prefix) / 'lib' / ('python%d%d.zip' % sys.version_info[:2])
    observed = []
    for p in entries:
        if p == source_scripts:
            continue
        if p not in roots and not any(p.is_relative_to(root) for root in roots) and p != allowed_missing_zip:
            raise Unknown('unqualified Python search root')
        if not p.exists():
            if p != allowed_missing_zip:
                raise Unknown('missing Python search input')
            observed.append({'path': str(p), 'present': False})
        elif p.is_file():
            # Zip execution/import layouts need an explicit separate protocol.
            raise Unknown('Python zip search input requires separate qualification')
        else:
            inventory.protected(p)
            observed.append({'path': str(p), 'present': True})
    extensions = {}
    for root in sorted(roots):
        if not root.exists():
            observed.append({'path': str(root), 'present': False})
            continue
        for path in inventory.tree(root):
            if path.name.endswith('.pth') or path.name.startswith(('sitecustomize.', 'usercustomize.')):
                raise Unknown('Python startup hook requires separate qualification')
            if re.search(r'credentials|secret|private[-_]?key|\.env(?:\.|$)', path.name, re.I):
                raise Unknown('Python runtime file may contain protected material')
            if path.suffix not in CODE_SUFFIXES and path.name not in {'LICENSE', 'README', 'Makefile'}:
                raise Unknown('unknown Python runtime file type')
            raw = inventory.capture(path)
            if path.suffix == '.so':
                extensions[str(path)] = {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}
    # Import startup files outside sys.path can still select a venv/._pth.
    executable = Path(sys.executable).absolute()
    for p in (executable.parent / 'pyvenv.cfg', executable.parent.parent / 'pyvenv.cfg',
              executable.with_suffix('._pth'), executable.parent / ('python%d%d._pth' % sys.version_info[:2])):
        if p.exists() or p.is_symlink():
            raise Unknown('Python startup configuration requires separate qualification')
    return {'complete': True, 'version': list(sys.version_info[:3]), 'search_roots': observed,
            'extension_files': extensions}


CONFIG_ALLOW = {
    'build': {'jobs': lambda x: type(x) is int and 1 <= x <= 128,
              'incremental': lambda x: type(x) is bool},
    'net': {'offline': lambda x: type(x) is bool,
            'retry': lambda x: type(x) is int and 0 <= x <= 10,
            'git-fetch-with-cli': lambda x: type(x) is bool},
    'term': {'verbose': lambda x: type(x) is bool, 'quiet': lambda x: type(x) is bool,
             'color': lambda x: x in ('auto', 'always', 'never')},
    'registries': {'crates-io': lambda x: x == {'protocol': 'sparse'}},
}


def cargo_config(raw):
    try:
        doc = tomllib.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise Unknown('Cargo configuration is not valid supported TOML') from None
    for section, values in doc.items():
        if section not in CONFIG_ALLOW or not isinstance(values, dict):
            raise Unknown('Cargo configuration contains an unqualified section')
        for key, value in values.items():
            check = CONFIG_ALLOW[section].get(key)
            if check is None or not check(value):
                raise Unknown('Cargo configuration contains an unqualified key/value')
    return doc


def cargo_inputs(inventory, repo, home=None):
    """Allowlisted config plus lock-checksummed crate archive/source metadata."""
    repo = Path(repo).absolute()
    home = Path(home if home is not None else os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))).absolute()
    inventory.protected(home)
    if home.is_symlink() or not home.is_dir():
        raise Unknown('Cargo home is not a protected directory')
    known_home = {'bin', 'registry', 'config', 'config.toml', 'credentials', 'credentials.toml', 'git', '.package-cache', '.package-cache-mutate'}
    if any(p.name not in known_home for p in home.iterdir()):
        raise Unknown('Cargo home has unqualified mutable metadata')
    target = os.environ.get('CARGO_TARGET_DIR')
    if target and Path(target).exists() and any(Path(target).iterdir()):
        raise Unknown('existing Cargo compiled target requires separate qualification')
    if (repo / 'target').exists() and any((repo / 'target').iterdir()):
        raise Unknown('existing workspace compiled target requires separate qualification')
    seen = set()
    config_rows = []
    # Cargo discovers from actual FULL cwd through every ancestor, plus home.
    cwd = repo / 'crates/disk-personal'
    for folder in (cwd, *cwd.parents):
        seen.add(folder / '.cargo')
    seen.add(home)
    for folder in sorted(seen):
        for name in ('config', 'config.toml'):
            p = folder / name
            if p.exists() or p.is_symlink():
                raw = inventory.read(p)
                cargo_config(raw)  # Validate BEFORE storing any digest.
                inventory.capture(p, raw)
                config_rows.append({'path': str(p), 'present': True})
            else:
                config_rows.append({'path': str(p), 'present': False})
    for p in (home / 'credentials', home / 'credentials.toml'):
        if p.exists() or p.is_symlink():
            # Never read/hash credentials or serialize their values.
            raise Unknown('Cargo credential reference is present but unqualified')
    if (home / 'git').exists() and any((home / 'git').iterdir()):
        raise Unknown('Cargo git cache requires separate qualification')
    registry = home / 'registry'
    packages = {}
    for lock in (repo / 'Cargo.lock', repo / 'fuzz/Cargo.lock'):
        try:
            doc = tomllib.loads(lock.read_text())
        except (OSError, ValueError):
            raise Unknown('tracked Cargo lock input unavailable') from None
        for package in doc.get('package', []):
            source = package.get('source')
            if source is None:
                continue  # Workspace package bytes belong to full Git closure.
            if source != 'registry+https://github.com/rust-lang/crates.io-index':
                raise Unknown('non-default Cargo package source requires qualification')
            name, version, digest = package['name'], package['version'], package.get('checksum', '')
            if not re.fullmatch(r'[A-Za-z0-9_-]+', name) or not re.fullmatch(r'[A-Za-z0-9.+_-]+', version) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                raise Unknown('Cargo package identity/checksum malformed')
            key = name + '-' + version
            if key in packages and packages[key]['checksum'] != digest:
                raise Unknown('Cargo lock package checksum conflict')
            packages[key] = {'name': name, 'version': version, 'checksum': digest}
    if len(packages) > 128:
        raise Unknown('Cargo package inventory budget exceeded')
    if packages:
        indexes = list((registry / 'index').iterdir()) if (registry / 'index').is_dir() else []
        if len(indexes) != 1 or not re.fullmatch(r'index\.crates\.io-[0-9a-f]+', indexes[0].name):
            raise Unknown('Cargo sparse registry identity absent or ambiguous')
        index = indexes[0]
        config = index / 'config.json'
        raw = inventory.read(config)
        try:
            registry_config = json.loads(raw)
        except ValueError:
            raise Unknown('Cargo index configuration malformed') from None
        if registry_config != {'dl': 'https://static.crates.io/crates', 'api': 'https://crates.io'}:
            raise Unknown('Cargo registry endpoints require qualification')
        inventory.capture(config, raw)
        for key, package in sorted(packages.items()):
            name = package['name'].lower()
            shard = ('1/' + name if len(name) == 1 else '2/' + name if len(name) == 2 else
                     '3/' + name[0] + '/' + name if len(name) == 3 else name[:2] + '/' + name[2:4] + '/' + name)
            cached_index = index / '.cache' / shard
            cached_raw = inventory.read(cached_index)
            qualify_sparse_index(cached_raw, package['name'])
            inventory.capture(cached_index, cached_raw)
            archive = registry / 'cache' / index.name / (key + '.crate')
            raw = inventory.read(archive)
            if hashlib.sha256(raw).hexdigest() != package['checksum']:
                raise Unknown('Cargo archive differs from tracked lock checksum')
            inventory.capture(archive, raw)
            source = registry / 'src' / index.name / key
            inventory.protected(source)
            archived = set()
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
                member_count = 0
                for member in tar:
                    member_count += 1
                    if member_count > MAX_FILES or time.monotonic() > inventory.deadline:
                        raise Unknown('Cargo archive inventory budget exceeded')
                    path = Path(member.name)
                    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != key:
                        raise Unknown('Cargo archive member escapes package identity')
                    if member.isdir():
                        continue
                    if not member.isfile() or member.size > MAX_FILE or len(archived) >= MAX_FILES:
                        raise Unknown('Cargo archive member type/size unsupported')
                    relative = Path(*path.parts[1:])
                    if relative in archived or not relative.parts:
                        raise Unknown('Cargo archive member is duplicate/ambiguous')
                    if re.search(r'credentials|secret|private[-_]?key|\.env(?:\.|$)', str(relative), re.I) or relative.suffix in {'.pem', '.key', '.p12'}:
                        raise Unknown('Cargo source member may contain protected material')
                    if inventory.bytes + member.size > MAX_BYTES:
                        raise Unknown('Cargo source byte budget exceeded')
                    payload = tar.extractfile(member).read(MAX_FILE + 1)
                    local = inventory.capture(source / relative)
                    if len(payload) != member.size or payload != local:
                        raise Unknown('Cargo extracted source differs from lock-bound archive')
                    archived.add(relative)
            for path in inventory.tree(source):
                relative = path.relative_to(source)
                if relative not in archived:
                    if str(relative) not in {'.cargo-ok', '.cargo-checksum.json'}:
                        raise Unknown('Cargo source has an unaccounted extra file')
                    metadata = inventory.read(path)
                    try:
                        doc = json.loads(metadata)
                    except ValueError:
                        raise Unknown('Cargo generated package metadata malformed') from None
                    if str(relative) == '.cargo-ok':
                        if doc != {'v': 1}:
                            raise Unknown('Cargo completion marker requires qualification')
                    elif (not isinstance(doc, dict) or set(doc) != {'package', 'files'}
                          or doc['package'] != package['checksum'] or not isinstance(doc['files'], dict)
                          or set(doc['files']) != {p.as_posix() for p in archived}
                          or any(not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{64}', v) for v in doc['files'].values())
                          or any(inventory.files[str(source / p)]['sha256'] != digest for p, digest in doc['files'].items())):
                        raise Unknown('Cargo source checksum metadata differs from archived inputs')
                    inventory.capture(path, metadata)
    elif registry.exists() and any(registry.iterdir()):
        raise Unknown('Cargo registry without declared locked inputs')
    return {'complete': True, 'config_presence': config_rows,
            'locked_packages': packages, 'credentials_read': False}


def qualify_sparse_index(raw, name):
    # Cargo cache v3: version byte, little-endian index format, etag, then
    # NUL-separated version/JSON pairs. Unsupported format remains unknown.
    if len(raw) < 6 or raw[:5] != b'\x03\x02\x00\x00\x00':
        raise Unknown('Cargo sparse cache format requires qualification')
    parts = raw[5:].split(b'\0')
    if not parts or not re.fullmatch(rb'etag: [A-Za-z0-9"/._ -]{1,256}', parts[0]):
        raise Unknown('Cargo sparse cache header malformed')
    rows = parts[1:]
    if not rows or rows[-1] != b'' or len(rows[:-1]) % 2:
        raise Unknown('Cargo sparse cache entries malformed')
    keys = {'name', 'vers', 'deps', 'cksum', 'features', 'yanked', 'links', 'rust_version', 'features2', 'v', 'pubtime'}
    depkeys = {'name', 'req', 'features', 'optional', 'default_features', 'target', 'kind', 'registry', 'package', 'public'}
    for version, encoded in zip(rows[0:-1:2], rows[1:-1:2]):
        try:
            doc = json.loads(encoded)
        except ValueError:
            raise Unknown('Cargo sparse cache JSON malformed') from None
        if not isinstance(doc, dict) or set(doc) - keys or doc.get('name') != name or doc.get('vers', '').encode() != version:
            raise Unknown('Cargo sparse cache package metadata unqualified')
        if not re.fullmatch(r'[0-9a-f]{64}', doc.get('cksum', '')):
            raise Unknown('Cargo sparse cache checksum malformed')
        if not isinstance(doc.get('deps'), list):
            raise Unknown('Cargo sparse cache dependency metadata malformed')
        for dep in doc['deps']:
            if not isinstance(dep, dict) or set(dep) - depkeys or dep.get('registry') not in (None, 'https://github.com/rust-lang/crates.io-index'):
                raise Unknown('Cargo sparse cache dependency source unqualified')


def rust_inputs(inventory, tools):
    compiler = tools.get('rustc', {}).get('path')
    if not compiler:
        raise Unknown('actual Rust compiler identity unavailable')
    root = Path(compiler).parent.parent / 'lib/rustlib'
    if not root.is_dir():
        raise Unknown('actual Rust standard library reference unavailable')
    for path in inventory.tree(root):
        if path.suffix not in {'.rlib', '.rmeta', '.so', '.a', '.o', '.txt', '.toml'} and not path.name.startswith(('manifest-', 'components', 'rust-installer-version', 'install.log')):
            raise Unknown('Rust standard library file type requires qualification')
        inventory.capture(path)
    rustup_home = Path(os.environ.get('RUSTUP_HOME', str(Path.home() / '.rustup')))
    settings = rustup_home / 'settings.toml'
    if settings.exists() or settings.is_symlink():
        raw = inventory.read(settings)
        try:
            doc = tomllib.loads(raw.decode())
        except (ValueError, UnicodeError):
            raise Unknown('Rustup settings malformed') from None
        if (set(doc) - {'version', 'default_toolchain', 'profile', 'auto_self_update', 'overrides'}
                or doc.get('version') != '12' or doc.get('overrides', {}) != {}
                or doc.get('profile', 'minimal') not in ('minimal', 'default', 'complete')
                or doc.get('auto_self_update', 'disable') not in ('disable', 'enable', 'check-only')
                or not re.fullmatch(r'1\.97\.1(?:-x86_64-unknown-linux-gnu|-aarch64-unknown-linux-gnu)?', doc.get('default_toolchain', ''))):
            raise Unknown('Rustup settings require separate qualification')
        inventory.capture(settings, raw)
    return {'complete': True, 'stdlib_root': str(root), 'settings_present': settings.exists()}


def qualify_external(repo, tools=None):
    inventory = Inventory()
    result = {'schema': 'PersonalExternalInputs/v1', 'complete': False,
              'python': {'complete': False}, 'cargo': {'complete': False}, 'rust': {'complete': False}, 'unknown': []}
    for label, fn in (('python', lambda: python_inputs(inventory)),
                      ('cargo', lambda: cargo_inputs(inventory, repo)),
                      ('rust', lambda: rust_inputs(inventory, tools or {}))):
        try:
            result[label] = fn()
        except (Unknown, OSError, ValueError, TypeError, AttributeError, KeyError, tarfile.TarError):
            # Do not expose TOML, filesystem, hook or credential values in errors.
            # Known fixed codes only, never str(exception) for generic failures.
            exc = sys.exc_info()[1]
            result['unknown'].append(label + ': ' + (str(exc) if type(exc) is Unknown else 'input unavailable/malformed'))
    result.update(complete=not result['unknown'] and all(result[k].get('complete') is True for k in ('python', 'cargo', 'rust')), files=inventory.files,
                  captured_bytes=inventory.bytes, max_files=MAX_FILES, max_bytes=MAX_BYTES,
                  capture_seconds=45)
    return result

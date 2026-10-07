"""Causal offline inputs; no real runner configuration, tools or suite execution."""
import hashlib
import importlib.util
import io
import json
import os
import stat
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('external_inputs', ROOT / 'scripts/ci_personal_inputs.py')
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


class ExternalControls(unittest.TestCase):
    def setUp(self):
        # Fixtures model a conventional uid0 filesystem root. The actual host
        # root is NOT thereby qualified or granted: all other lstat data is real.
        original = Path.lstat
        def root_metadata(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if str(path) == '/':
                values = list(result)
                values[4] = 0
                return os.stat_result(values)
            return result
        self.root_patch = patch.object(inputs.Path, 'lstat', root_metadata)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_foreign_root_ownership_is_refused(self):
        original = Path.lstat
        def foreign_root(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if str(path) == '/':
                values = list(result)
                values[4] = os.getuid() + 999
                return os.stat_result(values)
            return result
        with tempfile.TemporaryDirectory() as t, patch.object(inputs.Path, 'lstat', foreign_root):
            with self.assertRaisesRegex(inputs.Unknown, 'writable by another identity'):
                inputs.Inventory().protected(Path(t))

    def fixture(self, root):
        repo, home, python = root / 'repo', root / 'cargo', root / 'python'
        (repo / 'crates/disk-personal').mkdir(parents=True)
        (repo / 'fuzz').mkdir()
        home.mkdir()
        python.mkdir()
        (python / 'module.py').write_text('VALUE = 1\n')
        for p in (repo / 'Cargo.lock', repo / 'fuzz/Cargo.lock'):
            p.write_text('version = 4\n')
        return repo, home, python

    def test_actual_allowlisted_cargo_and_python_can_qualify(self):
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ, {}, clear=True):
            repo, home, python = self.fixture(Path(t))
            (home / 'config.toml').write_text('[build]\njobs=2\n[net]\noffline=true\n')
            capture = inputs.Inventory()
            self.assertTrue(inputs.cargo_inputs(capture, repo, home)['complete'])
            self.assertTrue(inputs.python_inputs(capture, [python], {python})['complete'])
            encoded = json.dumps(capture.files)
            self.assertNotIn('VALUE =', encoded)
            self.assertEqual(capture.files[str(python / 'module.py')]['sha256'], hashlib.sha256(b'VALUE = 1\n').hexdigest())

    def test_unknown_cargo_config_is_not_digested_or_disclosed(self):
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ, {}, clear=True):
            repo, home, _ = self.fixture(Path(t))
            p = home / 'config.toml'
            p.write_text('[env]\nTOKEN="secret-fixture"\n')
            capture = inputs.Inventory()
            with self.assertRaises(inputs.Unknown) as error:
                inputs.cargo_inputs(capture, repo, home)
            self.assertNotIn('secret-fixture', str(error.exception))
            self.assertNotIn(str(p), capture.files)

    def test_credentials_are_never_read(self):
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ, {}, clear=True):
            repo, home, _ = self.fixture(Path(t))
            credentials = home / 'credentials.toml'
            credentials.write_text('secret-fixture')
            capture = inputs.Inventory()
            original = capture.read
            def read(p):
                self.assertNotEqual(Path(p), credentials)
                return original(p)
            with patch.object(capture, 'read', side_effect=read), self.assertRaisesRegex(inputs.Unknown, 'credential reference'):
                inputs.cargo_inputs(capture, repo, home)
            self.assertNotIn(str(credentials), capture.files)

    def test_cargo_config_ancestors_are_captured_and_changes_differ(self):
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ, {}, clear=True):
            repo, home, _ = self.fixture(Path(t))
            p = repo / 'crates/.cargo/config'
            p.parent.mkdir()
            p.write_text('[build]\njobs=1\n')
            first = inputs.Inventory()
            inputs.cargo_inputs(first, repo, home)
            p.write_text('[build]\njobs=2\n')
            second = inputs.Inventory()
            inputs.cargo_inputs(second, repo, home)
            self.assertNotEqual(first.files[str(p)], second.files[str(p)])

    def test_python_hook_search_override_and_secret_file_refuse(self):
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ, {}, clear=True):
            _, _, python = self.fixture(Path(t))
            for name in ('startup.pth', 'sitecustomize.py', 'secret.py', 'key.pem'):
                p = python / name
                p.write_text('secret-fixture')
                with self.subTest(name=name), self.assertRaises(inputs.Unknown):
                    inputs.python_inputs(inputs.Inventory(), [python], {python})
                p.unlink()
            with self.assertRaisesRegex(inputs.Unknown, 'search root'):
                inputs.python_inputs(inputs.Inventory(), [Path(t)], {python})
            with patch.dict(os.environ, {'PYTHONPATH': 'secret-fixture'}), self.assertRaisesRegex(inputs.Unknown, 'startup environment'):
                inputs.python_inputs(inputs.Inventory(), [python], {python})

    def test_symlink_writable_and_size_bound_refuse(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            real = root / 'module.py'
            real.write_text('code')
            link = root / 'alias.py'
            link.symlink_to(real)
            with self.assertRaisesRegex(inputs.Unknown, 'symlink'):
                inputs.Inventory().capture(link)
            real.chmod(0o666)
            with self.assertRaisesRegex(inputs.Unknown, 'writable'):
                inputs.Inventory().capture(real)
            real.chmod(0o600)
            with patch.object(inputs, 'MAX_FILE', 2), self.assertRaisesRegex(inputs.Unknown, 'bounded'):
                inputs.Inventory().capture(real)

    def test_unknown_mutable_cargo_home_or_target_refuses(self):
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ, {}, clear=True):
            repo, home, _ = self.fixture(Path(t))
            (home / 'unreviewed.db').write_text('unknown')
            with self.assertRaisesRegex(inputs.Unknown, 'mutable metadata'):
                inputs.cargo_inputs(inputs.Inventory(), repo, home)
            (home / 'unreviewed.db').unlink()
            (repo / 'target').mkdir()
            (repo / 'target/executable').write_text('not-executed')
            with self.assertRaisesRegex(inputs.Unknown, 'compiled target'):
                inputs.cargo_inputs(inputs.Inventory(), repo, home)

    def registry(self, root):
        repo, home, _ = self.fixture(root)
        name, version = 'fixture', '1.0.0'
        key, registry = name + '-' + version, home / 'registry'
        index_name = 'index.crates.io-123abc'
        source = registry / 'src' / index_name / key
        source.mkdir(parents=True)
        (source / 'lib.rs').write_bytes(b'pub fn actual_fixture() {}\n')
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as tar:
            payload = (source / 'lib.rs').read_bytes()
            member = tarfile.TarInfo(key + '/lib.rs')
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
        archive = registry / 'cache' / index_name / (key + '.crate')
        archive.parent.mkdir(parents=True)
        archive.write_bytes(out.getvalue())
        digest = hashlib.sha256(out.getvalue()).hexdigest()
        index = registry / 'index' / index_name
        (index / '.cache/fi/xt').mkdir(parents=True)
        (index / 'config.json').write_text(json.dumps({'dl': 'https://static.crates.io/crates', 'api': 'https://crates.io'}))
        doc = {'name': name, 'vers': version, 'deps': [], 'cksum': digest, 'features': {}, 'yanked': False}
        (index / '.cache/fi/xt/fixture').write_bytes(b'\x03\x02\x00\x00\x00etag: "fixture"\x00' + version.encode() + b'\x00' + json.dumps(doc).encode() + b'\x00')
        (repo / 'Cargo.lock').write_text('version=4\n[[package]]\nname="fixture"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + digest + '"\n')
        return repo, home, source, archive, index

    def test_real_lock_checksum_archive_and_extracted_source_qualify(self):
        with tempfile.TemporaryDirectory() as t, patch.dict(os.environ, {}, clear=True):
            repo, home, source, _, _ = self.registry(Path(t))
            capture = inputs.Inventory()
            result = inputs.cargo_inputs(capture, repo, home)
            self.assertTrue(result['complete'])
            self.assertIn(str(source / 'lib.rs'), capture.files)
            self.assertFalse(result['credentials_read'])

    def test_changed_cache_source_archive_index_and_extra_refuse(self):
        for kind in ('source', 'archive', 'index', 'extra'):
            with tempfile.TemporaryDirectory() as t, patch.dict(os.environ, {}, clear=True):
                repo, home, source, archive, index = self.registry(Path(t))
                if kind == 'source': (source / 'lib.rs').write_text('edited')
                if kind == 'archive': archive.write_bytes(b'edited')
                if kind == 'index': (index / 'config.json').write_text('{"dl":"https://secret-fixture@example.invalid"}')
                if kind == 'extra': (source / 'unaccounted.rs').write_text('edited')
                with self.subTest(kind=kind), self.assertRaises(inputs.Unknown):
                    inputs.cargo_inputs(inputs.Inventory(), repo, home)

    def test_rust_stdlib_is_measured_and_settings_refuse_unknown(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            compiler = root / 'toolchain/bin/rustc'
            compiler.parent.mkdir(parents=True)
            compiler.write_text('not-executed')
            lib = root / 'toolchain/lib/rustlib/target/lib/std.rlib'
            lib.parent.mkdir(parents=True)
            lib.write_bytes(b'fixture-library')
            rustup = root / 'rustup'
            rustup.mkdir()
            settings = rustup / 'settings.toml'
            settings.write_text('version="12"\ndefault_toolchain="1.97.1-x86_64-unknown-linux-gnu"\n[overrides]\n')
            with patch.dict(os.environ, {'RUSTUP_HOME': str(rustup)}, clear=True):
                capture = inputs.Inventory()
                self.assertTrue(inputs.rust_inputs(capture, {'rustc': {'path': str(compiler)}})['complete'])
                self.assertIn(str(lib), capture.files)
                settings.write_text('[env]\nTOKEN="secret-fixture"\n')
                with self.assertRaises(inputs.Unknown):
                    inputs.rust_inputs(inputs.Inventory(), {'rustc': {'path': str(compiler)}})

    def test_component_unknown_never_becomes_complete_or_leaks_value(self):
        with patch.object(inputs, 'python_inputs', side_effect=ValueError('secret-fixture')), \
             patch.object(inputs, 'cargo_inputs', return_value={'complete': True}), \
             patch.object(inputs, 'rust_inputs', return_value={'complete': True}):
            result = inputs.qualify_external(ROOT, {})
        self.assertFalse(result['complete'])
        self.assertNotIn('secret-fixture', json.dumps(result))


if __name__ == '__main__':
    unittest.main()

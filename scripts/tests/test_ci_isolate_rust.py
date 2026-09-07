#!/usr/bin/env python3
"""Offline fixtures: no network, toolchain installation or runner-wide writes."""
import importlib.util
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('isolation', Path(__file__).parents[1] / 'ci-isolate-rust.py')
isolation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(isolation)


class IsolationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / 'home'
        self.bin = self.home / '.cargo/bin'
        self.bin.mkdir(parents=True)
        self.executable = self.bin / 'rustup'
        self.executable.write_text('#!/bin/sh\nexit 0\n')
        self.executable.chmod(0o700)
        self.environment = {'RUNNER_TEMP': str(self.root), 'GITHUB_ENV': str(self.root / 'env'),
                            'GITHUB_PATH': str(self.root / 'path'), 'PATH': str(self.bin), 'HOME': str(self.home)}
        self.env_patch = patch.dict(os.environ, self.environment, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def prepare(self):
        isolation.prepare()
        return dict(line.split('=', 1) for line in (self.root / 'env').read_text().splitlines())

    def test_prepare_copies_proxies_and_preserves_home(self):
        values = self.prepare()
        cargo = Path(values['CARGO_HOME'])
        self.assertEqual(os.environ['HOME'], str(self.home))
        self.assertNotIn('HOME', values)
        self.assertEqual((self.root / 'path').read_text(), str(cargo / 'bin') + '\n')
        self.assertEqual((cargo / 'bin/rustup').read_bytes(), self.executable.read_bytes())
        self.assertNotEqual((cargo / 'bin/rustup').stat().st_ino, self.executable.stat().st_ino)
        for name in isolation.PROXIES:
            self.assertEqual((cargo / 'bin' / name).resolve(), cargo / 'bin/rustup')
        self.assertEqual(cargo.stat().st_mode & 0o777, 0o700)

    def test_missing_path_uses_protected_standard_rustup(self):
        os.environ['PATH'] = ''
        self.prepare()

    def test_no_existing_rustup_uses_pinned_fallback(self):
        self.executable.unlink()
        with patch.object(isolation, 'bootstrap', side_effect=ValueError('fallback reached')) as fallback:
            with self.assertRaisesRegex(ValueError, 'fallback reached'):
                self.prepare()
            self.assertEqual(fallback.call_count, 1)

    def test_world_writable_existing_rustup_is_rejected_before_fallback(self):
        self.executable.chmod(0o777)
        with patch.object(isolation, 'bootstrap', side_effect=ValueError('fallback reached')):
            with self.assertRaisesRegex(ValueError, 'fallback reached'):
                self.prepare()
        for root in self.root.glob('disk-rust.*'):
            self.assertFalse((root / 'cargo/bin/rustup').exists())

    def test_each_prepare_uses_unique_homes(self):
        first = self.prepare()
        second = self.prepare()
        self.assertNotEqual(first['CARGO_HOME'], second['CARGO_HOME'])
        self.assertNotEqual(first['RUSTUP_HOME'], second['RUSTUP_HOME'])

    def fixture_installed(self):
        values = self.prepare()
        os.environ.update(values)
        os.environ['PATH'] = str(Path(values['CARGO_HOME']) / 'bin')
        toolchain = Path(values['RUSTUP_HOME']) / 'toolchains/synthetic/bin'
        toolchain.mkdir(parents=True)
        for name in ('cargo', 'rustc'):
            (toolchain / name).write_text('synthetic fixture')
        def output(args, **_kwargs):
            if args[1:] == ['show', 'home']:
                return values['RUSTUP_HOME'] + '\n'
            self.assertEqual(args[1:4], ['which', '--toolchain', '1.97.1'])
            return str(toolchain / args[-1]) + '\n'
        return values, output

    def test_verify_isolated_proxies_and_toolchains(self):
        _, output = self.fixture_installed()
        with patch.object(isolation.subprocess, 'check_output', side_effect=output), patch.object(isolation.subprocess, 'run') as run:
            isolation.verify('1.97.1')
            self.assertEqual(run.call_count, 2)

    def test_verify_rejects_shared_proxy(self):
        self.fixture_installed()
        os.environ['PATH'] = str(self.bin) + ':' + os.environ['PATH']
        with self.assertRaisesRegex(ValueError, 'outside isolated proxy'):
            isolation.verify('1.97.1')

    def test_verify_rejects_shared_home(self):
        self.fixture_installed()
        os.environ['CARGO_INSTALL_ROOT'] = str(self.home)
        with self.assertRaisesRegex(ValueError, 'escaped isolated state'):
            isolation.verify('1.97.1')

    def test_verify_rejects_toolchain_escape(self):
        values, _ = self.fixture_installed()
        with patch.object(isolation.subprocess, 'check_output', side_effect=[values['RUSTUP_HOME'], str(self.executable)]):
            with self.assertRaisesRegex(ValueError, 'toolchain escaped'):
                isolation.verify('1.97.1')

    def test_verify_rejects_rustup_home_disagreement(self):
        self.fixture_installed()
        with patch.object(isolation.subprocess, 'check_output', return_value=str(self.home)):
            with self.assertRaisesRegex(ValueError, 'different home'):
                isolation.verify('1.97.1')

    def bootstrap_env(self):
        root = self.root / 'bootstrap'
        root.mkdir(mode=0o700)
        env = dict(os.environ, CARGO_HOME=str(root / 'cargo'), RUSTUP_HOME=str(root / 'rustup'))
        return root, env

    def test_bootstrap_rejects_unsupported_host_before_download(self):
        root, env = self.bootstrap_env()
        with patch.object(isolation.platform, 'system', return_value='Darwin'), patch.object(isolation.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'only Linux x86_64'):
                isolation.bootstrap(root, env)
            run.assert_not_called()

    def test_bootstrap_digest_mismatch_never_executes_installer(self):
        root, env = self.bootstrap_env()
        def download(_args, **_kwargs):
            (root / 'rustup-init').write_bytes(b'untrusted bytes')
        with patch.object(isolation.platform, 'system', return_value='Linux'), patch.object(isolation.platform, 'machine', return_value='x86_64'), patch.object(isolation.subprocess, 'run', side_effect=download) as run:
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                isolation.bootstrap(root, env)
            self.assertEqual(run.call_count, 1)
            self.assertEqual((root / 'rustup-init').stat().st_mode & 0o111, 0)

    def test_bootstrap_verified_bytes_exact_flags_and_owned_destinations(self):
        root, env = self.bootstrap_env()
        payload = b'fixture bytes, never executed'
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            self.assertEqual(kwargs['env']['HOME'], str(self.home))
            self.assertEqual(kwargs['cwd'], root)
            self.assertTrue(Path(kwargs['env']['CARGO_HOME']).is_relative_to(root))
            self.assertTrue(Path(kwargs['env']['RUSTUP_HOME']).is_relative_to(root))
            self.assertTrue(kwargs['check'])
            self.assertLessEqual(kwargs['timeout'], 150)
            if args[0] == 'curl':
                self.assertEqual(args[1], '--disable')
                self.assertEqual(args[-1], isolation.RUSTUP_INIT_URL)
                self.assertIn('--max-filesize', args)
                (root / 'rustup-init').write_bytes(payload)
            else:
                self.assertEqual(args, [str(root / 'rustup-init'), '--no-modify-path', '--default-toolchain', 'none', '--profile', 'minimal', '-y'])
                binary = Path(env['CARGO_HOME']) / 'bin/rustup'
                binary.parent.mkdir(parents=True)
                binary.write_bytes(payload)
                binary.chmod(0o700)
        with patch.object(isolation.platform, 'system', return_value='Linux'), patch.object(isolation.platform, 'machine', return_value='x86_64'), patch.object(isolation, 'RUSTUP_INIT_SHA256', hashlib.sha256(payload).hexdigest()), patch.object(isolation.subprocess, 'run', side_effect=command):
            isolation.bootstrap(root, env)
        self.assertEqual(len(calls), 2)


if __name__ == '__main__':
    unittest.main()

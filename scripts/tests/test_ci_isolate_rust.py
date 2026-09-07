#!/usr/bin/env python3
"""Offline fixtures: no network, toolchain installation or runner-wide writes."""
import importlib.util
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

    def test_no_existing_rustup_fails_without_creating_state(self):
        self.executable.unlink()
        with self.assertRaisesRegex(ValueError, 'no installer fallback'):
            self.prepare()
        self.assertEqual(list(self.root.glob('disk-rust.*')), [])

    def test_world_writable_existing_rustup_is_rejected(self):
        self.executable.chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'no installer fallback'):
            self.prepare()

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


if __name__ == '__main__':
    unittest.main()

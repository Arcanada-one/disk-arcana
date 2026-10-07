"""Synthetic ELF boundary fixtures; no real c39 binary or product proof."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('exporter', Path(__file__).parents[1] / 'ci-export-linux-server.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExportBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.binary = self.root / 'synthetic-elf'
        data = bytearray(64)
        data[:6] = b'\x7fELF\x02\x01'
        data[16:18] = (2).to_bytes(2, 'little')
        data[18:20] = (62).to_bytes(2, 'little')
        self.binary.write_bytes(data)
        self.binary.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def export(self):
        return module.export_binary(self.binary, self.root, 'x86_64-unknown-linux-gnu', {'fixture_only': True})

    def test_private_export_digest_matches_exact_bytes(self):
        out = self.export()
        manifest = json.loads((out / 'BUILD.json').read_text())
        self.assertEqual(manifest['binary_sha256'], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertTrue(manifest['fixture_only'])
        self.assertEqual((out / 'disk-arcana-server').stat().st_mode & 0o777, 0o700)

    def test_missing_binary_refuses(self):
        self.binary.unlink()
        with self.assertRaises(FileNotFoundError): self.export()

    def test_symlink_binary_refuses(self):
        original = self.root / 'original'
        self.binary.rename(original)
        self.binary.symlink_to(original)
        with self.assertRaisesRegex(ValueError, 'indirect_or_invalid_export_path'): self.export()

    def test_windows_or_wrong_arch_refuses_without_output(self):
        self.binary.write_bytes(b'MZ' + bytes(62))
        with self.assertRaises(ValueError): self.export()
        self.assertEqual(list(self.root.glob('server-export.*')), [])

    def test_shared_stage_refuses(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError): self.export()

    def test_hardlinked_binary_refuses(self):
        os.link(self.binary, self.root / 'second-link')
        with self.assertRaises(ValueError): self.export()

    def cargo_alias(self):
        release = self.root / 'release'
        (release / 'deps').mkdir(parents=True)
        self.binary.rename(release / 'disk-arcana-server')
        self.binary = release / 'disk-arcana-server'
        os.link(self.binary, release / 'deps/disk_arcana_server-fixture')

    def test_actual_cargo_link_layout_exports_single_link_copy(self):
        self.cargo_alias()
        out = self.export()
        self.assertEqual((out / 'disk-arcana-server').stat().st_nlink, 1)
        self.assertEqual(self.binary.stat().st_nlink, 2)

    def test_cargo_layout_with_foreign_third_link_refuses(self):
        self.cargo_alias()
        os.link(self.binary, self.root / 'extra')
        with self.assertRaises(ValueError): self.export()

    def test_elf_wrong_machine_refuses(self):
        with self.binary.open('r+b') as out:
            out.seek(18)
            out.write((183).to_bytes(2, 'little'))
        with self.assertRaisesRegex(ValueError, 'not_matching_linux_elf'): self.export()

    def test_parent_symlink_refuses(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.binary = alias / self.binary.name
        with self.assertRaises(ValueError): self.export()

    def test_failed_manifest_write_rolls_back_only_new_output(self):
        with patch.object(Path, 'write_text', side_effect=OSError('fixture write refusal')):
            with self.assertRaises(OSError): self.export()
        self.assertEqual(list(self.root.glob('server-export.*')), [])
        self.assertTrue(self.binary.exists())


class SourceBinding(unittest.TestCase):
    def setUp(self):
        ExportBoundaries.setUp(self)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.workspace), *args], text=True).strip()
        self.git = git
        git('init', '-q')
        (self.workspace / 'source.txt').write_text('owned fixture\n')
        git('add', 'source.txt')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        target = self.workspace / 'target/x86_64-unknown-linux-gnu/release'
        target.mkdir(parents=True)
        self.binary.rename(target / 'disk-arcana-server')
        self.binary = target / 'disk-arcana-server'
        self.env = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
                    'GITHUB_WORKSPACE': str(self.workspace), 'EXPECTED_BUILD_SHA': git('rev-parse', 'HEAD'),
                    'CI_ISOLATED_RUST_ROOT': str(self.root), 'BUILD_TARGET': 'x86_64-unknown-linux-gnu',
                    'GITHUB_REPOSITORY': 'fixture/repo', 'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2',
                    'GITHUB_JOB': 'build', 'RUNNER_NAME': 'fixture-runner', 'GITHUB_OUTPUT': str(self.root / 'output')}

    def tearDown(self):
        self.temp.cleanup()

    def test_main_binds_actual_git_tree_and_run(self):
        with patch.dict(os.environ, self.env, clear=True): module.main()
        output = Path((self.root / 'output').read_text().strip().split('=', 1)[1])
        manifest = json.loads((output / 'BUILD.json').read_text())
        self.assertEqual(manifest['checkout_sha'], self.env['EXPECTED_BUILD_SHA'])
        self.assertEqual(manifest['checkout_tree'], self.git('rev-parse', 'HEAD^{tree}'))
        self.assertEqual(manifest['run_id'], '17')
        self.assertEqual(manifest['run_attempt'], '2')

    def test_main_refuses_wrong_source_without_export(self):
        self.env['EXPECTED_BUILD_SHA'] = '0' * 40
        with patch.dict(os.environ, self.env, clear=True):
            with self.assertRaisesRegex(ValueError, 'checkout_source_mismatch'): module.main()
        self.assertFalse((self.root / 'output').exists())

    def test_main_refuses_dirty_source(self):
        (self.workspace / 'source.txt').write_text('changed\n')
        with patch.dict(os.environ, self.env, clear=True):
            with self.assertRaises(subprocess.CalledProcessError): module.main()
        self.assertFalse((self.root / 'output').exists())

    def test_main_refuses_foreign_target(self):
        self.env['CARGO_TARGET_DIR'] = str(self.root)
        with patch.dict(os.environ, self.env, clear=True):
            with self.assertRaisesRegex(ValueError, 'foreign_target_root'): module.main()


class CliOutputs(unittest.TestCase):
    def setUp(self):
        ExportBoundaries.setUp(self)
        self.workspace = self.root / 'workspace'
        self.target = self.workspace / 'target'
        (self.target / 'debug/deps').mkdir(parents=True)
        self.rows = []
        for name, kind, source in [('disk', 'bin', 'src/main.rs'),
                                   ('it_local_e2e_writeback', 'test', 'tests/it_local_e2e_writeback.rs')]:
            src = self.workspace / 'crates/disk-cli' / source
            src.parent.mkdir(parents=True, exist_ok=True)
            src.write_text('// synthetic source')
            binary = self.target / 'debug' / ('disk' if name == 'disk' else 'deps/it_local_e2e_writeback-fixture')
            binary.write_bytes(self.binary.read_bytes())
            binary.chmod(0o700)
            self.rows.append({'reason': 'compiler-artifact', 'target': {'name': name, 'kind': [kind], 'src_path': str(src)},
                              'profile': {'test': name != 'disk'}, 'features': ['fixture'], 'executable': str(binary)})
        self.rows.append({'reason': 'build-finished', 'success': True})
        self.log = self.root / 'cargo.jsonl'

    def tearDown(self):
        self.temp.cleanup()

    def cli(self):
        self.log.write_text(''.join(json.dumps(row) + '\n' for row in self.rows))
        with patch.dict(os.environ, {'GITHUB_WORKSPACE': str(self.workspace)}):
            return module.export_cli(self.log, self.target, self.root, {'fixture_only': True})

    def test_both_outputs_have_exact_hashes_and_original_daemon_binding(self):
        outputs = self.cli()
        self.assertEqual(len(outputs), 2)
        for output, row in zip(outputs, self.rows):
            manifest = json.loads((output / 'BUILD.json').read_text())
            self.assertEqual(manifest['binary_sha256'], hashlib.sha256(Path(row['executable']).read_bytes()).hexdigest())
            self.assertEqual(manifest['original_daemon_path'], self.rows[0]['executable'])
            self.assertEqual(manifest['cargo_artifact'], row)

    def test_missing_daemon_refuses(self):
        self.rows.pop(0)
        with self.assertRaisesRegex(ValueError, 'missing_successful'): self.cli()

    def test_unsuccessful_cargo_refuses(self):
        self.rows[-1]['success'] = False
        with self.assertRaisesRegex(ValueError, 'missing_successful'): self.cli()

    def test_duplicate_driver_refuses(self):
        self.rows.insert(0, self.rows[1])
        with self.assertRaisesRegex(ValueError, 'ambiguous'): self.cli()

    def test_foreign_output_refuses(self):
        self.rows[1]['executable'] = str(self.binary)
        with self.assertRaisesRegex(ValueError, 'foreign_cargo_output'): self.cli()

    def test_foreign_source_refuses(self):
        self.rows[1]['target']['src_path'] = str(self.binary)
        with self.assertRaisesRegex(ValueError, 'ambiguous_or_foreign'): self.cli()

    def test_object_elf_refuses_and_rolls_back_pair(self):
        binary = Path(self.rows[1]['executable'])
        data = bytearray(binary.read_bytes()); data[16:18] = (1).to_bytes(2, 'little'); binary.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'not_matching_linux_elf'): self.cli()
        self.assertEqual(list(self.root.glob('server-export.*')), [])

    def test_daemon_cargo_two_link_copy(self):
        os.link(self.rows[0]['executable'], self.target / 'debug/deps/disk-fixture')
        for output in self.cli():
            manifest = json.loads((output / 'BUILD.json').read_text())
            self.assertEqual((output / manifest['binary']).stat().st_nlink, 1)


if __name__ == '__main__':
    unittest.main()

"""Negative controls for full-suite admission, with no provider or network IO."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'full-test-group.py'
SPEC = importlib.util.spec_from_file_location('full_test_group', PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FullTestGroups(unittest.TestCase):
    def test_unknown_group_cannot_execute(self):
        with patch.object(runner, 'run') as execute:
            self.assertEqual(runner.main(['disk-proto', 'cached.log']), 2)
            self.assertEqual(runner.main(['missing']), 2)
            execute.assert_not_called()

    def test_missing_executable_is_unmeasured(self):
        with patch.object(runner.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertRaises(runner.Unmeasured, runner.run, ['absent'])

    def test_raw_failure_is_not_overridden_by_pass_text(self):
        result = subprocess.CompletedProcess([], 1, '7 passed', 'failure')
        with patch.object(runner.subprocess, 'run', return_value=result):
            self.assertRaises(subprocess.CalledProcessError, runner.run, ['runner'], positive=True)

    def test_empty_or_partial_execution_is_not_full(self):
        for output in ('', '0 passed', '7 passed; 1 ignored'):
            with self.subTest(output=output), patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
                self.assertRaises(runner.Unmeasured, runner.run, ['runner'], positive=True)

    def test_complete_count_preserves_raw_output(self):
        with patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '7 passed; 0 ignored', '')):
            self.assertEqual(runner.run(['runner'], positive=True), '7 passed; 0 ignored')

    def test_storage_refuses_without_explicit_sandbox(self):
        with patch.dict(runner.os.environ, {}, clear=True), patch.object(runner, 'run') as execute:
            self.assertEqual(runner.main(['disk-storage']), 127)
            execute.assert_not_called()

    def test_storage_opt_in_and_credentials_do_not_establish_authority(self):
        # Synthetic values only; no cloud client or subprocess is invoked.
        environment = {'DISK_FULL_TEST_REMOTE_SANDBOX': 'authorized',
                       'DISK_B2_BUCKET': 'synthetic-bucket',
                       'DISK_B2_KEY_ID': 'synthetic-key',
                       'DISK_B2_APP_KEY': 'synthetic-secret',
                       'DISK_R2_ACCOUNT_ID': 'synthetic-account',
                       'DISK_R2_BUCKET': 'synthetic-bucket',
                       'DISK_R2_ACCESS_KEY_ID': 'synthetic-key',
                       'DISK_R2_SECRET_ACCESS_KEY': 'synthetic-secret'}
        for group in ('disk-storage', 'root'):
            with self.subTest(group=group), patch.dict(runner.os.environ, environment, clear=True), \
                    patch.object(runner, 'personal_preflight'), patch.object(runner, 'run') as execute:
                self.assertEqual(runner.main([group]), 127)
                execute.assert_not_called()

    def test_root_missing_preflight_cannot_run_partial_suite(self):
        with patch.object(runner, 'personal_preflight', side_effect=runner.Unmeasured('ENOSYS')), patch.object(runner, 'run') as execute:
            self.assertEqual(runner.main(['root']), 127)
            execute.assert_not_called()

    def test_crate_is_unfiltered_default_and_all_features_with_ignored(self):
        with patch.object(runner, 'run') as execute:
            runner.crate('disk-proto')
            commands = [c.args[0] for c in execute.call_args_list]
            self.assertEqual(len(commands), 2)
            self.assertIn('--no-default-features', commands[0])
            self.assertIn('--all-features', commands[1])
            for command in commands:
                self.assertEqual(command[-2:], ['--', '--include-ignored'])
                self.assertNotIn('--test', command)
                self.assertNotIn('--lib', command)

    def test_fuzz_stale_lock_stops_before_any_campaign(self):
        with patch.object(runner, 'run', side_effect=subprocess.CalledProcessError(101, ['cargo'])) as execute:
            self.assertEqual(runner.main(['fuzz']), 101)
            self.assertEqual(execute.call_count, 1)
            self.assertIn('--locked', execute.call_args.args[0])
            self.assertIn('metadata', execute.call_args.args[0])

    def test_real_unittest_zero_skipped_and_positive(self):
        for source, accepted in [('', False),
                ('@unittest.skip("fixture")\nclass Cases(unittest.TestCase):\n def test_one(self): pass\n', False),
                ('class Cases(unittest.TestCase):\n def test_one(self): pass\n', True)]:
            with self.subTest(accepted=accepted), tempfile.TemporaryDirectory() as directory:
                Path(directory, 'test_cases.py').write_text('import unittest\n' + source)
                command = [sys.executable, '-m', 'unittest', 'discover', '-s', directory]
                if accepted:
                    runner.run(command, suite='unittest')
                else:
                    self.assertRaises((runner.Unmeasured, subprocess.CalledProcessError), runner.run, command, suite='unittest')

    def test_unittest_zero_exit_does_not_accept_zero_or_skipped(self):
        for summary in ('Ran 0 tests in 0.001s\n\nOK\n',
                        'Ran 2 tests in 0.001s\n\nOK (skipped=2)\n',
                        'Ran 2 tests in 0.001s\n\nOK (skipped=1)\n'):
            with patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', summary)):
                self.assertRaises(runner.Unmeasured, runner.run, ['unittest'], suite='unittest')

    @staticmethod
    def report(cases):
        return {'success': True, 'numTotalTests': len(cases),
                'numPassedTests': sum(s == 'passed' for _, _, s in cases),
                'numPendingTests': sum(s in ('skipped', 'pending') for _, _, s in cases),
                'numTodoTests': sum(s == 'todo' for _, _, s in cases), 'numFailedTests': 0,
                'testResults': [{'name': str(runner.ROOT / 'plugins/obsidian' / path),
                                 'assertionResults': [{'fullName': name, 'status': status}]}
                                for path, name, status in cases]}

    def test_vitest_paired_exact_inventory(self):
        ordinary = self.report([('test/unit.test.ts', 'unit', 'passed'),
                                ('test/daemon-integration.test.ts', 'daemon', 'skipped')])
        paired = self.report([('test/daemon-integration.test.ts', 'daemon', 'passed')])
        plugin = runner.ROOT / 'plugins/obsidian'
        runner.check_plugin_pair(ordinary, paired, plugin)
        for bad in (self.report([('test/daemon-integration.test.ts', 'other', 'passed')]),
                    self.report([('test/daemon-integration.test.ts', 'daemon', 'skipped')])):
            self.assertRaises(runner.Unmeasured, runner.check_plugin_pair, ordinary, bad, plugin)

    def test_vitest_unaccounted_skipped_pending_todo_and_empty(self):
        plugin = runner.ROOT / 'plugins/obsidian'
        paired = self.report([('test/daemon-integration.test.ts', 'daemon', 'passed')])
        for status in ('skipped', 'pending', 'todo'):
            ordinary = self.report([('test/unit.test.ts', 'unit', 'passed'),
                                    ('test/other.test.ts', 'unaccounted', status)])
            self.assertRaises(runner.Unmeasured, runner.check_plugin_pair, ordinary, paired, plugin)
        self.assertRaises(runner.Unmeasured, runner.vitest_inventory, self.report([]), plugin)
        inconsistent = self.report([('test/unit.test.ts', 'unit', 'passed')])
        inconsistent['numPendingTests'] = 1
        self.assertRaises(runner.Unmeasured, runner.vitest_inventory, inconsistent, plugin)

    def test_child_lock_mutation_cannot_succeed_and_failure_stays_raw(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(runner, 'ROOT', Path(directory)):
            lock = Path(directory, 'Cargo.lock')
            def execute(*args, **kwargs):
                lock.write_bytes(b'changed')
                return subprocess.CompletedProcess([], result_code, '7 passed', '')
            for result_code, expected in ((0, runner.Unmeasured), (7, subprocess.CalledProcessError)):
                lock.write_bytes(b'original')
                with patch.object(runner, 'lock_state', return_value={'Cargo.lock': b'original'}), patch.object(runner.subprocess, 'run', side_effect=execute):
                    self.assertRaises(expected, runner.run, ['command'])

    def test_profile_declares_all_groups_and_real_runner(self):
        profile = json.loads((runner.ROOT / '.arcana/verify.json').read_text())
        groups = {k: v for k, v in profile['deployables'].items() if 'full_test' in v}
        self.assertEqual(set(groups), {'.', 'fuzz', *(f'crates/{n}' for n in runner.CRATES)})
        for group, declaration in groups.items():
            command = declaration['full_test']
            self.assertEqual(command[0], 'python3')
            self.assertEqual((runner.ROOT / group / command[1]).resolve(), PATH)
            self.assertIn(command[2], (*runner.CRATES, 'root', 'fuzz'))


if __name__ == '__main__':
    unittest.main()

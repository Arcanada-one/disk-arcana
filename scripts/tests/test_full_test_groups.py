"""Negative controls for full-suite admission, with no provider or network IO."""
import importlib.util
import json
from pathlib import Path
import subprocess
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

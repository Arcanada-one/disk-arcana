"""Exercise the canonical CLI's sole merge write and workflow custody."""
import contextlib
import importlib.util
import io
import os
import tempfile
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('gate', ROOT / 'dev-tools/gated-merge.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
HEAD = 'a' * 40


def answer():
    return {'repository': {'isPrivate': False,
        'defaultBranchRef': {'name': 'main', 'target': {'oid': 'b' * 40}},
        'workflows': {'entries': [{'name': 'ci.yml'}]},
        'pullRequest': {'number': 1, 'state': 'OPEN', 'isDraft': False,
            'baseRefName': 'main', 'headRefOid': HEAD,
            'mergeable': 'MERGEABLE', 'mergeStateStatus': 'CLEAN',
            'commits': {'nodes': [{'commit': {'oid': HEAD,
                'checkSuites': {'nodes': [{'app': {'slug': 'github-actions'},
                    'status': 'COMPLETED', 'conclusion': 'SUCCESS',
                    'checkRuns': {'nodes': [{'name': 'test', 'status': 'COMPLETED',
                        'conclusion': 'SUCCESS', 'startedAt': '2026-01-01T00:00:00Z',
                        'completedAt': '2026-01-01T00:01:00Z', 'databaseId': 1}]}}]}}}]}}}}


class Boundary(unittest.TestCase):
    def run_gate(self, data, rc=0, stdout='{"merged":true}', expect=HEAD, read_error=None):
        argv = ['gate', '--repo', 'example/project', '--pr', '1',
                '--method', 'squash', '--expect-sha', expect]
        result = subprocess.CompletedProcess([], rc, stdout, 'HTTP 409' if rc else '')
        with patch.object(sys, 'argv', argv), patch.object(gate, 'read_answer', return_value=data, side_effect=read_error), \
             patch.object(gate, 'read_compare', return_value={'behind_by': 0, 'missed': []}), \
             patch.object(gate, 'read_jobs', return_value={}), \
             patch.object(gate.subprocess, 'run', return_value=result) as write, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = gate.main()
        return code, write

    def test_green_has_one_exact_head_write(self):
        code, write = self.run_gate(answer())
        self.assertEqual(code, 0)
        self.assertEqual(write.call_count, 1)
        args = write.call_args.args[0]
        self.assertIn('PUT', args)
        self.assertIn('sha=' + HEAD, args)
        self.assertIn('merge_method=squash', args)

    def test_refusals_never_write(self):
        for case in ('red', 'pending', 'zero', 'stale', 'draft', 'base', 'closed'):
            with self.subTest(case=case):
                data = answer()
                pr = data['repository']['pullRequest']
                suites = pr['commits']['nodes'][0]['commit']['checkSuites']['nodes']
                check = suites[0]['checkRuns']['nodes'][0]
                if case == 'red': check['conclusion'] = 'FAILURE'
                if case == 'pending': check['status'] = 'IN_PROGRESS'
                if case == 'zero': suites.clear()
                if case == 'stale': pr['headRefOid'] = 'c' * 40
                if case == 'draft': pr['isDraft'] = True
                if case == 'base': pr['baseRefName'] = 'other'
                if case == 'closed': pr['state'] = 'CLOSED'
                code, write = self.run_gate(data)
                self.assertNotEqual(code, 0)
                write.assert_not_called()

    def test_head_race_or_api_nonmerge_stays_nonzero(self):
        for rc, body in ((1, ''), (0, '{"merged":false}')):
            with self.subTest(rc=rc):
                code, write = self.run_gate(answer(), rc, body)
                self.assertNotEqual(code, 0)
                self.assertEqual(write.call_count, 1)

    def test_api_read_failure_never_writes(self):
        code, write = self.run_gate(answer(), read_error=RuntimeError('unreadable'))
        self.assertEqual(code, 2)
        write.assert_not_called()

    def test_partial_sha_never_writes(self):
        code, write = self.run_gate(answer(), expect='abc')
        self.assertEqual(code, 2)
        write.assert_not_called()

    def test_actual_workflow_shell_propagates_gate_exit_and_guards_bundle(self):
        workflow = (ROOT / '.github/workflows/dependabot-auto-merge.yml').read_text()
        shell = workflow.split('        run: |', 1)[1].replace(
            '${{ github.event.repository.default_branch }}', 'main')
        for exit_code, changed_file in ((0, 'Cargo.lock'), (5, 'Cargo.lock'),
                (1, 'Cargo.lock'), (0, 'dev-tools/gated-merge.py')):
            with self.subTest(exit_code=exit_code, changed_file=changed_file), \
                 tempfile.TemporaryDirectory() as directory:
                d = Path(directory)
                # Absolute interpreter avoids PATH interception recursion.
                fake_gh = d / 'gh'
                fake_gh.write_text('#!' + sys.executable + '\n' +
                    'import json,sys\n' +
                    'endpoint=next(a for a in sys.argv[1:] if a.startswith("repos/"))\n' +
                    'if "/commits/" in endpoint: print("1")\n' +
                    'elif "/files" in endpoint: print(' + repr(changed_file) + ')\n' +
                    'else: print(json.dumps({"user":{"login":"dependabot[bot]"},'
                    '"title":"Bump example from 1.2.3 to 1.2.4",'
                    '"base":{"ref":"main"},"draft":False}))\n')
                fake_python = d / 'python3'
                fake_python.write_text('#!/bin/bash\nprintf "%s\\n" "$@" > "$RUNNER_TEMP/called"\nexit ' + str(exit_code) + '\n')
                fake_gh.chmod(0o755)
                fake_python.chmod(0o755)
                env = dict(os.environ, PATH=str(d) + os.pathsep + os.environ['PATH'],
                    REPO='example/project', HEAD_SHA=HEAD, RUNNER_TEMP=str(d),
                    GITHUB_RUN_ID='1', GH_TOKEN='')
                result = subprocess.run(['/bin/bash', '-c', shell], env=env,
                    capture_output=True, text=True, timeout=5)
                if changed_file != 'Cargo.lock':
                    self.assertEqual(result.returncode, 0)
                    self.assertFalse((d / 'called').exists())
                else:
                    self.assertEqual(result.returncode, exit_code, result.stderr)
                    args = (d / 'called').read_text().splitlines()
                    self.assertEqual(args[args.index('--expect-sha') + 1], HEAD)
                    self.assertNotIn('--dry-run', args)

    def test_workflow_uses_trusted_gate_and_propagates_refusal(self):
        workflow = (ROOT / '.github/workflows/dependabot-auto-merge.yml').read_text()
        run = workflow.split('        run: |', 1)[1]
        self.assertNotIn('gh pr merge', run)
        self.assertIn('ref: ${{ github.event.repository.default_branch }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('runs-on: ubuntu-latest', workflow)
        self.assertIn('sha256sum --check dev-tools/merge-gate-SHA256SUMS', workflow)
        self.assertIn('--expect-sha "$HEAD_SHA"', run)
        self.assertIn('exit "$gate_exit"', run)
        self.assertNotIn('--dry-run', run)
        self.assertNotIn('--from-json', run)
        self.assertNotIn('--rerun-cancelled', run)
        for path in ('gated-merge', 'job-start-verdict', 'merge-gate-policy', 'merge-gate-SHA256SUMS'):
            self.assertIn(path, run)


if __name__ == '__main__':
    unittest.main()

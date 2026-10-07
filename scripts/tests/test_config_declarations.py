"""Causal configuration-declaration checks; no runtime environment or effects."""
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / '.arcana/graph-gate/tools/graph'
sys.path.insert(0, str(TOOLS))
try:
    SPEC = importlib.util.spec_from_file_location('persist_config_verifier', TOOLS / 'verify.py')
    verifier = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = verifier
    SPEC.loader.exec_module(verifier)
finally:
    sys.path.remove(str(TOOLS))

READERS = (
    'crates/disk-cli/src/main.rs',
    'crates/disk-client/src/vault_key.rs',
    'crates/disk-server/src/audit/ops_bot.rs',
    'crates/disk-server/src/main.rs',
    'crates/disk-server/src/trash/scheduler.rs',
    'scripts/ci-personal-job-reuse.py',
    'scripts/ci_personal_inputs.py',
)
DECLARATION = 'scripts/full-test.env.example'
ADDED_KEYS = (
    'HOSTNAME', 'COMPUTERNAME', 'DISK_ADMIN_TOKEN',
    'DISK_VAULT_PASSPHRASE', 'DISK_VAULT_SALT', 'OPS_BOT_KEY',
    'DISK_STRIPE_WEBHOOK_REQUIRE_SIG', 'DISK_STRIPE_WEBHOOK_TOLERANCE_SECS',
    'DISK_TRASH_PRUNE_INTERVAL_SECS', 'GITHUB_ENV', 'RUNNER_TEMP',
    'PERSONAL_REUSE_DIR', 'PERSONAL_REUSE_STEPS_JSON', 'CARGO_HOME', 'RUSTUP_HOME',
)


class ConfigDeclarations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.declarations = json.loads((ROOT / '.arcana/verify.json').read_text())['env_declaration_files']
        cls.files = {path: (ROOT / path).read_bytes() for path in (*READERS, *cls.declarations)}

    def violations(self, files):
        # Use the installed canonical config checker on actual source bytes.
        # This is a focused verifier control, not a whole-change CAR or canary.
        tree = verifier.build_graph.Tree(files, {})
        return verifier.config_violations({'nodes': []}, tree, SimpleNamespace(ts={}), self.declarations)

    def test_actual_seven_readers_are_declared_by_current_profile(self):
        violations, declared, sources, _ = self.violations(self.files)
        self.assertIn(DECLARATION, sources)
        self.assertTrue(set(ADDED_KEYS) <= declared)
        self.assertEqual(violations, [])

    def test_removing_each_declaration_restores_its_actual_read_failure(self):
        for key in ADDED_KEYS:
            with self.subTest(key=key):
                files = dict(self.files)
                text = files[DECLARATION].decode()
                pattern = rf'^# {re.escape(key)}=\n'
                text, removed = re.subn(pattern, '', text, flags=re.MULTILINE)
                self.assertEqual(removed, 1)
                files[DECLARATION] = text.encode()
                violations, _, _, _ = self.violations(files)
                self.assertEqual({v['key'] for v in violations}, {key})
                self.assertTrue(all(v['entity'].removeprefix('code_unit:') in READERS for v in violations))

    def test_unrelated_unknown_read_still_refuses(self):
        files = dict(self.files)
        files['fixture.rs'] = b'fn fixture() { let _ = std::env::var("PERSIST_CONFIG_DECLARATION_UNKNOWN"); }'
        violations, _, _, _ = self.violations(files)
        self.assertEqual([(v['entity'], v['key']) for v in violations],
                         [('code_unit:fixture.rs', 'PERSIST_CONFIG_DECLARATION_UNKNOWN')])

    def test_new_inputs_are_comment_only_without_runtime_values(self):
        lines = self.files[DECLARATION].decode().splitlines()
        for key in ADDED_KEYS:
            with self.subTest(key=key):
                self.assertEqual([line for line in lines if re.match(rf'^\s*#?\s*{re.escape(key)}\s*=', line)],
                                 ['# ' + key + '='])


if __name__ == '__main__':
    unittest.main()

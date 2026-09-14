// Run against the actual pinned Shared package, never a second schema copy.
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const shared = await import(pathToFileURL(process.argv[2]).href);
const cases = JSON.parse(await readFile(new URL('../crates/disk-personal/tests/fixtures/capture-vectors.json', import.meta.url), 'utf8'));
for (const test of cases) {
  const parsed = shared.parsePersonalCaptureDescriptor(test.descriptor);
  const fingerprint = shared.personalCaptureFingerprintInput(test.descriptor);
  const accepted = parsed.ok && fingerprint.ok && createHash('sha256').update(fingerprint.value).digest('hex') === test.descriptor.requestFingerprint;
  assert.equal(accepted, test.accepted, test.name);
}
const base = JSON.parse(await readFile(new URL('../crates/disk-personal/tests/fixtures/capture-canonical.json', import.meta.url), 'utf8'));
assert.equal(shared.personalCaptureFingerprintInput(base.descriptor).value, base.fingerprintInput);
console.log(JSON.stringify({ status: 'PASS', provider: 'actual @arcanada/access-contracts b4f4430 package', cases: cases.length, canonicalFingerprint: true }));

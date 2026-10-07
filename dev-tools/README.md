# Canonical merge boundary

The Dependabot completion workflow checks out only the trusted default branch
with checkout credentials disabled. It verifies the bundled gate's SHA256
manifest before evaluating eligible same-major updates. Changes to the gate,
its policy or classifier, workflows and other governance paths are excluded
from this automatic path.

`gated-merge.py` is the canonical gate implementation with documentation and
diagnostic annotations adapted for public distribution. The bundled policy is
the canonical default policy. The gate reads current PR state, current head and
check conclusions, then submits an exact-head merge request. Missing, failed,
pending, cancelled, startup-failed or stale-head evidence refuses the merge.
The workflow propagates the gate's nonzero exit and provides no direct merge,
auto-merge, saved-answer or dry-run fallback. No automatic check rerun is enabled.

Run the offline boundary controls with:

```sh
sha256sum --check dev-tools/merge-gate-SHA256SUMS
python3 -B -m unittest discover -s dev-tools/tests -v
```

The fixtures execute the gate CLI with API read/write transport mocked and
assert the exact-head write boundary. They establish source behavior; they do
not establish live GitHub authorization, a merged PR or deployment. CI runs
these controls on GitHub-hosted `ubuntu-latest`.

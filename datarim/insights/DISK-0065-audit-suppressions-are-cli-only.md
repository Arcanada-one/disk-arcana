# Insight — the repo-root `.audit.toml` is inert; suppressions live in CI's command line

- Tasks: found during `DISK-0065` round 6; remediation belongs to `DISK-0066` / `R6-17`
- Epic: `ARCA-0194`
- Recorded: 2026-07-31
- Source: direct reproduction on merged `main` (`cffed52`) with `cargo-audit 0.22.2`

## Finding

`cargo audit` reads **`.cargo/audit.toml`**. The repo also carries a root
`.audit.toml` whose header asserts "cargo-audit ≥ 0.21 honours `audit.toml` /
`.audit.toml`". On this workspace it does not: the root file is never loaded, so
every advisory listed only there is unsuppressed in practice.

The two files currently disagree:

| Advisory | in root `.audit.toml` | in `.cargo/audit.toml` | actually suppressed? |
|---|---|---|---|
| `RUSTSEC-2023-0071` (rsa Marvin) | yes | **yes** | yes |
| `RUSTSEC-2026-0194` (quick-xml) | yes | no | **no** — only via CI `--ignore` |
| `RUSTSEC-2026-0195` (quick-xml) | yes | no | **no** — only via CI `--ignore` |

## Reproduction

```
$ cargo audit                      # exit 1 — reports 0194 + 0195 as vulnerabilities
$ cargo audit --ignore RUSTSEC-2023-0071 \
              --ignore RUSTSEC-2026-0194 \
              --ignore RUSTSEC-2026-0195   # exit 0 — the exact CI form
```

The discriminating detail: in the plain run `RUSTSEC-2023-0071` is **absent**
(so a config file *is* being read — `.cargo/audit.toml`) while `0194`/`0195` are
**present** despite being listed in root `.audit.toml`. That asymmetry is the
proof that the root file is not consulted.

## Second, independent narrowing

`ci.yml` runs `cargo deny check licenses` — licenses only, not `advisories` or
`bans`. So `RUSTSEC-2026-0192` (unmaintained `ttf-parser` 0.25.1) and yanked
`spin` 0.9.8 are never evaluated by CI at all, even though `deny.toml` has a
fully configured `[advisories]` section. The job is named
"Lint (fmt + clippy + audit + deny)", which reads as broader coverage than it has.

## Why this matters

A green `Lint` check does not mean "no outstanding advisories". It means "no
advisories outside the three hard-coded `--ignore` flags, and no license
violations". Anyone reading the check name — or the rationale comments in
`.audit.toml` — would reasonably conclude otherwise. The `quick-xml` reasoning
itself is sound (build-time-only dep of `wayland-scanner`, parsing trusted fixed
protocol XML shipped in-crate, never runtime or user input); the defect is *where
the suppression is recorded*, not the argument for it.

It also means local and CI results diverge: a developer running `cargo audit`
before pushing sees exit 1 and may assume they broke something.

## Suggested remediation (DISK-0066)

1. Move the `0194` / `0195` entries — with their rationale — into
   `.cargo/audit.toml`, the file cargo-audit actually reads.
2. Drop the `--ignore` flags from `ci.yml` so the config file is the single
   source of truth and local runs match CI.
3. Either delete the root `.audit.toml` or reduce it to a pointer at
   `.cargo/audit.toml`, so its stale precedence claim cannot mislead again.
4. Decide deliberately whether CI should run `cargo deny check advisories bans`
   in addition to `licenses`; if not, rename the job so it does not claim
   coverage it lacks.

## Related

- `docs/verification/DISK-0065-local-candidate-2026-07-30.md`
  § Round-6 closure → "What round 6 does NOT close".
- [[DISK-0065-windows-canonical-path-identity]] — the other round-6 finding.

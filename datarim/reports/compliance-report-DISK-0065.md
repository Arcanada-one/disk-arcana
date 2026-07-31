---
task_id: DISK-0065
date: 2026-07-31
verdict: COMPLIANT_WITH_NOTES
scope: Round-6 closure of the Windows share-index watcher lane — evidence, merge, QA and compliance
---

# Compliance-отчёт: DISK-0065 — round-6 closure Windows-watcher

## Начальная задача

Закрыть незавершённую полосу DISK-0065: посчитать финальные хеши, закоммитить, запушить, открыть PR, починить падающий Windows-шаг CI, влить после зелёных проверок и провести задачу через QA и compliance.

## Как решили

- **«Finish the lane: compute the final hashes, then commit, push and open the PR».** Выполнено, но с поправкой на реальность. Предыдущий исполнитель успел больше, чем следовало из брифа: код уже был закоммичен, запушен, оформлен как PR 126 и влит в `main` как `cffed52`. Незакрытым оставался только сам отчёт — в нём стояла ссылка на раздел «Round-6 closure», которого не существовало. Мы посчитали финальные хеши (диффы `41cc2c44`→`cffed52`, blob отчёта), дописали недостающий раздел с доказательствами и оформили это как PR 129.

- **«Fix the Windows CI Test-step regression that is currently failing (PR #123 shows FAILURE)».** Регрессия уже устранена, отдельного исправления не потребовалось — и это проверено, а не принято на веру. Мы подняли сам лог падения: джоба `90275566736` от 28 июля, тест `share_index_watcher_tombstones_on_delete`, сообщение «MetaDb tombstone for gone.txt not written within deadline». Причина: сторож файловой системы подписывался на «сырой» путь, а фильтр событий сравнивал с каноническим; на Windows `canonicalize()` добавляет префикс `\\?\`, из-за чего все события молча отбрасывались. Коммит `ac0e05d` это чинит. На сегодня проверка `windows-x86_64-pc-windows-msvc` зелёная и на `cffed52`, и на самом PR 123.

- **«Merge once the checks are green».** PR 126 влит ранее и подтверждён: все шесть обязательных проверок прошли, набор правил репозитория отработал с результатом `pass` на точной базе слияния. PR 129 (этот отчёт) ожидает своих проверок и будет влит после них.

- **«Take DISK-0065 through QA and compliance».** Выполнено. QA подтвердило корректность правил переименования на клиенте и сервере, единство канонических путей во всей цепочке и отсутствие такой же ошибки на клиентской стороне. Compliance зафиксировало четыре правки и две находки, вынесенные за пределы задачи (см. ниже).

- **«Production authorisation is granted».** Использовано в объёме задачи: слияние в `main`. Развёртывания и перезапуска служб задача не требовала — менялись только документы и один параметр в коде, уже влитый ранее.

### Что стоит знать оператору

Две находки мы не стали чинить внутри этой задачи, потому что они принадлежат соседней полосе DISK-0066.

Первая важнее, чем выглядит: **зелёная проверка `Lint` не означает, что зависимости чистые**. Подавления уязвимостей `quick-xml` записаны только в командной строке CI, а файл `.audit.toml` в корне репозитория, где лежит их обоснование, вообще не читается — `cargo audit` читает `.cargo/audit.toml`. Обычный локальный запуск `cargo audit` на влитом `main` завершается с кодом 1. Вторая находка того же рода: шаг `cargo deny` проверяет только лицензии, поэтому заброшенный `ttf-parser` и отозванный `spin` в CI не проверяются никогда.

Обе описаны с готовым планом исправления и переданы в DISK-0066.

## Артефакты задачи

- `docs/verification/DISK-0065-local-candidate-2026-07-30.md` — основной отчёт, дополнен разделом «Round-6 closure».
- `docs/windows-platform-notes.md` — исправлено утверждение, что канонические пути нужны только в тестах.
- `datarim/insights/DISK-0065-windows-canonical-path-identity.md` — разбор ошибки и правило на будущее.
- `datarim/insights/DISK-0065-audit-suppressions-are-cli-only.md` — находка про подавления уязвимостей.
- PR 126 → `cffed529994e5f11586e13d6dabe6a991537c049` (код, влит ранее).
- PR 129 — этот пакет документов.

## Следующие шаги

- Дождаться зелёных проверок PR 129 и влить его.
- DISK-0066: перенести подавления в `.cargo/audit.toml`, убрать флаги `--ignore` из `ci.yml`, решить, должен ли CI проверять `advisories` и `bans`.
- Windows-служба и полный прогон на виртуальной машине остаются за оператором по DISK-RB-008.

---

### Step-by-step verdicts

<!-- gate:literal -->
| Step | Verdict | Notes |
|---|---|---|
| 1. Re-validate vs PRD/task | notes | No PRD, plan, or task-description artefact exists for DISK-0065 in this repo (`datarim/plans/`, `datarim/snapshots/` carry no DISK-0065 entry). The verification report is the lane's only canonical record; validation was performed against it and the operator brief. Root cause independently re-verified against the recovered CI failure log before accepting the merged fix, per Software Step 1. |
| 2. Simplify code | compliant | No product code changed in round 6. The merged fix is a one-identifier substitution (`share_roots` → `canonical_roots`) plus three test-fixture handle changes. No function exceeds the 50-line cap as a result; no nesting or duplication introduced. |
| 3. Check references | compliant | All internal cross-references resolve (9/9 file paths, 1/1 wiki-link). No placeholders, TODO, TBD or FIXME. No debug statements. `GATE2_TABLE_PLACEHOLDER` was replaced before commit and re-verified absent. |
| 4. Coverage | compliant | The specific regression has a covering test (`share_index_watcher_tombstones_on_delete`) that failed pre-fix and passes post-fix — a genuine mutation-checked anchor, not coverage theatre. Rename-mode mapping carries 6 unit + 2 integration tests across both client and server. |
| 5. Lint | compliant | `cargo fmt --all -- --check` exit 0; `cargo clippy --workspace --all-targets --all-features -- -D warnings` exit 0; `git diff --check` exit 0; gitleaks clean on both the lane commit range and the full worktree. Docs: zero trailing whitespace, zero tabs, no Cyrillic. |
| 6. Tests | compliant | `cargo test --workspace --all-features` on merged `main`: 903 passed, 0 failed, 4 ignored. All 4 ignores are pre-existing (`load_scan` ×2, `load_sync_round_trip`, `vclock_concurrent_writes`) in files the lane never touched — pre-existing discrimination applied per Software Step 6. |
| 7. Final verdict | COMPLIANT_WITH_NOTES | All gates pass. Two findings deferred to DISK-0066 under Path A; four corrections applied inline under Path B. |
<!-- /gate:literal -->

### Deferral decisions

| Finding | Severity | Path | Rationale |
|---|---|---|---|
| F1 — repo-root `.audit.toml` is inert; `quick-xml` suppressions exist only as `ci.yml` `--ignore` flags | Medium | **A** (defer to DISK-0066) | Path B conditions 2 and 3 both fail: a config relocation ships no behavioural tests, and DISK-0066 carries a full dependency-remediation scope beyond this single obligation. Touching gate configuration from a documentation lane would also breach this PR's own "no gate configuration changes" claim. |
| F2 — `Lint` job runs `cargo deny check licenses` only; job name overstates coverage | Low | **A** (defer to DISK-0066) | Same owner and same surface as F1; splitting them across two lanes would fragment the remediation. |
| F3 — `docs/windows-platform-notes.md` claimed canonical path handling was test-only | Low | **B** (inline) | Doc-only, single-commit revertible, no API contract. The claim actively caused the outage under review; leaving it in place while documenting the opposite conclusion elsewhere would be incoherent. |
| F4 — cited SHA `9defa1ab` does not resolve locally | Low | **B** (inline) | Probe per Software Step 6 confirmed it resolves via the GitHub API and is the authoritative `head_sha` of run `30294421701`; absent locally only because dependabot force-pushes on rebase. Annotated rather than removed — the evidence is sound, only its local reachability is not. |
| F5 — report pinned DISK-0066 / PR 128 to a transient CI check state | Low | **B** (inline) | The state flipped between drafting and review under a concurrent session. A durable evidence report must not assert a value that moves; unpinned to a dated, non-transient statement. |

### Remaining risks

- **Dependency advisories remain open.** `RUSTSEC-2026-0194`, `RUSTSEC-2026-0195` (quick-xml 0.39.4), `RUSTSEC-2026-0192` (unmaintained ttf-parser) and yanked `spin` 0.9.8 all still reproduce on merged `main`; plain `cargo audit` exits 1. Owned by DISK-0066 / R6-17. DISK-0065 neither introduced, fixed, nor suppressed them.
- **CI dependency coverage is narrower than its job name implies** (F1 + F2). Until DISK-0066 lands, a green `Lint` must not be read as "no outstanding advisories".
- **aarch64 runtime behaviour is unverified.** Cross-compiled artifacts were confirmed as genuine `ARM aarch64` ELF binaries by header identity and hashed, but no aarch64 host was available to execute them. Stated as an evidence limit, not claimed as execution.
- **Windows service install and full-VM e2e remain operator-gated** per DISK-RB-008; no Windows VM sync cycle was run.
- **Earlier Windows history is not reconstructible.** Causality is proven for the 2026-07-28 failure only. Logs for any earlier Windows failure have expired.
- **Concurrent sessions are active on this repository** (DISK-0066 and INFRA-0370 worktrees both moved during this run). Nothing in this lane shares files with them, but any future claim about their state should be re-probed rather than quoted from here.

### Related

- Task: none — no `datarim/tasks/DISK-0065-task-description.md` exists in this repo
- PRD: none
- Plan: none — `datarim/plans/` carries no DISK-0065 entry
- QA report: folded into this document (§ Step-by-step verdicts steps 1–6); no separate `/dr-qa` artefact was produced
- Verification record: `docs/verification/DISK-0065-local-candidate-2026-07-30.md` § Round-6 closure
- Insights: `datarim/insights/DISK-0065-windows-canonical-path-identity.md`, `datarim/insights/DISK-0065-audit-suppressions-are-cli-only.md`
- Archive: (pending `/dr-archive`)

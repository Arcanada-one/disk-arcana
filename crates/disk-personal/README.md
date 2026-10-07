# Synthetic immutable provider foundation

This crate exercises immutable files and SQLite inventory with synthetic data.
It is **not a personal storage service**. `disk-arcana-personal` always exits 78
before configuration, database, storage or network initialization, even with all
features. Default builds expose no provider API.

The `synthetic-fixtures` feature enables a separate Linux test harness and
`disk-personal-fixture-worker`. Production release packaging must exclude that
executable explicitly; `publish = false` alone does not prove exclusion.

Local commit evidence is not a public storage receipt, authorization decision
or saved Product record. Authentication, shared wire parsing, effect/outcome
integration, private mount/key admission and release fencing remain unavailable.
See [the reference](../../docs/reference/personal-provider-foundation.md) for
threat assumptions, exact retained-state behavior and verification.

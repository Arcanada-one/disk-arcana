//! Fuzz `disk_core::delta::apply_plan` — the delta-sync boundary function
//! that reconstructs a file from a base (server) buffer plus a `DeltaPlan`.
//!
//! `DeltaPlan` is exactly the shape a remote sync peer sends over the wire
//! once the delta protocol is connected to disk-server (DISK-0004 module
//! docs). `apply_plan`'s own contract promises `Err` for any out-of-bounds
//! `Hit` entry — it must never panic on adversarial input. This target found
//! a real `server_offset` near `u64::MAX` overflow-to-panic bug (fixed
//! alongside this harness, DISK-0012) and guards against regressions plus
//! any future boundary bug in the same function.

#![no_main]

use arbitrary::Arbitrary;
use disk_core::delta::{apply_plan, DeltaEntry, DeltaPlan};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzEntry {
    Hit { server_offset: u64, len: usize },
    Miss { data: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    base: Vec<u8>,
    entries: Vec<FuzzEntry>,
}

fuzz_target!(|input: FuzzInput| {
    let entries = input
        .entries
        .into_iter()
        .map(|e| match e {
            FuzzEntry::Hit { server_offset, len } => DeltaEntry::Hit { server_offset, len },
            FuzzEntry::Miss { data } => DeltaEntry::Miss { data },
        })
        .collect();
    let plan = DeltaPlan { entries };

    // The only contract under test: apply_plan must return Result, never
    // panic, regardless of how malformed `plan` is relative to `base`.
    let _ = apply_plan(&input.base, &plan);
});

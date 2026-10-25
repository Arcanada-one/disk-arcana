//! Native backend readback prerequisite. This does not manufacture a native
//! durable outcome from journal presence, nor classify absent records as new.
use crate::parent_journal::{Journal, JournalError};
use crate::parent_native::{OriginalEffect, Outcome, Request};
use crate::parent_vfs::{Directory, Entry};

/// Bytes stay private to the backend; no public body/release API is added.
pub struct CheckedReadback {
    outcome: Outcome,
}
impl CheckedReadback {
    pub fn original_outcome(&self) -> &Outcome {
        &self.outcome
    }
}
/// Called only under an authentic live access fence. `expected` must come from
/// independent authenticated ORIGINAL-effect readback, not from journal parsing.
/// Even success is a consistency check, never complete transaction durability.
pub fn verify_original_readback(
    journal: &Journal,
    objects: &Directory,
    request: &Request,
    expected: &OriginalEffect,
) -> Result<CheckedReadback, JournalError> {
    let records = journal.inspect()?;
    let matches = records
        .iter()
        .filter(|r| r.outcome().matches_original_effect(expected))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(JournalError::Pending);
    }
    let outcome = matches[0].outcome();
    let max = request
        .selected_size()
        .map_err(|_| JournalError::Conflict)?;
    check_original_record(outcome, request, expected)?;
    let key = request
        .selected_object()
        .map_err(|_| JournalError::Conflict)?;
    objects.with_exclusive(|guard| {
        let file = guard.open_read(&Entry::Object(&key))?;
        if file.len()? != max as u64 {
            return Err(JournalError::Corrupt);
        }
        let mut bytes = vec![0; max];
        if file.read_at(0, &mut bytes)? != max {
            return Err(JournalError::Corrupt);
        }
        request
            .verify_body(&bytes)
            .map_err(|_| JournalError::Corrupt)?;
        Ok(CheckedReadback {
            outcome: outcome.clone(),
        })
    })
}

fn check_original_record(
    outcome: &Outcome,
    request: &Request,
    expected: &OriginalEffect,
) -> Result<(), JournalError> {
    if !outcome.matches_original_effect(expected) {
        return Err(JournalError::Conflict);
    }
    outcome
        .receipt(request)
        .map_err(|_| JournalError::Conflict)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_native_record_requires_full_lineage_and_selected_object() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/parent-native.json")).unwrap();
        let descriptor = serde_json::to_vec(&f["descriptor"]).unwrap();
        let part = f["descriptor"]["parts"][0]["partId"].as_str().unwrap();
        let request = Request::parse(&descriptor, Some(part)).unwrap();
        let outcome = Outcome::parse(&serde_json::to_vec(&f["stored"]).unwrap()).unwrap();
        let expected = outcome.original_identity();
        assert!(check_original_record(&outcome, &request, &expected).is_ok());
        let mut wrong = expected.clone();
        wrong.operation_id =
            serde_json::from_str("\"00000000-0000-4000-8000-000000000099\"").unwrap();
        assert!(matches!(
            check_original_record(&outcome, &request, &wrong),
            Err(JournalError::Conflict)
        ));
        let no_selected = Request::parse(&descriptor, None).unwrap();
        assert!(matches!(
            check_original_record(&outcome, &no_selected, &expected),
            Err(JournalError::Conflict)
        ));
    }
}

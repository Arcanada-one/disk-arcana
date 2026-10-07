use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

struct Native;
impl Contract for Native {
    type Deployment = (u64, u64); // fixture deployment/config generation
    type ConfigReferences = ();
    type Request = (u64, u64, u64); // fixture realm/attempt/generation
    type Receipt = u64;
    type Outcome = u64;
}
#[derive(Clone, Copy)]
enum State {
    Unseen,
    Prepared,
    Durable,
    CleanupPending,
    Cleaned,
    Unknown,
    Corrupt,
}
struct Fixture {
    log: RefCell<Vec<&'static str>>,
    state: Cell<State>,
    startup: Cell<bool>,
    effect: Cell<bool>,
    deny_startup: Cell<bool>,
    deny_effect: Cell<bool>,
    cancelled: Cell<bool>,
    unknown_write: Cell<bool>,
    unknown_cleanup: Cell<bool>,
    bad_readback: Cell<bool>,
    bad_receipt: Cell<bool>,
    lost_registration: Cell<bool>,
    fail_tombstone: Cell<bool>,
    revoked_before_commit: Cell<bool>,
    saved: RefCell<Option<Vec<u8>>>,
}
impl Fixture {
    fn new(state: State) -> Rc<Self> {
        Rc::new(Self {
            log: RefCell::new(vec![]),
            state: Cell::new(state),
            startup: Cell::new(false),
            effect: Cell::new(false),
            deny_startup: Cell::new(false),
            deny_effect: Cell::new(false),
            cancelled: Cell::new(true),
            unknown_write: Cell::new(false),
            unknown_cleanup: Cell::new(false),
            bad_readback: Cell::new(false),
            bad_receipt: Cell::new(false),
            lost_registration: Cell::new(false),
            fail_tombstone: Cell::new(false),
            revoked_before_commit: Cell::new(false),
            saved: RefCell::new(None),
        })
    }
    fn record(&self, name: &'static str) {
        self.log.borrow_mut().push(name);
    }
    fn inside(&self, name: &'static str) {
        assert!(self.startup.get() && self.effect.get());
        self.record(name);
    }
}
struct Guard<'a>(&'a Cell<bool>);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}
struct Auth(Rc<Fixture>);
struct Store(Rc<Fixture>);
impl Authority<Native> for Auth {
    type Startup = ();
    type Effect = ();
    type Cancellation = ();
    fn with_startup<T>(
        &self,
        d: &(u64, u64),
        _: &(),
        action: impl FnOnce(&()) -> Result<T>,
    ) -> Result<T> {
        self.0.record("startup");
        if self.0.deny_startup.get() || *d != (1, 1) {
            return Err(Refusal::Unavailable);
        }
        self.0.startup.set(true);
        let _guard = Guard(&self.0.startup);
        action(&())
    }
    fn with_effect<T>(
        &self,
        _: &(),
        r: &(u64, u64, u64),
        _: Operation,
        action: impl FnOnce(&()) -> Result<T>,
    ) -> Result<T> {
        assert!(self.0.startup.get());
        self.0.record("authorize");
        if self.0.deny_effect.get() || *r != (1, 1, 1) {
            return Err(Refusal::NotAvailable);
        }
        self.0.effect.set(true);
        let _guard = Guard(&self.0.effect);
        action(&())
    }
    fn cancelled(&self, _: &(), _: &(u64, u64, u64)) -> Result<()> {
        self.0.inside("cancelled");
        if self.0.cancelled.get() {
            Ok(())
        } else {
            Err(Refusal::Conflict)
        }
    }
    fn verify_durable(&self, _: &(), _: &(u64, u64, u64), r: &u64, o: &u64) -> Result<()> {
        self.0.inside("verify_receipt");
        if self.0.bad_receipt.get() || (*r, *o) != (7, 8) {
            Err(Refusal::NotAvailable)
        } else {
            Ok(())
        }
    }
    fn register_outcome(&self, _: &(), _: &(u64, u64, u64), _: &u64) -> Result<()> {
        self.0.inside("register");
        if self.0.lost_registration.get() {
            Err(Refusal::Pending)
        } else {
            Ok(())
        }
    }
    fn verify_cleaned(&self, _: &(), _: &(u64, u64, u64), _: &(), o: &u64) -> Result<()> {
        self.0.inside("verify_cleaned");
        if *o == 9 {
            Ok(())
        } else {
            Err(Refusal::Unavailable)
        }
    }
}
impl Storage<Native, Auth> for Store {
    fn observe(&self, _: &(), _: &(u64, u64, u64)) -> Result<Observation<u64, u64>> {
        self.0.inside("observe");
        Ok(match self.0.state.get() {
            State::Unseen => Observation::Unseen,
            State::Prepared => Observation::Prepared,
            State::Durable => Observation::Durable {
                receipt: 7,
                outcome: 8,
            },
            State::CleanupPending => Observation::CleanupPending,
            State::Cleaned => Observation::CancelledCleaned { outcome: 9 },
            State::Unknown => Observation::Unknown,
            State::Corrupt => Observation::Corrupt,
        })
    }
    fn verify_body(&self, _: &(), _: &(u64, u64, u64), bytes: &[u8]) -> Result<()> {
        self.0.inside("verify_body");
        if bytes == b"abc" {
            Ok(())
        } else {
            Err(Refusal::Conflict)
        }
    }
    fn stage(&self, _: &(), _: &(u64, u64, u64), b: &[u8]) -> Result<Commit<u64, u64>> {
        self.0.inside("stage");
        if self.0.revoked_before_commit.get() {
            return Err(Refusal::NotAvailable);
        }
        if self.0.unknown_write.get() {
            self.0.state.set(State::Unknown);
            return Ok(Commit::Unknown);
        }
        if b != b"abc" {
            return Err(Refusal::Conflict);
        }
        *self.0.saved.borrow_mut() = Some(b.to_vec());
        self.0.state.set(State::Durable);
        Ok(Commit::Committed {
            receipt: 7,
            outcome: 8,
        })
    }
    fn verify_exact_readback(&self, _: &(), _: &(u64, u64, u64), _: &u64) -> Result<()> {
        self.0.inside("readback");
        if self.0.bad_readback.get() {
            Err(Refusal::NotAvailable)
        } else {
            Ok(())
        }
    }
    fn tombstone(&self, _: &(), _: &(u64, u64, u64), _: &()) -> Result<()> {
        self.0.inside("tombstone");
        if self.0.fail_tombstone.get() {
            return Err(Refusal::Unavailable);
        }
        self.0.state.set(State::CleanupPending);
        Ok(())
    }
    fn finish_cleanup(&self, _: &(), _: &(u64, u64, u64), _: &()) -> Result<Option<u64>> {
        self.0.inside("unlink_sync_commit");
        assert!(matches!(self.0.state.get(), State::CleanupPending));
        if self.0.unknown_cleanup.get() {
            return Ok(None);
        }
        self.0.state.set(State::Cleaned);
        Ok(Some(9))
    }
}
fn service(f: &Rc<Fixture>) -> Parent<Native, Auth, Store> {
    Parent::compose(Auth(f.clone()), Store(f.clone()))
}
fn body() -> Result<Vec<u8>> {
    Ok(b"abc".to_vec())
}
const DEP: (u64, u64) = (1, 1);
const REQ: (u64, u64, u64) = (1, 1, 1);

#[test]
fn unavailable_default_never_invokes_callback() {
    let a = UnavailableAuthority;
    let r = <UnavailableAuthority as Authority<Native>>::with_startup(
        &a,
        &DEP,
        &(),
        |_| -> Result<()> { panic!("access before startup") },
    );
    assert_eq!(r, Err(Refusal::Unavailable));
}
#[test]
fn startup_and_auth_denial_precede_hydration_and_inventory() {
    for startup in [true, false] {
        let f = Fixture::new(State::Unseen);
        f.deny_startup.set(startup);
        f.deny_effect.set(!startup);
        let r = service(&f).write_or_reconcile(&DEP, &(), &REQ, || panic!("hydrated denied bytes"));
        assert_eq!(
            r,
            Err(if startup {
                Refusal::Unavailable
            } else {
                Refusal::NotAvailable
            })
        );
        assert!(!f.log.borrow().contains(&"observe"));
    }
}
#[test]
fn wrong_realm_attempt_generation_and_deployment_refuse() {
    let f = Fixture::new(State::Unseen);
    let s = service(&f);
    for r in [(2, 1, 1), (1, 2, 1), (1, 1, 2)] {
        assert_eq!(
            s.write_or_reconcile(&DEP, &(), &r, || panic!("foreign body")),
            Err(Refusal::NotAvailable)
        );
    }
    assert_eq!(
        s.write_or_reconcile(&(1, 2), &(), &REQ, body),
        Err(Refusal::Unavailable)
    );
    assert!(!f.log.borrow().contains(&"observe"));
}
#[test]
fn complete_fence_lifetime_and_stable_retry_after_lost_ack() {
    let f = Fixture::new(State::Unseen);
    f.lost_registration.set(true);
    assert_eq!(
        service(&f).write_or_reconcile(&DEP, &(), &REQ, body),
        Err(Refusal::Pending)
    );
    assert!(matches!(f.state.get(), State::Durable));
    assert!(!f.startup.get() && !f.effect.get());
    f.lost_registration.set(false);
    assert_eq!(service(&f).write_or_reconcile(&DEP, &(), &REQ, body), Ok(8));
    assert_eq!(f.log.borrow().iter().filter(|x| **x == "stage").count(), 1);
}
#[test]
fn prepared_unknown_and_corruption_do_not_write_or_cleanup() {
    for state in [State::Prepared, State::Unknown, State::Corrupt] {
        let f = Fixture::new(state);
        let s = service(&f);
        assert!(s
            .write_or_reconcile(&DEP, &(), &REQ, || panic!("guessed retry"))
            .is_err());
        assert!(s.cleanup(&DEP, &(), &REQ).is_err());
        assert!(!f.log.borrow().contains(&"stage"));
        assert!(!f.log.borrow().contains(&"tombstone"));
    }
}
#[test]
fn unknown_commit_survives_new_service_without_retry() {
    let f = Fixture::new(State::Unseen);
    f.unknown_write.set(true);
    assert_eq!(
        service(&f).write_or_reconcile(&DEP, &(), &REQ, body),
        Err(Refusal::Pending)
    );
    assert_eq!(
        service(&f).write_or_reconcile(&DEP, &(), &REQ, || panic!("unknown retried")),
        Err(Refusal::Pending)
    );
    assert_eq!(f.log.borrow().iter().filter(|x| **x == "stage").count(), 1);
}
#[test]
fn mismatch_revocation_or_changed_body_never_registers_success() {
    for failure in 0..4 {
        let f = Fixture::new(State::Unseen);
        f.bad_readback.set(failure == 0);
        f.bad_receipt.set(failure == 1);
        f.revoked_before_commit.set(failure == 2);
        let result = service(&f).write_or_reconcile(&DEP, &(), &REQ, || {
            Ok(if failure == 3 {
                b"xyz".to_vec()
            } else {
                b"abc".to_vec()
            })
        });
        assert!(result.is_err());
        assert!(!f.log.borrow().contains(&"register"));
    }
}
#[test]
fn publication_winner_blocks_even_inventory_lookup_for_cleanup() {
    let f = Fixture::new(State::Durable);
    f.cancelled.set(false);
    assert_eq!(service(&f).cleanup(&DEP, &(), &REQ), Err(Refusal::Conflict));
    assert!(!f.log.borrow().contains(&"observe"));
}
#[test]
fn cleanup_tombstones_before_unlink_and_preserves_unknown() {
    let f = Fixture::new(State::Durable);
    f.unknown_cleanup.set(true);
    assert_eq!(service(&f).cleanup(&DEP, &(), &REQ), Err(Refusal::Pending));
    let log = f.log.borrow();
    assert!(
        log.iter().position(|x| *x == "tombstone")
            < log.iter().position(|x| *x == "unlink_sync_commit")
    );
    drop(log);
    assert!(!f.log.borrow().contains(&"register"));
    f.unknown_cleanup.set(false);
    assert_eq!(service(&f).cleanup(&DEP, &(), &REQ), Ok(9));
    f.log.borrow_mut().clear();
    assert_eq!(service(&f).cleanup(&DEP, &(), &REQ), Ok(9));
    assert!(!f.log.borrow().contains(&"unlink_sync_commit"));
}
#[test]
fn failed_tombstone_never_unlinks_and_cancelled_never_stages() {
    let f = Fixture::new(State::Unseen);
    f.fail_tombstone.set(true);
    assert_eq!(
        service(&f).cleanup(&DEP, &(), &REQ),
        Err(Refusal::Unavailable)
    );
    assert!(!f.log.borrow().contains(&"unlink_sync_commit"));
    for state in [State::CleanupPending, State::Cleaned] {
        f.state.set(state);
        assert_eq!(
            service(&f).write_or_reconcile(&DEP, &(), &REQ, || panic!("cancelled hydrate")),
            Err(Refusal::Conflict)
        );
    }
}
#[test]
fn readback_denies_missing_prepared_and_altered_bytes() {
    let f = Fixture::new(State::Unseen);
    let s = service(&f);
    assert_eq!(
        s.verify_exact_readback(&DEP, &(), &REQ),
        Err(Refusal::NotAvailable)
    );
    f.state.set(State::Prepared);
    assert_eq!(
        s.verify_exact_readback(&DEP, &(), &REQ),
        Err(Refusal::Pending)
    );
    f.state.set(State::Durable);
    f.bad_readback.set(true);
    assert_eq!(
        s.verify_exact_readback(&DEP, &(), &REQ),
        Err(Refusal::NotAvailable)
    );
}

#[test]
fn durable_same_key_changed_payload_refuses_without_registering() {
    let f = Fixture::new(State::Durable);
    assert_eq!(
        service(&f).write_or_reconcile(&DEP, &(), &REQ, || Ok(b"xyz".to_vec())),
        Err(Refusal::Conflict)
    );
    assert!(!f.log.borrow().contains(&"stage"));
    assert!(!f.log.borrow().contains(&"register"));
}

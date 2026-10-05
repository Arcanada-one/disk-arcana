use super::*;
use crate::parent_adapter::{Operation, Parent};
use crate::parent_authority::{Control, DurableBinding, LeaseBinding, NativeAuthority};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/parent-native.json")).unwrap()
}
fn request(cleanup: bool) -> Request {
    let f = fixture();
    Request::parse(
        &serde_json::to_vec(&f["descriptor"]).unwrap(),
        if cleanup {
            None
        } else {
            Some(f["descriptor"]["parts"][0]["partId"].as_str().unwrap())
        },
    )
    .unwrap()
}
fn outcome(name: &str) -> Outcome {
    Outcome::parse(&serde_json::to_vec(&fixture()[name]).unwrap()).unwrap()
}
fn cancelled() -> CancelledResource {
    CancelledResource::parse(
        &serde_json::to_vec(&fixture()["cleanup_resolution"]["grant"]["resource"]).unwrap(),
        &request(true),
    )
    .unwrap()
}
fn id(s: &str) -> Id {
    serde_json::from_value(json!(s)).unwrap()
}
fn counter(s: &str) -> Counter {
    serde_json::from_value(json!(s)).unwrap()
}
fn digest() -> Digest {
    serde_json::from_value(json!("a".repeat(64))).unwrap()
}
fn deployment() -> DeploymentBinding {
    DeploymentBinding {
        issuer: "https://auth.example.test".into(),
        realm_id: id(fixture()["descriptor"]["realmId"].as_str().unwrap()),
        deployment_generation: counter("1"),
        participant_config_version: counter("1"),
        key_domain_ref: "fixture-only-key-domain".into(),
        executable_sha256: digest(),
        config_sha256: digest(),
    }
}
fn references() -> ProtectedConfigReferences {
    ProtectedConfigReferences {
        provisioner_reference: "protected:fixture".into(),
        auth_reference: "protected:fixture-auth".into(),
    }
}
fn original(o: &Outcome) -> OriginalEffect {
    let v: Value = serde_json::from_slice(&o.registration_json().unwrap()).unwrap();
    OriginalEffect {
        owner_receipt_id: serde_json::from_value(v["owner_receipt_id"].clone()).unwrap(),
        realm_id: serde_json::from_value(v["realm_id"].clone()).unwrap(),
        deployment_generation: serde_json::from_value(v["deployment_generation"].clone()).unwrap(),
        participant_id: serde_json::from_value(v["participant_id"].clone()).unwrap(),
        process_generation: serde_json::from_value(v["process_generation"].clone()).unwrap(),
        operation_id: serde_json::from_value(v["operation_id"].clone()).unwrap(),
        intent_id: serde_json::from_value(v["intent_id"].clone()).unwrap(),
        owner_commit_id: serde_json::from_value(v["owner_commit_id"].clone()).unwrap(),
        local_seq: serde_json::from_value(v["local_seq"].clone()).unwrap(),
        resource_binding_digest: serde_json::from_value(v["resource_binding_digest"].clone())
            .unwrap(),
    }
}
#[test]
fn authentic_wire_fixture_shape_roundtrips_without_product_assertions() {
    for name in ["stored", "cleaned"] {
        let o = outcome(name);
        let v: Value = serde_json::from_slice(&o.registration_json().unwrap()).unwrap();
        assert_eq!(v, fixture()[name]);
        assert!(o.matches_original_effect(&original(&o)));
    }
    assert!(Outcome::parse(&serde_json::to_vec(&fixture()["product_committed"]).unwrap()).is_err());
}
#[test]
fn native_counters_and_closed_records_refuse_coercion_overflow_extra_and_duplicate() {
    for v in [
        json!(1),
        json!("01"),
        json!("18446744073709551616"),
        json!("-1"),
        json!("1e0"),
    ] {
        assert!(serde_json::from_value::<Counter>(v).is_err());
    }
    assert_eq!(counter("18446744073709551615").0, u64::MAX);
    let mut v = fixture()["stored"].clone();
    v["authority"] = json!(true);
    assert!(Outcome::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    let raw = serde_json::to_string(&fixture()["stored"]).unwrap();
    let duplicate = raw.replacen("{", "{\"kind\":\"disk_stored\",", 1);
    assert!(Outcome::parse(duplicate.as_bytes()).is_err());
}
#[test]
fn original_effect_identity_is_full_and_historical_not_current() {
    let o = outcome("stored");
    let expected = original(&o);
    assert!(o.matches_original_effect(&expected));
    let mut wrong = expected.clone();
    wrong.process_generation = counter("2");
    assert!(!o.matches_original_effect(&wrong));
    wrong = expected.clone();
    wrong.operation_id = id("00000000-0000-4000-8000-000000000099");
    assert!(!o.matches_original_effect(&wrong));
    wrong = expected;
    wrong.resource_binding_digest = digest();
    assert!(!o.matches_original_effect(&wrong));
}
#[test]
fn selected_native_receipt_and_real_bytes_match_or_refuse() {
    let r = request(false);
    let o = outcome("stored");
    assert!(o.receipt(&r).is_ok());
    assert!(r.verify_body(&vec![b'A'; 4096]).is_ok());
    assert!(r.verify_body(&vec![b'B'; 4096]).is_err());
    let mut v = fixture()["stored"].clone();
    v["object_receipt"]["objectRevision"] = json!("00000000-0000-4000-8000-000000000099");
    assert!(Outcome::parse(&serde_json::to_vec(&v).unwrap())
        .unwrap()
        .receipt(&r)
        .is_err());
}
#[test]
fn cancelled_resource_binds_exact_generation_parts_and_native_cleaned_set() {
    let r = request(true);
    let c = cancelled();
    assert!(c.verify_cleaned(&r, &outcome("cleaned")).is_ok());
    let original = fixture()["cleanup_resolution"]["grant"]["resource"].clone();
    for field in ["intent_id", "owner_outcome_id"] {
        let mut v = original.clone();
        v[field] = json!("invalid");
        assert!(CancelledResource::parse(&serde_json::to_vec(&v).unwrap(), &r).is_err());
    }
    for field in ["terminal_intent_revision", "cancellation_generation"] {
        let mut v = original.clone();
        v[field] = json!(99);
        assert!(CancelledResource::parse(&serde_json::to_vec(&v).unwrap(), &r).is_err());
    }
    let mut v = original.clone();
    v["part_ids"] = json!([]);
    assert!(CancelledResource::parse(&serde_json::to_vec(&v).unwrap(), &r).is_err());
    let mut v = fixture()["cleaned"].clone();
    v["cleaned_objects"][0]["object_revision"] = json!("00000000-0000-4000-8000-000000000099");
    assert!(c
        .verify_cleaned(
            &r,
            &Outcome::parse(&serde_json::to_vec(&v).unwrap()).unwrap()
        )
        .is_err());
}

struct Spy {
    startup: Cell<bool>,
    effect: Cell<bool>,
    mode: Cell<u8>,
    events: RefCell<Vec<&'static str>>,
}
impl Spy {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            startup: Cell::new(false),
            effect: Cell::new(false),
            mode: Cell::new(0),
            events: RefCell::new(vec![]),
        })
    }
    fn io(&self, s: &'static str) {
        assert!(self.startup.get() && self.effect.get());
        self.events.borrow_mut().push(s);
    }
}
struct Hold<'a>(&'a Cell<bool>);
impl Drop for Hold<'_> {
    fn drop(&mut self) {
        self.0.set(false)
    }
}
struct TestControl(Rc<Spy>);
impl Control for TestControl {
    type StartupLease = ();
    type EffectLease = ();
    fn with_startup<T>(
        &self,
        expected: &DeploymentBinding,
        _: &ProtectedConfigReferences,
        action: impl FnOnce((), DeploymentBinding) -> Result<T>,
    ) -> Result<T> {
        self.0.startup.set(true);
        let _h = Hold(&self.0.startup);
        let mut observed = expected.clone();
        if self.0.mode.get() == 1 {
            observed.key_domain_ref = "wrong".into();
        }
        action((), observed)
    }
    fn with_effect<T>(
        &self,
        _: &(),
        r: &Request,
        op: Operation,
        action: impl FnOnce((), LeaseBinding) -> Result<T>,
    ) -> Result<T> {
        self.0.effect.set(true);
        let _h = Hold(&self.0.effect);
        let mut b = LeaseBinding {
            deployment: deployment(),
            descriptor_identity: r.descriptor_identity(),
            resource_identity: r.resource_identity(),
            operation: op,
        };
        match self.0.mode.get() {
            2 => b.descriptor_identity = "wrong".into(),
            3 => b.resource_identity = "other-part".into(),
            4 => b.operation = Operation::Status,
            _ => {}
        }
        action((), b)
    }
    fn cancelled_resource(&self, _: &(), _: &Request) -> Result<Vec<u8>> {
        self.0.io("cancelled");
        Ok(serde_json::to_vec(&fixture()["cleanup_resolution"]["grant"]["resource"]).unwrap())
    }
    fn durable_binding(&self, _: &(), _: &Request, o: &Outcome) -> Result<DurableBinding> {
        self.0.io("provenance");
        let mut b = DurableBinding {
            original_effect: original(o),
            storage_receipt_id: o.storage_receipt_id().unwrap().into(),
        };
        if self.0.mode.get() == 5 {
            b.storage_receipt_id = "wrong".into();
        }
        Ok(b)
    }
    fn cleaned_binding(&self, _: &(), _: &Request, o: &Outcome) -> Result<OriginalEffect> {
        self.0.io("cleaned-provenance");
        Ok(original(o))
    }
    fn register_original_outcome(&self, _: &(), _: &Request, _: &Outcome) -> Result<()> {
        self.0.io("register");
        if self.0.mode.get() == 6 {
            Err(Refusal::Pending)
        } else {
            Ok(())
        }
    }
}
struct Backend(Rc<Spy>);
impl NativeBackend<crate::parent_authority::Effect<()>> for Backend {
    fn observe(
        &self,
        _: &crate::parent_authority::Effect<()>,
        r: &Request,
    ) -> Result<Observation<(), Outcome>> {
        self.0.io("observe");
        if r.selected.is_none() {
            Ok(Observation::Unseen)
        } else {
            Ok(Observation::Durable {
                receipt: (),
                outcome: outcome("stored"),
            })
        }
    }
    fn stage(
        &self,
        _: &crate::parent_authority::Effect<()>,
        _: &Request,
        _: &[u8],
    ) -> Result<Option<Outcome>> {
        panic!("durable retry must not restage")
    }
    fn read_exact(
        &self,
        _: &crate::parent_authority::Effect<()>,
        _: &Request,
        max: usize,
    ) -> Result<Vec<u8>> {
        self.0.io("read");
        assert_eq!(max, 4096);
        Ok(vec![if self.0.mode.get() == 7 { b'B' } else { b'A' }; 4096])
    }
    fn tombstone_exact(
        &self,
        _: &crate::parent_authority::Effect<()>,
        r: &Request,
        objects: &[ObjectKey],
        c: &CancelledResource,
    ) -> Result<()> {
        self.0.io("tombstone");
        assert_eq!(objects.len(), 1);
        assert!(c.validate(r).is_ok());
        Ok(())
    }
    fn cleanup_exact(
        &self,
        _: &crate::parent_authority::Effect<()>,
        _: &Request,
        objects: &[ObjectKey],
        _: &CancelledResource,
    ) -> Result<Option<Outcome>> {
        self.0.io("unlink");
        assert_eq!(
            objects[0].object_id(),
            fixture()["descriptor"]["parts"][0]["objectId"]
                .as_str()
                .unwrap()
        );
        Ok(Some(outcome("cleaned")))
    }
}
fn parent(
    s: &Rc<Spy>,
) -> Parent<NativeContract, NativeAuthority<TestControl>, NativeStorage<Backend>> {
    Parent::compose(
        NativeAuthority(TestControl(s.clone())),
        NativeStorage(Backend(s.clone())),
    )
}
#[test]
fn concrete_native_adapters_bind_before_actual_readback_and_registration() {
    let s = Spy::new();
    let p = parent(&s);
    assert!(p
        .write_or_reconcile(&deployment(), &references(), &request(false), || Ok(
            vec![b'A'; 4096]
        ))
        .is_ok());
    assert_eq!(
        *s.events.borrow(),
        vec!["observe", "provenance", "read", "register"]
    );
    assert!(!s.startup.get() && !s.effect.get());
    for mode in 1..=4 {
        s.events.borrow_mut().clear();
        s.mode.set(mode);
        assert!(p
            .verify_exact_readback(&deployment(), &references(), &request(false))
            .is_err());
        assert!(s.events.borrow().is_empty());
    }
}
#[test]
fn native_receipt_mismatch_and_altered_real_body_cannot_return_success() {
    for mode in [5, 7] {
        let s = Spy::new();
        s.mode.set(mode);
        assert!(parent(&s)
            .write_or_reconcile(&deployment(), &references(), &request(false), || Ok(
                vec![b'A'; 4096]
            ))
            .is_err());
        assert!(!s.events.borrow().contains(&"register"));
    }
    let s = Spy::new();
    s.mode.set(6);
    assert!(matches!(
        parent(&s).write_or_reconcile(&deployment(), &references(), &request(false), || Ok(
            vec![b'A'; 4096]
        )),
        Err(Refusal::Pending)
    ));
}
#[test]
fn concrete_cleanup_uses_only_authenticated_exact_native_object_set() {
    let s = Spy::new();
    assert!(parent(&s)
        .cleanup(&deployment(), &references(), &request(true))
        .is_ok());
    assert_eq!(
        *s.events.borrow(),
        vec![
            "cancelled",
            "observe",
            "tombstone",
            "unlink",
            "cleaned-provenance",
            "register"
        ]
    );
}

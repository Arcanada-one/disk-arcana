//! Concrete native field-binding adapter around admitted control-plane IO.
//! The injected Control owns authentication, mount observation and lease/fence
//! liveness. This adapter checks exact subject bindings; it is never registered
//! by default and accepts no browser-supplied verifier or evidence boolean.
use crate::parent_adapter::{Authority, Operation, Refusal, Result};
use crate::parent_native::{
    CancelledResource, DeploymentBinding, NativeContract, OriginalEffect, Outcome,
    ProtectedConfigReferences, Receipt, Request,
};

/// Internal authenticated observation, not a new network record/schema. It must
/// be derived by Control from native Auth resolution, NOT from HTTP request JSON.
pub struct LeaseBinding {
    pub deployment: DeploymentBinding,
    pub descriptor_identity: String,
    pub resource_identity: String,
    pub operation: Operation,
}
pub struct DurableBinding {
    pub original_effect: OriginalEffect,
    pub storage_receipt_id: String,
}

/// Actual provisioner/Auth transport seam. Both callbacks are scoped: retain
/// authenticated startup and effect/revocation guards until callback returns.
/// References select protected credentials, not proof. Absence refuses without
/// fallback. Recovery uses original-effect readback, never current-generation
/// rewriting. No supplied implementation means no production composition.
pub trait Control {
    type StartupLease;
    type EffectLease;
    fn with_startup<T>(
        &self,
        expected: &DeploymentBinding,
        refs: &ProtectedConfigReferences,
        action: impl FnOnce(Self::StartupLease, DeploymentBinding) -> Result<T>,
    ) -> Result<T>;
    fn with_effect<T>(
        &self,
        startup: &Self::StartupLease,
        request: &Request,
        operation: Operation,
        action: impl FnOnce(Self::EffectLease, LeaseBinding) -> Result<T>,
    ) -> Result<T>;
    /// Native Product cancelled-resource bytes derived from authenticated
    /// registered outcome and current capture fence. Never a caller's proof.
    fn cancelled_resource(&self, effect: &Self::EffectLease, request: &Request) -> Result<Vec<u8>>;
    fn durable_binding(
        &self,
        effect: &Self::EffectLease,
        request: &Request,
        outcome: &Outcome,
    ) -> Result<DurableBinding>;
    fn cleaned_binding(
        &self,
        effect: &Self::EffectLease,
        request: &Request,
        outcome: &Outcome,
    ) -> Result<OriginalEffect>;
    fn register_original_outcome(
        &self,
        effect: &Self::EffectLease,
        request: &Request,
        outcome: &Outcome,
    ) -> Result<()>;
}
/// No Clone/Deserialize/public constructor on live context wrappers.
pub struct Startup<L> {
    lease: L,
    observed: DeploymentBinding,
}
pub struct Effect<L> {
    lease: L,
    operation: Operation,
    descriptor_identity: String,
    resource_identity: String,
}
pub struct NativeAuthority<P>(pub P);

impl<P: Control> Authority<NativeContract> for NativeAuthority<P> {
    type Startup = Startup<P::StartupLease>;
    type Effect = Effect<P::EffectLease>;
    type Cancellation = CancelledResource;
    fn with_startup<T>(
        &self,
        d: &DeploymentBinding,
        refs: &ProtectedConfigReferences,
        action: impl FnOnce(&Self::Startup) -> Result<T>,
    ) -> Result<T> {
        if !d.selection_valid()
            || refs.provisioner_reference.is_empty()
            || refs.auth_reference.is_empty()
        {
            return Err(Refusal::Unavailable);
        }
        self.0.with_startup(d, refs, |lease, observed| {
            if observed != *d {
                return Err(Refusal::Unavailable);
            }
            action(&Startup { lease, observed })
        })
    }
    fn with_effect<T>(
        &self,
        s: &Self::Startup,
        r: &Request,
        op: Operation,
        action: impl FnOnce(&Self::Effect) -> Result<T>,
    ) -> Result<T> {
        if r.realm() != s.observed.realm() || !r.accepts_operation(op) {
            return Err(Refusal::NotAvailable);
        }
        self.0.with_effect(&s.lease, r, op, |lease, binding| {
            if binding.deployment != s.observed
                || binding.descriptor_identity != r.descriptor_identity()
                || binding.resource_identity != r.resource_identity()
                || binding.operation != op
            {
                return Err(Refusal::NotAvailable);
            }
            action(&Effect {
                lease,
                operation: op,
                descriptor_identity: binding.descriptor_identity,
                resource_identity: binding.resource_identity,
            })
        })
    }
    fn cancelled(&self, e: &Self::Effect, r: &Request) -> Result<CancelledResource> {
        e.matches(r, Operation::CleanupCancelled)?;
        CancelledResource::parse(&self.0.cancelled_resource(&e.lease, r)?, r)
    }
    fn verify_durable(
        &self,
        e: &Self::Effect,
        r: &Request,
        receipt: &Receipt,
        outcome: &Outcome,
    ) -> Result<()> {
        if !matches!(e.operation, Operation::Stage | Operation::Verify) {
            return Err(Refusal::NotAvailable);
        }
        e.same_request(r)?;
        outcome.verify_receipt(r, receipt)?;
        let expected = self.0.durable_binding(&e.lease, r, outcome)?;
        if !outcome.matches_original_effect(&expected.original_effect)
            || outcome.storage_receipt_id() != Some(expected.storage_receipt_id.as_str())
        {
            return Err(Refusal::NotAvailable);
        }
        Ok(())
    }
    fn register_outcome(&self, e: &Self::Effect, r: &Request, outcome: &Outcome) -> Result<()> {
        e.same_request(r)?;
        if !outcome.matches_operation(e.operation) {
            return Err(Refusal::NotAvailable);
        }
        self.0.register_original_outcome(&e.lease, r, outcome)
    }
    fn verify_cleaned(
        &self,
        e: &Self::Effect,
        r: &Request,
        c: &CancelledResource,
        o: &Outcome,
    ) -> Result<()> {
        e.matches(r, Operation::CleanupCancelled)?;
        c.verify_cleaned(r, o)?;
        let expected = self.0.cleaned_binding(&e.lease, r, o)?;
        if !o.matches_original_effect(&expected) {
            return Err(Refusal::NotAvailable);
        }
        Ok(())
    }
}
impl<L> Effect<L> {
    fn same_request(&self, r: &Request) -> Result<()> {
        if self.descriptor_identity != r.descriptor_identity()
            || self.resource_identity != r.resource_identity()
        {
            return Err(Refusal::NotAvailable);
        }
        Ok(())
    }
    fn matches(&self, r: &Request, op: Operation) -> Result<()> {
        self.same_request(r)?;
        if self.operation != op {
            return Err(Refusal::NotAvailable);
        }
        Ok(())
    }
    /// Backend adapters receive a borrowed authenticated lease, never a public
    /// grant serialization. Its Control callback must still be live.
    #[cfg(target_os = "linux")]
    pub(crate) fn require_backend_operation(
        &self,
        r: &Request,
        operation: Operation,
    ) -> Result<()> {
        self.matches(r, operation)
    }
    pub fn native_lease(&self) -> &L {
        &self.lease
    }
}

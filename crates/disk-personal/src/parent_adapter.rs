//! Disabled parent orchestration for strict-disk/1-proposed.
//!
//! Ports are trusted composition dependencies, NOT caller-supplied capabilities.
//! No implementation here opens storage, verifies an issuer, or grants authority.
//! Native wire types remain associated types so this module cannot silently invent
//! a second receipt, request fingerprint, or Product terminal-outcome protocol.

/// Content-free internal disposition. Unknown effects must be reconciled using
/// their original identity; neither Pending nor Unavailable authorizes retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotAvailable,
    Pending,
    Conflict,
    Backpressure,
    Unavailable,
}
pub type Result<T> = std::result::Result<T, Refusal>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Stage,
    Verify,
    Status,
    CleanupCancelled,
}

/// Internal projection of the native inventory, not a serialized wire outcome.
/// Missing rows and PREPARED are deliberately distinct from fenced no-commit.
pub enum Observation<R, O> {
    Unseen,
    Prepared,
    Durable { receipt: R, outcome: O },
    CleanupPending,
    CancelledCleaned { outcome: O },
    Corrupt,
    Unknown,
}

/// An adapter returns Committed only after its complete durable transaction and
/// directory synchronization, never after enqueueing background work.
pub enum Commit<R, O> {
    Committed { receipt: R, outcome: O },
    Unknown,
}

/// Exact native decoded types supplied by the owning wire adapter. Implementors
/// are trusted server composition, never deserialized dependency injection.
pub trait Contract {
    type Deployment;
    type ConfigReferences;
    type Request;
    type Receipt;
    type Outcome;
}

/// Real implementations must validate deployment/executable/config generation,
/// realm/account ownership, encrypted mount/key domain BEFORE invoking action.
/// The nonserializable Startup value and its revocation exclusion live through
/// the WHOLE callback. A path, boolean or synthetic02F handle is not a verifier.
pub trait Authority<C: Contract> {
    type Startup;
    type Effect;
    type Cancellation;

    fn with_startup<T>(
        &self,
        deployment: &C::Deployment,
        config: &C::ConfigReferences,
        action: impl FnOnce(&Self::Startup) -> Result<T>,
    ) -> Result<T>;

    /// Resolve the native Auth grant, peer, exact descriptor/resource/attempt,
    /// purpose/audience, epoch/generation and validity. Keep the common capture
    /// fence and revocation exclusion until action AND its durable commit return.
    /// No check-then-release or asynchronous fire-and-forget callback is valid.
    fn with_effect<T>(
        &self,
        startup: &Self::Startup,
        request: &C::Request,
        operation: Operation,
        action: impl FnOnce(&Self::Effect) -> Result<T>,
    ) -> Result<T>;

    /// Authenticate Product's registered terminal cancellation, full descriptor,
    /// generation+1, intent revision and exact1..2-object set. The proof must
    /// exclude a publication winner under the SAME fence held by with_effect.
    fn cancelled(&self, effect: &Self::Effect, request: &C::Request) -> Result<Self::Cancellation>;

    /// Compare complete native outcome/receipt and historical producer lineage
    /// with Auth and the request; never mint a receipt from a LocalCommit.
    fn verify_durable(
        &self,
        effect: &Self::Effect,
        request: &C::Request,
        receipt: &C::Receipt,
        outcome: &C::Outcome,
    ) -> Result<()>;

    /// Register/reconcile the ORIGINAL native owner outcome idempotently. Lost
    /// acknowledgment remains Pending. Must not relabel old participant lineage.
    /// This is control-plane registration, not permission to release private data.
    fn register_outcome(
        &self,
        effect: &Self::Effect,
        request: &C::Request,
        outcome: &C::Outcome,
    ) -> Result<()>;

    fn verify_cleaned(
        &self,
        effect: &Self::Effect,
        request: &C::Request,
        cancelled: &Self::Cancellation,
        outcome: &C::Outcome,
    ) -> Result<()>;
}

/// Trusted durable storage port. All methods receive the live Auth context.
/// No implementation for the synthetic foundation exists intentionally: its
/// exclusive-root SQLite mechanics are not a production VFS or wire journal.
pub trait Storage<C: Contract, A: Authority<C>> {
    /// Transactionally inspect/reconcile the ORIGINAL attempt under its fence.
    /// Unknown cannot become Unseen merely because a row/outbox is absent.
    fn observe(
        &self,
        effect: &A::Effect,
        request: &C::Request,
    ) -> Result<Observation<C::Receipt, C::Outcome>>;

    /// Validate submitted bytes even on a durable retry; no mutation permitted.
    fn verify_body(&self, effect: &A::Effect, request: &C::Request, body: &[u8]) -> Result<()>;

    /// Validate exact length/digest/UTF8 and immutable allocation before writing.
    /// Reserve original identity before effects; commit bytes/inventory/journal
    /// atomically according to native contract. Identical retry preserves IDs.
    fn stage(
        &self,
        effect: &A::Effect,
        request: &C::Request,
        body: &[u8],
    ) -> Result<Commit<C::Receipt, C::Outcome>>;

    /// Verify authenticated native receipt identity AND actual bytes, length,
    /// digest, realm, resource, version, attempt and cancellation generation.
    /// Must not merely validate caller-provided receipt shape or cached metadata.
    fn verify_exact_readback(
        &self,
        effect: &A::Effect,
        request: &C::Request,
        receipt: &C::Receipt,
    ) -> Result<()>;

    /// Durably tombstone the exact authenticated object set BEFORE unlink. Keep
    /// historical D receipts; no directory/prefix deletion or guessed absence.
    fn tombstone(
        &self,
        effect: &A::Effect,
        request: &C::Request,
        cancelled: &A::Cancellation,
    ) -> Result<()>;

    /// Reconcile/finish only the already tombstoned set, sync directories and
    /// journal disk_cleaned. None means uncertain; never infer completed unlink.
    fn finish_cleanup(
        &self,
        effect: &A::Effect,
        request: &C::Request,
        cancelled: &A::Cancellation,
    ) -> Result<Option<C::Outcome>>;
}

/// Parent service logic. It is NOT registered in main.rs or a network router.
/// Results are internal observations, not publicly releasable wire frames.
pub struct Parent<C, A, S> {
    authority: A,
    storage: S,
    contract: std::marker::PhantomData<C>,
}

impl<C: Contract, A: Authority<C>, S: Storage<C, A>> Parent<C, A, S> {
    pub fn compose(authority: A, storage: S) -> Self {
        Self {
            authority,
            storage,
            contract: std::marker::PhantomData,
        }
    }

    fn authorized<T>(
        &self,
        deployment: &C::Deployment,
        config: &C::ConfigReferences,
        request: &C::Request,
        operation: Operation,
        action: impl FnOnce(&A::Effect) -> Result<T>,
    ) -> Result<T> {
        self.authority.with_startup(deployment, config, |startup| {
            self.authority
                .with_effect(startup, request, operation, action)
        })
    }

    fn confirmed(
        &self,
        effect: &A::Effect,
        request: &C::Request,
        receipt: C::Receipt,
        outcome: C::Outcome,
    ) -> Result<C::Outcome> {
        self.authority
            .verify_durable(effect, request, &receipt, &outcome)?;
        self.storage
            .verify_exact_readback(effect, request, &receipt)?;
        self.authority.register_outcome(effect, request, &outcome)?;
        Ok(outcome)
    }

    /// Body hydration occurs only inside BOTH trusted startup and Auth fences.
    /// No automatic retry on Prepared/Unknown, including after process restart.
    pub fn write_or_reconcile(
        &self,
        deployment: &C::Deployment,
        config: &C::ConfigReferences,
        request: &C::Request,
        body: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<C::Outcome> {
        self.authorized(
            deployment,
            config,
            request,
            Operation::Stage,
            |effect| match self.storage.observe(effect, request)? {
                Observation::Durable { receipt, outcome } => {
                    let bytes = body()?;
                    if bytes.len() > 1_048_576 {
                        return Err(Refusal::NotAvailable);
                    }
                    self.storage.verify_body(effect, request, &bytes)?;
                    self.confirmed(effect, request, receipt, outcome)
                }
                Observation::Unseen => {
                    let bytes = body()?;
                    if bytes.len() > 1_048_576 {
                        return Err(Refusal::NotAvailable);
                    }
                    self.storage.verify_body(effect, request, &bytes)?;
                    match self.storage.stage(effect, request, &bytes)? {
                        Commit::Committed { receipt, outcome } => {
                            self.confirmed(effect, request, receipt, outcome)
                        }
                        Commit::Unknown => Err(Refusal::Pending),
                    }
                }
                Observation::Prepared | Observation::Unknown => Err(Refusal::Pending),
                Observation::CleanupPending | Observation::CancelledCleaned { .. } => {
                    Err(Refusal::Conflict)
                }
                Observation::Corrupt => Err(Refusal::Unavailable),
            },
        )
    }

    pub fn verify_exact_readback(
        &self,
        deployment: &C::Deployment,
        config: &C::ConfigReferences,
        request: &C::Request,
    ) -> Result<C::Outcome> {
        self.authorized(
            deployment,
            config,
            request,
            Operation::Verify,
            |effect| match self.storage.observe(effect, request)? {
                Observation::Durable { receipt, outcome } => {
                    self.authority
                        .verify_durable(effect, request, &receipt, &outcome)?;
                    self.storage
                        .verify_exact_readback(effect, request, &receipt)?;
                    Ok(outcome)
                }
                Observation::Unseen => Err(Refusal::NotAvailable),
                Observation::Prepared | Observation::Unknown => Err(Refusal::Pending),
                Observation::Corrupt => Err(Refusal::Unavailable),
                _ => Err(Refusal::NotAvailable),
            },
        )
    }

    /// Status is protected too: absent rows are not authenticated no-commit.
    pub fn status(
        &self,
        deployment: &C::Deployment,
        config: &C::ConfigReferences,
        request: &C::Request,
    ) -> Result<Observation<C::Receipt, C::Outcome>> {
        self.authorized(deployment, config, request, Operation::Status, |effect| {
            self.storage.observe(effect, request)
        })
    }

    pub fn cleanup(
        &self,
        deployment: &C::Deployment,
        config: &C::ConfigReferences,
        request: &C::Request,
    ) -> Result<C::Outcome> {
        self.authorized(
            deployment,
            config,
            request,
            Operation::CleanupCancelled,
            |effect| {
                // Authenticate terminal cancellation before even reading inventory.
                let cancelled = self.authority.cancelled(effect, request)?;
                let outcome = match self.storage.observe(effect, request)? {
                    Observation::Unknown | Observation::Prepared => return Err(Refusal::Pending),
                    Observation::Corrupt => return Err(Refusal::Unavailable),
                    Observation::CancelledCleaned { outcome } => outcome,
                    Observation::Unseen
                    | Observation::Durable { .. }
                    | Observation::CleanupPending => {
                        self.storage.tombstone(effect, request, &cancelled)?;
                        self.storage
                            .finish_cleanup(effect, request, &cancelled)?
                            .ok_or(Refusal::Pending)?
                    }
                };
                self.authority
                    .verify_cleaned(effect, request, &cancelled, &outcome)?;
                self.authority.register_outcome(effect, request, &outcome)?;
                Ok(outcome)
            },
        )
    }
}

/// Default composition rejects before invoking any application callback.
/// It cannot produce startup/effect/cancellation handles.
pub enum Never {}
pub struct UnavailableAuthority;
impl<C: Contract> Authority<C> for UnavailableAuthority {
    type Startup = Never;
    type Effect = Never;
    type Cancellation = Never;
    fn with_startup<T>(
        &self,
        _: &C::Deployment,
        _: &C::ConfigReferences,
        _: impl FnOnce(&Never) -> Result<T>,
    ) -> Result<T> {
        Err(Refusal::Unavailable)
    }
    fn with_effect<T>(
        &self,
        _: &Never,
        _: &C::Request,
        _: Operation,
        _: impl FnOnce(&Never) -> Result<T>,
    ) -> Result<T> {
        Err(Refusal::Unavailable)
    }
    fn cancelled(&self, _: &Never, _: &C::Request) -> Result<Never> {
        Err(Refusal::Unavailable)
    }
    fn verify_durable(
        &self,
        _: &Never,
        _: &C::Request,
        _: &C::Receipt,
        _: &C::Outcome,
    ) -> Result<()> {
        Err(Refusal::Unavailable)
    }
    fn register_outcome(&self, _: &Never, _: &C::Request, _: &C::Outcome) -> Result<()> {
        Err(Refusal::Unavailable)
    }
    fn verify_cleaned(&self, _: &Never, _: &C::Request, _: &Never, _: &C::Outcome) -> Result<()> {
        Err(Refusal::Unavailable)
    }
}

#[cfg(test)]
#[path = "parent_adapter_tests.rs"]
mod tests;

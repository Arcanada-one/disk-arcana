//! HTTP handlers for `/onboarding` (DISK-0025 slice 3).

pub mod routes;

pub use routes::{get_onboarding, put_onboarding};

//! Agent webhook signing helpers (DISK-0028).

pub mod webhook_sig;

pub use webhook_sig::{
    compute_disk_webhook_signature, format_disk_signature_header, verify_disk_webhook_signature,
    DiskWebhookSigError,
};

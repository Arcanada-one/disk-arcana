//! Generated protobuf bindings for Disk Arcana.
//!
//! Re-exports the `disk` package produced by `build.rs` so consumers can import
//! `disk_proto::FileMetadata` etc. without referencing tonic-build internals.

#![forbid(unsafe_code)]

pub mod disk {
    tonic::include_proto!("disk");
}

pub use disk::*;

#[cfg(test)]
mod tests {
    use super::disk::FileMetadata;
    use prost::Message;

    #[test]
    fn schema_roundtrip_all_fields() {
        let original = FileMetadata {
            path: "vault/note.md".into(),
            content_hash: vec![1, 2, 3, 4],
            size: 1024,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: 42,
            vector_clock: [("nodeA".into(), 7u64)].into_iter().collect(),
            deleted: false,
            deleted_at: 0,
            node_id: "nodeA".into(),
            encryption_nonce: b"abc".to_vec(),
            tenant_id: "t1".into(),
            vault_id: "default".into(),
            user_id: "user-1".into(),
            version_id: 42,
            parent_version_id: 41,
        };
        let bytes = original.encode_to_vec();
        let decoded = FileMetadata::decode(bytes.as_slice()).expect("decode");
        assert_eq!(original, decoded);
    }

    #[test]
    fn schema_forward_compat_unknown_fields_ignored() {
        // Encode a FileMetadata with values, then prepend a junk field
        // (tag 99, varint) and ensure decode succeeds (proto3 ignores unknown tags).
        let original = FileMetadata {
            path: "x".into(),
            content_hash: vec![],
            size: 0,
            mtime_ns: 0,
            inode: 0,
            vector_clock: Default::default(),
            deleted: false,
            deleted_at: 0,
            node_id: String::new(),
            encryption_nonce: vec![],
            tenant_id: String::new(),
            vault_id: String::new(),
            user_id: String::new(),
            version_id: 0,
            parent_version_id: 0,
        };
        let mut bytes = original.encode_to_vec();
        // Append unknown varint field tag=99 (wire type 0): tag = (99 << 3) | 0 = 792.
        // Encode as two-byte varint: 0x98 0x06 then value 0x01.
        bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
        let decoded = FileMetadata::decode(bytes.as_slice()).expect("decode tolerates unknown");
        assert_eq!(decoded, original);
    }
}

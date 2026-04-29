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
    use super::disk::*;
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
        let original = FileMetadata {
            path: "x".into(),
            ..Default::default()
        };
        let mut bytes = original.encode_to_vec();
        // Append unknown varint field tag=99 (wire type 0): tag = (99 << 3) | 0 = 792.
        // Encode as two-byte varint: 0x98 0x06 then value 0x01.
        bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
        let decoded = FileMetadata::decode(bytes.as_slice()).expect("decode tolerates unknown");
        assert_eq!(decoded, original);
    }

    // Phase 3 new message roundtrips (DISK-0004)

    #[test]
    fn node_auth_request_roundtrip() {
        let msg = NodeAuthRequest {
            node_id: "node-abc".into(),
            api_key: "arc_disk_AAABBBCCC".into(),
        };
        let decoded = NodeAuthRequest::decode(msg.encode_to_vec().as_slice()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn node_auth_response_roundtrip() {
        let msg = NodeAuthResponse {
            session_token: "arc_disk_sess_XYZ".into(),
            expires_at: 9_999_999_999,
        };
        let decoded = NodeAuthResponse::decode(msg.encode_to_vec().as_slice()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn sync_state_ack_roundtrip() {
        let msg = SyncStateAck {
            session_token: "tok".into(),
            sequence_id: 42,
        };
        let decoded = SyncStateAck::decode(msg.encode_to_vec().as_slice()).unwrap();
        assert_eq!(msg.session_token, decoded.session_token);
        assert_eq!(msg.sequence_id, decoded.sequence_id);
    }

    #[test]
    fn delta_download_request_roundtrip() {
        let msg = DeltaDownloadRequest {
            path: "notes/a.md".into(),
            expected_hash: vec![0xde, 0xad, 0xbe, 0xef],
            tenant_id: "t1".into(),
            vault_id: "default".into(),
        };
        let decoded = DeltaDownloadRequest::decode(msg.encode_to_vec().as_slice()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn delta_chunk_roundtrip() {
        let msg = DeltaChunk {
            offset: 4096,
            weak_checksum: 0xdeadbeef,
            strong_hash: vec![0u8; 32],
            data: b"hello world".to_vec(),
        };
        let decoded = DeltaChunk::decode(msg.encode_to_vec().as_slice()).unwrap();
        assert_eq!(msg, decoded);
    }
}

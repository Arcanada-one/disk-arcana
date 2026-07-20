//! Fuzz protobuf decoders for wire messages — must tolerate arbitrary bytes
//! without panic (graceful `Err` only).

#![no_main]

use disk_proto::{
    DeltaChunk, DeltaDownloadRequest, FileMetadata, NodeAuthRequest, NodeAuthResponse,
    SyncStateAck,
};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let _ = FileMetadata::decode(data);
    let _ = NodeAuthRequest::decode(data);
    let _ = NodeAuthResponse::decode(data);
    let _ = SyncStateAck::decode(data);
    let _ = DeltaDownloadRequest::decode(data);
    let _ = DeltaChunk::decode(data);
});

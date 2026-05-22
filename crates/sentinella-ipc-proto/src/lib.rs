//! Sentinella IPC Protocol — JSON-RPC 2.0 typed contract.
//!
//! This crate defines every request, response, notification, and error
//! that crosses the GUI ↔ daemon ↔ CLI boundary. It is the single
//! source of truth for the IPC schema.
//!
//! # Framing
//!
//! Over the wire, each message is a **4-byte big-endian length prefix**
//! followed by a UTF-8 JSON object. Max frame size: 16 MiB.
//!
//! # Versioning
//!
//! The protocol version is negotiated via `engine.status` — the
//! `protocol_version` field. Breaking changes bump the major version.

pub mod engine;
pub mod scan;
pub mod quarantine;
pub mod watcher;
pub mod update;
pub mod settings;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─── JSON-RPC 2.0 envelope ──────────────────────────────────────

pub const JSONRPC_VERSION: &str = "2.0";
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// A JSON-RPC 2.0 request (client → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
}

/// A JSON-RPC 2.0 success response (server → client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Value,
}

/// A JSON-RPC 2.0 error response (server → client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcErrorResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub error: RpcError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

/// A JSON-RPC 2.0 notification (server → client, no id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
}

// ─── Error codes ─────────────────────────────────────────────────

/// Standard JSON-RPC error codes.
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    /// Application-specific error codes.
    pub const ENGINE_NOT_READY: i32 = -32000;
    pub const INVALID_PATH: i32 = -32001;
    pub const JOB_NOT_FOUND: i32 = -32002;
    pub const QUARANTINE_NOT_FOUND: i32 = -32003;
    pub const UPDATE_ALREADY_RUNNING: i32 = -32004;
    pub const INSUFFICIENT_PRIVILEGE: i32 = -32005;
    pub const DATABASE_CORRUPTED: i32 = -32010;
    pub const ENGINE_OOM: i32 = -32011;
}

// ─── Helper constructors ─────────────────────────────────────────

impl RpcResponse {
    pub fn ok(id: u64, result: impl Serialize) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.into(),
            id,
            result: serde_json::to_value(result).unwrap_or(Value::Null),
        }
    }
}

impl RpcErrorResponse {
    pub fn err(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.into(),
            id,
            error: RpcError {
                code,
                message: message.into(),
                data: Value::Null,
            },
        }
    }
}

impl RpcNotification {
    pub fn new(method: impl Into<String>, params: impl Serialize) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.into(),
            method: method.into(),
            params: serde_json::to_value(params).unwrap_or(Value::Null),
        }
    }
}

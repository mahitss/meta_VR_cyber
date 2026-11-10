//! Data models for the security-engine WASM contract.
//!
//! These types define the versioned JSON request/response boundary between
//! the TypeScript client and the Rust simulation engine. All fields are
//! strictly typed and validated; the engine performs authoritative validation.

use serde::{Deserialize, Serialize};

/// The current contract version supported by the security engine.
pub const CONTRACT_VERSION: &str = "1.0";

/// A request ID must be a non-empty ASCII string.
pub fn validate_request_id(s: &str) -> bool {
    !s.is_empty() && s.is_ascii() && s.len() <= 256
}

/// Health-check request.
///
/// Contract version 1.0.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthRequest {
    /// Must be exactly "1.0".
    pub contract_version: String,
    /// Non-empty ASCII identifier, max 256 characters.
    pub request_id: String,
}

/// Health-check response.
///
/// Contract version 1.0.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Echo of the request contract version.
    pub contract_version: String,
    /// Echo of the request ID.
    pub request_id: String,
    /// Engine identifier.
    pub engine: String,
    /// Status of the health check.
    pub status: String,
}

/// Error returned by the engine for invalid input.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EngineError {
    /// A stable error code.
    pub code: String,
    /// Human-readable description.
    pub message: String,
}

/// Supported engine operations.
///
/// Reserved for future operations beyond the M002 health check.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "operation", content = "payload")]
pub enum EngineOperation {
    #[serde(rename = "health")]
    Health,
}

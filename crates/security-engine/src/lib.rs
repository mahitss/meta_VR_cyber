//! NetVigil XR Security Engine — WebAssembly library.
//!
//! This crate exposes a versioned JSON contract to the TypeScript XR client
//! via wasm-bindgen. Core business logic is pure and independently testable.
//!
//! Contract v1.0:
//!   Request:  { "contract_version": "1.0", "request_id": "<string>" }
//!   Response: { "contract_version": "1.0", "request_id": "<string>",
//!               "engine": "security-engine", "status": "ok" }
//!
//! Invalid inputs produce explicit JSON errors, never panics.

use wasm_bindgen::prelude::*;
pub mod models;
pub mod validation;

pub use models::{EngineError, HealthRequest, HealthResponse};
pub use validation::validate_health_request;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator. This is optional and commented out by default.
// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Raw JSON health request handler exported to JavaScript.
///
/// Accepts a JSON string, validates it strictly, and returns a JSON string.
/// Invalid input produces an error JSON object, never a Rust panic.
#[wasm_bindgen]
pub fn health_check_json(input: &str) -> String {
    match health_check_json_inner(input) {
        Ok(response) => response,
        Err(error) => serde_json::to_string(&error).unwrap_or_else(|_| {
            r#"{"code":"INTERNAL_ERROR","message":"failed to serialize error"}"#.to_string()
        }),
    }
}

/// Inner implementation returning `Result<String, EngineError>`.
fn health_check_json_inner(input: &str) -> Result<String, EngineError> {
    let request: HealthRequest = serde_json::from_str(input).map_err(|e| EngineError {
        code: validation::codes::MALFORMED_JSON.to_string(),
        message: format!("invalid JSON: {}", e),
    })?;

    validate_health_request(&request.contract_version, &request.request_id)
        .map_err(|(code, message)| EngineError { code, message })?;

    let response = HealthResponse {
        contract_version: request.contract_version,
        request_id: request.request_id,
        engine: "security-engine".to_string(),
        status: "ok".to_string(),
    };

    serde_json::to_string(&response).map_err(|e| EngineError {
        code: "INTERNAL_ERROR".to_string(),
        message: format!("failed to serialize response: {}", e),
    })
}

/// Typed health-check operation.
///
/// Kept separate from the JSON wrapper so the pure logic can be unit-tested
/// without wasm-bindgen.
pub fn health_check(request: &HealthRequest) -> Result<HealthResponse, EngineError> {
    validate_health_request(&request.contract_version, &request.request_id)
        .map_err(|(code, message)| EngineError { code, message })?;

    Ok(HealthResponse {
        contract_version: request.contract_version.clone(),
        request_id: request.request_id.clone(),
        engine: "security-engine".to_string(),
        status: "ok".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_check_returns_ok_for_valid_request() {
        let request = HealthRequest {
            contract_version: "1.0".to_string(),
            request_id: "m002-smoke-001".to_string(),
        };
        let response = health_check(&request).unwrap();
        assert_eq!(response.contract_version, "1.0");
        assert_eq!(response.request_id, "m002-smoke-001");
        assert_eq!(response.engine, "security-engine");
        assert_eq!(response.status, "ok");
    }

    #[test]
    fn health_check_rejects_unsupported_version() {
        let request = HealthRequest {
            contract_version: "2.0".to_string(),
            request_id: "req-1".to_string(),
        };
        let err = health_check(&request).unwrap_err();
        assert_eq!(err.code, validation::codes::UNSUPPORTED_CONTRACT_VERSION);
    }

    #[test]
    fn health_check_rejects_empty_request_id() {
        let request = HealthRequest {
            contract_version: "1.0".to_string(),
            request_id: "".to_string(),
        };
        let err = health_check(&request).unwrap_err();
        assert_eq!(err.code, validation::codes::INVALID_REQUEST_ID);
    }

    #[test]
    fn json_handler_returns_valid_response() {
        let input = r#"{"contract_version":"1.0","request_id":"m002-smoke-001"}"#;
        let output = health_check_json(input);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["engine"], "security-engine");
    }

    #[test]
    fn json_handler_rejects_malformed_json() {
        let output = health_check_json("{not json}");
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["code"], validation::codes::MALFORMED_JSON);
    }

    #[test]
    fn json_handler_rejects_unsupported_version() {
        let input = r#"{"contract_version":"9.9","request_id":"req-1"}"#;
        let output = health_check_json(input);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            parsed["code"],
            validation::codes::UNSUPPORTED_CONTRACT_VERSION
        );
    }

    #[test]
    fn json_handler_rejects_empty_request_id() {
        let input = r#"{"contract_version":"1.0","request_id":""}"#;
        let output = health_check_json(input);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["code"], validation::codes::INVALID_REQUEST_ID);
    }

    #[test]
    fn json_handler_does_not_panic_on_missing_fields() {
        let input = r#"{}"#;
        let output = health_check_json(input);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["code"], validation::codes::MALFORMED_JSON);
    }
}

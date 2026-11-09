//! Integration tests for the security-engine health check contract.
//!
//! These tests exercise the public WASM-compatible API from outside the crate,
//! mirroring how the TypeScript adapter will invoke it.

use security_engine::validation;
use security_engine::{health_check, HealthRequest};

#[test]
fn valid_health_request_returns_ok() {
    let request = HealthRequest {
        contract_version: "1.0".to_string(),
        request_id: "m002-smoke-001".to_string(),
    };
    let response = health_check(&request).unwrap();
    assert_eq!(response.status, "ok");
    assert_eq!(response.engine, "security-engine");
    assert_eq!(response.contract_version, "1.0");
    assert_eq!(response.request_id, "m002-smoke-001");
}

#[test]
fn unsupported_contract_version_is_rejected() {
    let request = HealthRequest {
        contract_version: "2.0".to_string(),
        request_id: "req-1".to_string(),
    };
    let err = health_check(&request).unwrap_err();
    assert_eq!(err.code, validation::codes::UNSUPPORTED_CONTRACT_VERSION);
}

#[test]
fn empty_request_id_is_rejected() {
    let request = HealthRequest {
        contract_version: "1.0".to_string(),
        request_id: "".to_string(),
    };
    let err = health_check(&request).unwrap_err();
    assert_eq!(err.code, validation::codes::INVALID_REQUEST_ID);
}

#[test]
fn non_ascii_request_id_is_rejected() {
    let request = HealthRequest {
        contract_version: "1.0".to_string(),
        request_id: "rèquest-1".to_string(),
    };
    let err = health_check(&request).unwrap_err();
    assert_eq!(err.code, validation::codes::INVALID_REQUEST_ID);
}

#[test]
fn request_id_too_long_is_rejected() {
    let long_id = "a".repeat(257);
    let request = HealthRequest {
        contract_version: "1.0".to_string(),
        request_id: long_id,
    };
    let err = health_check(&request).unwrap_err();
    assert_eq!(err.code, validation::codes::INVALID_REQUEST_ID);
}

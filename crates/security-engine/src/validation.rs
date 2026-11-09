//! Validation logic for engine requests.
//!
//! The Rust engine performs authoritative validation. The TypeScript adapter
//! must not assume Rust accepts arbitrary JSON.

use crate::models::{validate_request_id, CONTRACT_VERSION};

/// Validation error codes.
pub mod codes {
    /// The contract version field was missing or unsupported.
    pub const UNSUPPORTED_CONTRACT_VERSION: &str = "UNSUPPORTED_CONTRACT_VERSION";
    /// The request ID was missing, empty, non-ASCII, or too long.
    pub const INVALID_REQUEST_ID: &str = "INVALID_REQUEST_ID";
    /// The request body was not valid JSON.
    pub const MALFORMED_JSON: &str = "MALFORMED_JSON";
    /// A required field was missing from the request.
    #[allow(dead_code)]
    pub const MISSING_FIELD: &str = "MISSING_FIELD";
}

/// Validate a health-check request.
///
/// Returns `Ok(())` if the request is valid, or an error code and message
/// describing the first validation failure encountered.
pub fn validate_health_request(
    contract_version: &str,
    request_id: &str,
) -> Result<(), (String, String)> {
    if contract_version != CONTRACT_VERSION {
        return Err((
            codes::UNSUPPORTED_CONTRACT_VERSION.to_string(),
            format!(
                "unsupported contract version '{}', expected '{}'",
                contract_version, CONTRACT_VERSION
            ),
        ));
    }

    if !validate_request_id(request_id) {
        return Err((
            codes::INVALID_REQUEST_ID.to_string(),
            format!(
                "invalid request id: must be a non-empty ASCII string of at most 256 characters, got {:?}",
                request_id
            ),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_request() {
        assert!(validate_health_request("1.0", "m002-smoke-001").is_ok());
    }

    #[test]
    fn rejects_unsupported_version() {
        let err = validate_health_request("2.0", "req-1").unwrap_err();
        assert_eq!(err.0, codes::UNSUPPORTED_CONTRACT_VERSION);
    }

    #[test]
    fn rejects_empty_request_id() {
        let err = validate_health_request("1.0", "").unwrap_err();
        assert_eq!(err.0, codes::INVALID_REQUEST_ID);
    }

    #[test]
    fn rejects_non_ascii_request_id() {
        let err = validate_health_request("1.0", "réquest").unwrap_err();
        assert_eq!(err.0, codes::INVALID_REQUEST_ID);
    }

    #[test]
    fn rejects_too_long_request_id() {
        let long_id = "a".repeat(257);
        let err = validate_health_request("1.0", &long_id).unwrap_err();
        assert_eq!(err.0, codes::INVALID_REQUEST_ID);
    }
}

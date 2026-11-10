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
pub mod graph_algorithms;
pub mod graph_models;
pub mod graph_validation;
pub mod models;
pub mod validation;

pub use graph_models::{
    Asset, GraphSimulationRequest, GraphSimulationResponse, NetworkEdge, NetworkReachability,
    ServiceDependency, ServiceImpact, Witness,
};
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

/// Typed graph simulation operation.
///
/// Performs the full validation pipeline, network reachability calculation,
/// and service-impact propagation. Returns deterministic results.
pub fn simulate_graph(
    request: &GraphSimulationRequest,
) -> Result<GraphSimulationResponse, EngineError> {
    // Stage 1-16: Validate via the graph_validation pipeline on serialized JSON.
    let json = serde_json::to_string(request)
        .map_err(|e| EngineError {
            code: graph_validation::codes::MALFORMED_JSON.to_string(),
            message: format!("failed to serialize request: {}", e),
        })?;
    graph_validation::validate_request(&json).map_err(|e| EngineError {
        code: e.code,
        message: e.message,
    })?;

    // Compute network reachability.
    let reachability = graph_algorithms::compute_reachability(
        &request.assets,
        &request.network_edges,
        &request.attack_source_asset_ids,
    );

    // Compute service impact.
    let impact = graph_algorithms::compute_service_impact(
        &request.assets,
        &request.service_dependencies,
    );

    Ok(GraphSimulationResponse {
        contract_version: request.contract_version.clone(),
        request_id: request.request_id.clone(),
        scenario_id: request.scenario_id.clone(),
        network_reachability: NetworkReachability {
            reachable_asset_ids: reachability.reachable_asset_ids,
            unreachable_asset_ids: reachability.unreachable_asset_ids,
            witnesses: reachability
                .witnesses
                .into_iter()
                .map(|w| Witness {
                    target_asset: w.target_asset,
                    source_asset: w.source_asset,
                    asset_path: w.asset_path,
                    edge_path: w.edge_path,
                })
                .collect(),
        },
        service_impact: ServiceImpact {
            initially_unavailable_asset_ids: impact.initially_unavailable_asset_ids,
            impacted_dependent_asset_ids: impact.impacted_dependent_asset_ids,
            unavailable_asset_ids: impact.unavailable_asset_ids,
        },
    })
}

/// Raw JSON graph simulation handler exported to JavaScript.
///
/// Accepts a JSON string, validates it strictly through the full 16-stage
/// pipeline, computes reachability and impact, and returns a JSON string.
/// Invalid input produces an error JSON object, never a Rust panic.
#[wasm_bindgen]
pub fn simulate_graph_json(input: &str) -> String {
    // Stage 1: Raw byte limit.
    if input.len() > graph_validation::MAX_REQUEST_BYTES {
        return serde_json::to_string(&EngineError {
            code: graph_validation::codes::LIMIT_EXCEEDED.to_string(),
            message: format!(
                "request body exceeds maximum size of {} bytes",
                graph_validation::MAX_REQUEST_BYTES
            ),
        })
        .unwrap_or_else(|_| {
            r#"{"code":"LIMIT_EXCEEDED","message":"request body exceeds maximum size"}"#
                .to_string()
        });
    }

    // Stages 2-16: Validate via the graph_validation pipeline.
    match graph_validation::validate_request(input) {
        Ok(_value) => {
            // Deserialize into typed models.
            let request: GraphSimulationRequest =
                match serde_json::from_str(input) {
                    Ok(r) => r,
                    Err(e) => {
                        return serde_json::to_string(&EngineError {
                            code: graph_validation::codes::MALFORMED_JSON.to_string(),
                            message: format!("failed to deserialize request: {}", e),
                        })
                        .unwrap_or_else(|_| {
                            r#"{"code":"MALFORMED_JSON","message":"failed to deserialize request"}"#
                                .to_string()
                        });
                    }
                };

            // Run typed simulation (semantic validation stages 12-16 again
            // in the typed path for defense in depth).
            match simulate_graph(&request) {
                Ok(response) => serde_json::to_string(&response).unwrap_or_else(|_| {
                    r#"{"code":"INTERNAL_ERROR","message":"failed to serialize response"}"#
                        .to_string()
                }),
                Err(err) => serde_json::to_string(&err).unwrap_or_else(|_| {
                    r#"{"code":"INTERNAL_ERROR","message":"failed to serialize error"}"#
                        .to_string()
                }),
            }
        }
        Err(err) => serde_json::to_string(&EngineError {
            code: err.code,
            message: err.message,
        })
        .unwrap_or_else(|_| {
            r#"{"code":"INTERNAL_ERROR","message":"failed to serialize error"}"#
                .to_string()
        }),
    }
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

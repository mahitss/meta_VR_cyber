//! NetVigil XR Security Engine — WebAssembly library.
//!
//! This crate exposes a versioned JSON contract to the TypeScript XR client
//! via wasm-bindgen. Core business logic is pure and independently testable.
//!
//! Contract v1.0:
//!   Request:  { "contract_version": "1.0", "request_id": "<string>" }
//!   Response: { "contract_version": "1.0", "request_id": "<string>",
//!               "scenario_id": "<string>", "network_reachability": {...}, "service_impact": {...} }
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
        contract_version: request.contract_version.clone(),
        request_id: request.request_id.clone(),
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
/// Performs the full validation pipeline, graph simulation, and returns
/// deterministic results.
pub fn simulate_graph(
    request: &GraphSimulationRequest,
) -> Result<GraphSimulationResponse, EngineError> {
    use crate::graph_models::{validate_request_id, validate_resource_id};
    use crate::graph_validation::{
        codes, MAX_ASSETS, MAX_ATTACK_SOURCES, MAX_NETWORK_EDGES, MAX_SERVICE_DEPENDENCIES,
    };

    // Validate contract version
    if request.contract_version != graph_models::CONTRACT_VERSION {
        return Err(EngineError {
            code: codes::UNSUPPORTED_CONTRACT_VERSION.to_string(),
            message: format!(
                "unsupported contract version '{}', expected '{}'",
                request.contract_version,
                graph_models::CONTRACT_VERSION
            ),
        });
    }

    // Validate request ID
    if !validate_request_id(&request.request_id) {
        return Err(EngineError {
            code: codes::INVALID_REQUEST_ID.to_string(),
            message:
                "request_id must be a non-empty printable ASCII string of at most 256 characters"
                    .to_string(),
        });
    }

    // Validate scenario ID
    if !validate_resource_id(&request.scenario_id) {
        return Err(EngineError {
            code: codes::INVALID_SCENARIO_ID.to_string(),
            message: "invalid scenario id: must start with an alphanumeric character and contain only alphanumeric, '.', '_', ':', or '-', max 64 characters"
                .to_string(),
        });
    }

    // Validate collection size limits
    if request.assets.len() > MAX_ASSETS {
        return Err(EngineError {
            code: codes::LIMIT_EXCEEDED.to_string(),
            message: format!("assets array exceeds maximum of {}", MAX_ASSETS),
        });
    }
    if request.network_edges.len() > MAX_NETWORK_EDGES {
        return Err(EngineError {
            code: codes::LIMIT_EXCEEDED.to_string(),
            message: format!(
                "network_edges array exceeds maximum of {}",
                MAX_NETWORK_EDGES
            ),
        });
    }
    if request.service_dependencies.len() > MAX_SERVICE_DEPENDENCIES {
        return Err(EngineError {
            code: codes::LIMIT_EXCEEDED.to_string(),
            message: format!(
                "service_dependencies array exceeds maximum of {}",
                MAX_SERVICE_DEPENDENCIES
            ),
        });
    }
    if request.attack_source_asset_ids.len() > MAX_ATTACK_SOURCES {
        return Err(EngineError {
            code: codes::LIMIT_EXCEEDED.to_string(),
            message: format!(
                "attack_source_asset_ids array exceeds maximum of {}",
                MAX_ATTACK_SOURCES
            ),
        });
    }

    // Validate resource identifiers and availability values.
    for asset in &request.assets {
        if !validate_resource_id(&asset.id) {
            return Err(EngineError {
                code: codes::INVALID_GRAPH.to_string(),
                message: format!(
                    "asset id '{}' must start with alphanumeric and contain only alphanumeric, '.', '_', ':', or '-', max 64 characters",
                    asset.id
                ),
            });
        }
        if asset.availability != "available" && asset.availability != "unavailable" {
            return Err(EngineError {
                code: codes::INVALID_GRAPH.to_string(),
                message: format!(
                    "asset '{}' has invalid availability '{}'",
                    asset.id, asset.availability
                ),
            });
        }
    }

    for edge in &request.network_edges {
        if !validate_resource_id(&edge.id) {
            return Err(EngineError {
                code: codes::INVALID_GRAPH.to_string(),
                message: format!(
                    "network edge id '{}' must start with alphanumeric and contain only alphanumeric, '.', '_', ':', or '-', max 64 characters",
                    edge.id
                ),
            });
        }
    }

    for dep in &request.service_dependencies {
        if !validate_resource_id(&dep.id) {
            return Err(EngineError {
                code: codes::INVALID_GRAPH.to_string(),
                message: format!(
                    "service dependency id '{}' must start with alphanumeric and contain only alphanumeric, '.', '_', ':', or '-', max 64 characters",
                    dep.id
                ),
            });
        }
    }

    // Stage 12: Validate duplicate entity IDs.
    let mut asset_id_set_check = std::collections::HashSet::new();
    for asset in &request.assets {
        if !asset_id_set_check.insert(asset.id.as_str()) {
            return Err(EngineError {
                code: codes::DUPLICATE_ASSET_ID.to_string(),
                message: format!("duplicate asset id: {}", asset.id),
            });
        }
    }

    let mut edge_id_set = std::collections::HashSet::new();
    for edge in &request.network_edges {
        if !edge_id_set.insert(edge.id.as_str()) {
            return Err(EngineError {
                code: codes::DUPLICATE_NETWORK_EDGE_ID.to_string(),
                message: format!("duplicate network edge id: {}", edge.id),
            });
        }
    }

    let mut dep_id_set = std::collections::HashSet::new();
    for dep in &request.service_dependencies {
        if !dep_id_set.insert(dep.id.as_str()) {
            return Err(EngineError {
                code: codes::DUPLICATE_SERVICE_DEPENDENCY_ID.to_string(),
                message: format!("duplicate service dependency id: {}", dep.id),
            });
        }
    }

    // Stage 13: Validate duplicate graph relationships and duplicate attack sources.
    let mut network_relationships = std::collections::HashSet::new();
    for edge in &request.network_edges {
        let key = (edge.source_asset_id.as_str(), edge.target_asset_id.as_str());
        if !network_relationships.insert(key) {
            return Err(EngineError {
                code: codes::DUPLICATE_NETWORK_RELATIONSHIP.to_string(),
                message: format!("duplicate network relationship: {} -> {}", key.0, key.1),
            });
        }
    }

    let mut service_relationships = std::collections::HashSet::new();
    for dep in &request.service_dependencies {
        let key = (
            dep.dependent_asset_id.as_str(),
            dep.dependency_asset_id.as_str(),
        );
        if !service_relationships.insert(key) {
            return Err(EngineError {
                code: codes::DUPLICATE_SERVICE_RELATIONSHIP.to_string(),
                message: format!(
                    "duplicate service dependency relationship: {} -> {}",
                    key.0, key.1
                ),
            });
        }
    }

    let mut source_id_set = std::collections::HashSet::new();
    for source_id in &request.attack_source_asset_ids {
        if !source_id_set.insert(source_id.as_str()) {
            return Err(EngineError {
                code: codes::DUPLICATE_ATTACK_SOURCE_ID.to_string(),
                message: format!("duplicate attack source id: {}", source_id),
            });
        }
    }

    // Build asset_id_set for reachability validation
    let asset_id_set: std::collections::HashSet<&str> =
        request.assets.iter().map(|a| a.id.as_str()).collect();

    // Validate edge source/target references.
    for edge in &request.network_edges {
        if !asset_id_set.contains(edge.source_asset_id.as_str()) {
            return Err(EngineError {
                code: codes::UNKNOWN_ASSET_REFERENCE.to_string(),
                message: format!(
                    "network edge '{}' references unknown source asset '{}'",
                    edge.id, edge.source_asset_id
                ),
            });
        }
        if !asset_id_set.contains(edge.target_asset_id.as_str()) {
            return Err(EngineError {
                code: codes::UNKNOWN_ASSET_REFERENCE.to_string(),
                message: format!(
                    "network edge '{}' references unknown target asset '{}'",
                    edge.id, edge.target_asset_id
                ),
            });
        }
    }

    // Validate dependency references.
    for dep in &request.service_dependencies {
        if !asset_id_set.contains(dep.dependent_asset_id.as_str()) {
            return Err(EngineError {
                code: codes::UNKNOWN_ASSET_REFERENCE.to_string(),
                message: format!(
                    "service dependency '{}' references unknown dependent asset '{}'",
                    dep.id, dep.dependent_asset_id
                ),
            });
        }
        if !asset_id_set.contains(dep.dependency_asset_id.as_str()) {
            return Err(EngineError {
                code: codes::UNKNOWN_ASSET_REFERENCE.to_string(),
                message: format!(
                    "service dependency '{}' references unknown dependency asset '{}'",
                    dep.id, dep.dependency_asset_id
                ),
            });
        }
    }

    // Validate attack source references.
    for source_id in &request.attack_source_asset_ids {
        if !asset_id_set.contains(source_id.as_str()) {
            return Err(EngineError {
                code: codes::UNKNOWN_ASSET_REFERENCE.to_string(),
                message: format!("attack source '{}' references unknown asset", source_id),
            });
        }
    }

    // Stage 15: Validate prohibited self-loops.
    for edge in &request.network_edges {
        if edge.source_asset_id == edge.target_asset_id {
            return Err(EngineError {
                code: codes::SELF_LOOP_NOT_ALLOWED.to_string(),
                message: format!(
                    "network edge '{}' is a self-loop on asset '{}'",
                    edge.id, edge.source_asset_id
                ),
            });
        }
    }
    for dep in &request.service_dependencies {
        if dep.dependent_asset_id == dep.dependency_asset_id {
            return Err(EngineError {
                code: codes::SELF_LOOP_NOT_ALLOWED.to_string(),
                message: format!(
                    "service dependency '{}' is a self-loop on asset '{}'",
                    dep.id, dep.dependent_asset_id
                ),
            });
        }
    }

    // Stage 16: Validate attack-source availability.
    let availability: std::collections::HashMap<&str, &str> = request
        .assets
        .iter()
        .map(|a| (a.id.as_str(), a.availability.as_str()))
        .collect();

    for source_id in &request.attack_source_asset_ids {
        if let Some(avail) = availability.get(source_id.as_str()) {
            if *avail == "unavailable" {
                return Err(EngineError {
                    code: codes::SOURCE_ASSET_UNAVAILABLE.to_string(),
                    message: format!("attack source asset '{}' is unavailable", source_id),
                });
            }
        }
    }

    // Compute reachability and service impact.
    let reachability = graph_algorithms::compute_reachability(
        &request.assets,
        &request.network_edges,
        &request.attack_source_asset_ids,
    );

    let impact =
        graph_algorithms::compute_service_impact(&request.assets, &request.service_dependencies);

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

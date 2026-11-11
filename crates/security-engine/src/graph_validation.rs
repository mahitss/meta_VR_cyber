//! Authoritative validation for graph simulation requests.
//!
//! Implements a staged, first-failure-wins validation pipeline compatible with
//! strict deserialization. The pipeline parses into `serde_json::Value`,
//! validates the envelope and structural conditions explicitly, then
//! deserializes into strict typed models for semantic graph validation.

use serde_json::Value;

use crate::graph_models::{validate_request_id, validate_resource_id, CONTRACT_VERSION};

/// Maximum raw serialized request size in bytes (2 MiB).
pub const MAX_REQUEST_BYTES: usize = 2_097_152;

/// Maximum number of assets.
pub const MAX_ASSETS: usize = 256;
/// Maximum number of network edges.
pub const MAX_NETWORK_EDGES: usize = 2_048;
/// Maximum number of service dependencies.
pub const MAX_SERVICE_DEPENDENCIES: usize = 2_048;
/// Maximum number of attack sources.
pub const MAX_ATTACK_SOURCES: usize = 256;

/// Validation error codes.
pub mod codes {
    /// Body is not valid JSON, or missing/unknown/type-incorrect fields.
    pub const MALFORMED_JSON: &str = "MALFORMED_JSON";
    /// `contract_version` is not `"1.0"`.
    pub const UNSUPPORTED_CONTRACT_VERSION: &str = "UNSUPPORTED_CONTRACT_VERSION";
    /// `request_id` is empty, non-ASCII, or > 256 chars.
    pub const INVALID_REQUEST_ID: &str = "INVALID_REQUEST_ID";
    /// `scenario_id` is empty, non-ASCII, > 64 chars, or violates grammar.
    pub const INVALID_SCENARIO_ID: &str = "INVALID_SCENARIO_ID";
    /// Invalid `availability` value or other graph-level semantic violation.
    pub const INVALID_GRAPH: &str = "INVALID_GRAPH";
    /// Two assets share the same `id`.
    pub const DUPLICATE_ASSET_ID: &str = "DUPLICATE_ASSET_ID";
    /// Two network edges share the same `id`.
    pub const DUPLICATE_NETWORK_EDGE_ID: &str = "DUPLICATE_NETWORK_EDGE_ID";
    /// Two dependencies share the same `id`.
    pub const DUPLICATE_SERVICE_DEPENDENCY_ID: &str = "DUPLICATE_SERVICE_DEPENDENCY_ID";
    /// Two dependencies share the same `(dependent_asset_id, dependency_asset_id)` pair.
    pub const DUPLICATE_SERVICE_RELATIONSHIP: &str = "DUPLICATE_SERVICE_RELATIONSHIP";
    /// Edge or dependency references a non-existent asset ID.
    pub const UNKNOWN_ASSET_REFERENCE: &str = "UNKNOWN_ASSET_REFERENCE";
    /// Two edges have the same `(source_asset_id, target_asset_id)` pair.
    pub const DUPLICATE_NETWORK_RELATIONSHIP: &str = "DUPLICATE_NETWORK_RELATIONSHIP";
    /// Edge or dependency references the same asset as source and target.
    pub const SELF_LOOP_NOT_ALLOWED: &str = "SELF_LOOP_NOT_ALLOWED";
    /// Attack source asset has `availability: "unavailable"`.
    pub const SOURCE_ASSET_UNAVAILABLE: &str = "SOURCE_ASSET_UNAVAILABLE";
    /// Duplicate value in `attack_source_asset_ids`.
    pub const DUPLICATE_ATTACK_SOURCE_ID: &str = "DUPLICATE_ATTACK_SOURCE_ID";
    /// Input collection exceeds MVP bounds or raw request exceeds 2 MiB.
    pub const LIMIT_EXCEEDED: &str = "LIMIT_EXCEEDED";
}

/// Required top-level fields in the request object.
const REQUIRED_TOP_LEVEL_FIELDS: &[&str] = &[
    "contract_version",
    "request_id",
    "scenario_id",
    "assets",
    "network_edges",
    "service_dependencies",
    "attack_source_asset_ids",
];

/// Allowed top-level fields (same as required, since all are required).
const ALLOWED_TOP_LEVEL_FIELDS: &[&str] = REQUIRED_TOP_LEVEL_FIELDS;

/// Required fields within an asset object.
const REQUIRED_ASSET_FIELDS: &[&str] = &["id", "availability"];
/// Allowed fields within an asset object.
const ALLOWED_ASSET_FIELDS: &[&str] = REQUIRED_ASSET_FIELDS;

/// Required fields within a network edge object.
const REQUIRED_EDGE_FIELDS: &[&str] = &["id", "source_asset_id", "target_asset_id", "enabled"];
/// Allowed fields within a network edge object.
const ALLOWED_EDGE_FIELDS: &[&str] = REQUIRED_EDGE_FIELDS;

/// Required fields within a service dependency object.
const REQUIRED_DEPENDENCY_FIELDS: &[&str] = &["id", "dependent_asset_id", "dependency_asset_id"];
/// Allowed fields within a service dependency object.
const ALLOWED_DEPENDENCY_FIELDS: &[&str] = REQUIRED_DEPENDENCY_FIELDS;

/// A validation error with a stable code and human-readable message.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Check required fields in a JSON object, returning the first missing field.
fn check_required_fields(obj: &serde_json::Map<String, Value>, fields: &[&str]) -> Option<String> {
    for field in fields {
        if !obj.contains_key(*field) {
            return Some(format!("missing required field: {}", field));
        }
    }
    None
}

/// Check unknown fields in a JSON object, returning the first unknown field.
fn check_unknown_fields(obj: &serde_json::Map<String, Value>, allowed: &[&str]) -> Option<String> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Some(format!("unknown field: {}", key));
        }
    }
    None
}

/// Extract an array from an object field, safely returning an error if missing
/// or not an array.
fn extract_array<'a>(
    obj: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a [Value], ValidationError> {
    match obj.get(field) {
        Some(Value::Array(arr)) => Ok(arr),
        _ => Err(ValidationError::new(
            codes::MALFORMED_JSON,
            &format!("field '{}' must be an array", field),
        )),
    }
}

/// Extract an object from a Value, safely returning an error if not an object.
fn extract_object<'a>(
    v: &'a Value,
    index: usize,
    context: &str,
) -> Result<&'a serde_json::Map<String, Value>, ValidationError> {
    match v {
        Value::Object(map) => Ok(map),
        _ => Err(ValidationError::new(
            codes::MALFORMED_JSON,
            &format!("{} at index {} must be an object", context, index),
        )),
    }
}

/// Result of validating a raw request string.
///
/// Returns the parsed `serde_json::Value` on success, or a `ValidationError`
/// describing the first failure encountered.
pub fn validate_request(raw: &str) -> Result<Value, ValidationError> {
    // Stage 1: Enforce maximum raw request byte size.
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(ValidationError::new(
            codes::LIMIT_EXCEEDED,
            format!(
                "request body exceeds maximum size of {} bytes",
                MAX_REQUEST_BYTES
            ),
        ));
    }

    // Stage 2: Parse syntactically valid JSON.
    let value: Value = serde_json::from_str(raw).map_err(|e| {
        ValidationError::new(codes::MALFORMED_JSON, &format!("invalid JSON: {}", e))
    })?;

    // Stage 3: Validate that the root is a JSON object.
    let obj = match &value {
        Value::Object(map) => map,
        _ => {
            return Err(ValidationError::new(
                codes::MALFORMED_JSON,
                "request body must be a JSON object",
            ));
        }
    };

    // Stage 4: Check required fields at all object levels.
    if let Some(msg) = check_required_fields(obj, REQUIRED_TOP_LEVEL_FIELDS) {
        return Err(ValidationError::new(codes::MALFORMED_JSON, &msg));
    }

    // Extract arrays for nested validation.
    let assets = extract_array(obj, "assets")?;
    let network_edges = extract_array(obj, "network_edges")?;
    let service_dependencies = extract_array(obj, "service_dependencies")?;
    let attack_sources = extract_array(obj, "attack_source_asset_ids")?;

    // Validate required fields within each asset object.
    for (i, asset) in assets.iter().enumerate() {
        let a = extract_object(asset, i, "asset")?;
        if let Some(msg) = check_required_fields(a, REQUIRED_ASSET_FIELDS) {
            return Err(ValidationError::new(
                codes::MALFORMED_JSON,
                &format!("asset at index {}: {}", i, msg),
            ));
        }
    }

    // Validate required fields within each edge object.
    for (i, edge) in network_edges.iter().enumerate() {
        let e = extract_object(edge, i, "network edge")?;
        if let Some(msg) = check_required_fields(e, REQUIRED_EDGE_FIELDS) {
            return Err(ValidationError::new(
                codes::MALFORMED_JSON,
                &format!("network edge at index {}: {}", i, msg),
            ));
        }
    }

    // Validate required fields within each dependency object.
    for (i, dep) in service_dependencies.iter().enumerate() {
        let d = extract_object(dep, i, "service dependency")?;
        if let Some(msg) = check_required_fields(d, REQUIRED_DEPENDENCY_FIELDS) {
            return Err(ValidationError::new(
                codes::MALFORMED_JSON,
                &format!("service dependency at index {}: {}", i, msg),
            ));
        }
    }

    // Stage 5: Check unknown fields at all object levels.
    if let Some(msg) = check_unknown_fields(obj, ALLOWED_TOP_LEVEL_FIELDS) {
        return Err(ValidationError::new(codes::MALFORMED_JSON, &msg));
    }

    // Check unknown fields within each asset object.
    for (i, asset) in assets.iter().enumerate() {
        let a = extract_object(asset, i, "asset")?;
        if let Some(msg) = check_unknown_fields(a, ALLOWED_ASSET_FIELDS) {
            return Err(ValidationError::new(
                codes::MALFORMED_JSON,
                &format!("asset at index {}: {}", i, msg),
            ));
        }
    }

    // Check unknown fields within each edge object.
    for (i, edge) in network_edges.iter().enumerate() {
        let e = extract_object(edge, i, "network edge")?;
        if let Some(msg) = check_unknown_fields(e, ALLOWED_EDGE_FIELDS) {
            return Err(ValidationError::new(
                codes::MALFORMED_JSON,
                &format!("network edge at index {}: {}", i, msg),
            ));
        }
    }

    // Check unknown fields within each dependency object.
    for (i, dep) in service_dependencies.iter().enumerate() {
        let d = extract_object(dep, i, "service dependency")?;
        if let Some(msg) = check_unknown_fields(d, ALLOWED_DEPENDENCY_FIELDS) {
            return Err(ValidationError::new(
                codes::MALFORMED_JSON,
                &format!("service dependency at index {}: {}", i, msg),
            ));
        }
    }

    // Stage 6: Validate structural JSON types at all object levels.
    // Top-level fields.
    for field in REQUIRED_TOP_LEVEL_FIELDS {
        match obj.get(*field) {
            Some(Value::String(_))
                if ["contract_version", "request_id", "scenario_id"].contains(field) => {}
            Some(Value::Array(_))
                if [
                    "assets",
                    "network_edges",
                    "service_dependencies",
                    "attack_source_asset_ids",
                ]
                .contains(field) => {}
            Some(_) => {
                return Err(ValidationError::new(
                    codes::MALFORMED_JSON,
                    &format!("field '{}' has invalid type", field),
                ));
            }
            None => {
                // Already caught by Stage 4 required-field check.
            }
        }
    }

    // Validate structural types within each asset object.
    for (i, asset) in assets.iter().enumerate() {
        let a = extract_object(asset, i, "asset")?;
        for field in REQUIRED_ASSET_FIELDS {
            match a.get(*field) {
                Some(Value::String(_)) => {}
                Some(_) => {
                    return Err(ValidationError::new(
                        codes::MALFORMED_JSON,
                        &format!("asset at index {} field '{}' must be a string", i, field),
                    ));
                }
                None => {
                    // Already caught by Stage 4 required-field check.
                }
            }
        }
    }

    // Validate structural types within each edge object.
    for (i, edge) in network_edges.iter().enumerate() {
        let e = extract_object(edge, i, "network edge")?;
        for field in REQUIRED_EDGE_FIELDS {
            match e.get(*field) {
                Some(Value::String(_)) if *field != "enabled" => {}
                Some(Value::Bool(_)) if *field == "enabled" => {}
                Some(_) => {
                    let expected = if *field == "enabled" {
                        "boolean"
                    } else {
                        "string"
                    };
                    return Err(ValidationError::new(
                        codes::MALFORMED_JSON,
                        &format!(
                            "network edge at index {} field '{}' must be {}",
                            i, field, expected
                        ),
                    ));
                }
                None => {
                    // Already caught by Stage 4 required-field check.
                }
            }
        }
    }

    // Validate structural types within each dependency object.
    for (i, dep) in service_dependencies.iter().enumerate() {
        let d = extract_object(dep, i, "service dependency")?;
        for field in REQUIRED_DEPENDENCY_FIELDS {
            match d.get(*field) {
                Some(Value::String(_)) => {}
                Some(_) => {
                    return Err(ValidationError::new(
                        codes::MALFORMED_JSON,
                        &format!(
                            "service dependency at index {} field '{}' must be a string",
                            i, field
                        ),
                    ));
                }
                None => {
                    // Already caught by Stage 4 required-field check.
                }
            }
        }
    }

    // Validate structural types of attack source array elements.
    for (i, source_id) in attack_sources.iter().enumerate() {
        if !source_id.is_string() {
            return Err(ValidationError::new(
                codes::MALFORMED_JSON,
                &format!("attack_source_asset_ids at index {} is not a string", i),
            ));
        }
    }

    // Stage 7: Validate contract version.
    let contract_version = obj["contract_version"].as_str().unwrap();
    if contract_version != CONTRACT_VERSION {
        return Err(ValidationError::new(
            codes::UNSUPPORTED_CONTRACT_VERSION,
            &format!(
                "unsupported contract version '{}', expected '{}'",
                contract_version, CONTRACT_VERSION
            ),
        ));
    }

    // Stage 8: Validate request ID.
    let request_id = obj["request_id"].as_str().unwrap();
    if !validate_request_id(request_id) {
        return Err(ValidationError::new(
            codes::INVALID_REQUEST_ID,
            &format!(
                "invalid request id: must be a non-empty printable ASCII string of at most 256 characters"
            ),
        ));
    }

    // Stage 9: Validate scenario ID.
    let scenario_id = obj["scenario_id"].as_str().unwrap();
    if !validate_resource_id(scenario_id) {
        return Err(ValidationError::new(
            codes::INVALID_SCENARIO_ID,
            &format!(
                "invalid scenario id: must start with an alphanumeric character and contain only alphanumeric, '.', '_', ':', or '-', max 64 characters"
            ),
        ));
    }

    // Stage 10: Enforce collection size limits.
    if assets.len() > MAX_ASSETS {
        return Err(ValidationError::new(
            codes::LIMIT_EXCEEDED,
            &format!("assets array exceeds maximum of {}", MAX_ASSETS),
        ));
    }
    if network_edges.len() > MAX_NETWORK_EDGES {
        return Err(ValidationError::new(
            codes::LIMIT_EXCEEDED,
            &format!(
                "network_edges array exceeds maximum of {}",
                MAX_NETWORK_EDGES
            ),
        ));
    }
    if service_dependencies.len() > MAX_SERVICE_DEPENDENCIES {
        return Err(ValidationError::new(
            codes::LIMIT_EXCEEDED,
            &format!(
                "service_dependencies array exceeds maximum of {}",
                MAX_SERVICE_DEPENDENCIES
            ),
        ));
    }
    if attack_sources.len() > MAX_ATTACK_SOURCES {
        return Err(ValidationError::new(
            codes::LIMIT_EXCEEDED,
            &format!(
                "attack_source_asset_ids array exceeds maximum of {}",
                MAX_ATTACK_SOURCES
            ),
        ));
    }

    // Stage 11: Validate resource identifiers and availability values.
    for (i, asset) in assets.iter().enumerate() {
        let a = extract_object(asset, i, "asset")?;
        let id = a["id"].as_str().unwrap();
        if !validate_resource_id(id) {
            return Err(ValidationError::new(
                codes::INVALID_GRAPH,
                &format!(
                    "asset at index {} has invalid id '{}': must start with alphanumeric and contain only alphanumeric, '.', '_', ':', or '-', max 64 characters",
                    i, id
                ),
            ));
        }
        let availability = match a.get("availability") {
            Some(Value::String(s)) => s.to_string(),
            _ => {
                return Err(ValidationError::new(
                    codes::MALFORMED_JSON,
                    &format!("asset at index {} field 'availability' must be a string", i),
                ));
            }
        };
        if availability != "available" && availability != "unavailable" {
            return Err(ValidationError::new(
                codes::INVALID_GRAPH,
                &format!("asset '{}' has invalid availability '{}'", id, availability),
            ));
        }
    }

    for (i, edge) in network_edges.iter().enumerate() {
        let e = extract_object(edge, i, "network edge")?;
        let id = e["id"].as_str().unwrap();
        if !validate_resource_id(id) {
            return Err(ValidationError::new(
                codes::INVALID_GRAPH,
                &format!("network edge at index {} has invalid id '{}'", i, id),
            ));
        }
    }

    for (i, dep) in service_dependencies.iter().enumerate() {
        let d = extract_object(dep, i, "service dependency")?;
        let id = d["id"].as_str().unwrap();
        if !validate_resource_id(id) {
            return Err(ValidationError::new(
                codes::INVALID_GRAPH,
                &format!("service dependency at index {} has invalid id '{}'", i, id),
            ));
        }
    }

    // Stage 12: Validate duplicate entity IDs.
    let mut asset_ids = std::collections::HashSet::new();
    for asset in assets.iter() {
        let id = extract_object(asset, 0, "asset")?["id"].as_str().unwrap();
        if !asset_ids.insert(id) {
            return Err(ValidationError::new(
                codes::DUPLICATE_ASSET_ID,
                &format!("duplicate asset id: {}", id),
            ));
        }
    }

    let mut edge_ids = std::collections::HashSet::new();
    for edge in network_edges.iter() {
        let id = extract_object(edge, 0, "network edge")?["id"]
            .as_str()
            .unwrap();
        if !edge_ids.insert(id) {
            return Err(ValidationError::new(
                codes::DUPLICATE_NETWORK_EDGE_ID,
                &format!("duplicate network edge id: {}", id),
            ));
        }
    }

    let mut dependency_ids = std::collections::HashSet::new();
    for dep in service_dependencies.iter() {
        let id = extract_object(dep, 0, "service dependency")?["id"]
            .as_str()
            .unwrap();
        if !dependency_ids.insert(id) {
            return Err(ValidationError::new(
                codes::DUPLICATE_SERVICE_DEPENDENCY_ID,
                &format!("duplicate service dependency id: {}", id),
            ));
        }
    }

    // Stage 13: Validate duplicate graph relationships and duplicate attack sources.
    let mut network_relationships = std::collections::HashSet::new();
    for edge in network_edges.iter() {
        let e = extract_object(edge, 0, "network edge")?;
        let key = (
            e["source_asset_id"].as_str().unwrap(),
            e["target_asset_id"].as_str().unwrap(),
        );
        if !network_relationships.insert(key) {
            return Err(ValidationError::new(
                codes::DUPLICATE_NETWORK_RELATIONSHIP,
                &format!("duplicate network relationship: {} -> {}", key.0, key.1),
            ));
        }
    }

    let mut service_relationships = std::collections::HashSet::new();
    for dep in service_dependencies.iter() {
        let d = extract_object(dep, 0, "service dependency")?;
        let key = (
            d["dependent_asset_id"].as_str().unwrap(),
            d["dependency_asset_id"].as_str().unwrap(),
        );
        if !service_relationships.insert(key) {
            return Err(ValidationError::new(
                codes::DUPLICATE_SERVICE_RELATIONSHIP,
                &format!(
                    "duplicate service dependency relationship: {} -> {}",
                    key.0, key.1
                ),
            ));
        }
    }

    let mut source_ids = std::collections::HashSet::new();
    for source in attack_sources.iter() {
        let id = source.as_str().unwrap();
        if !source_ids.insert(id) {
            return Err(ValidationError::new(
                codes::DUPLICATE_ATTACK_SOURCE_ID,
                &format!("duplicate attack source id: {}", id),
            ));
        }
    }

    // Stage 14: Validate referenced asset existence.
    let mut asset_id_set = std::collections::HashSet::new();
    for asset in assets.iter() {
        let m = extract_object(asset, 0, "asset")?;
        asset_id_set.insert(m["id"].as_str().unwrap());
    }

    for edge in network_edges.iter() {
        let e = extract_object(edge, 0, "network edge")?;
        let source_asset_id = e["source_asset_id"].as_str().unwrap();
        let dest_id = e["target_asset_id"].as_str().unwrap();
        if !asset_id_set.contains(source_asset_id) {
            return Err(ValidationError::new(
                codes::UNKNOWN_ASSET_REFERENCE,
                &format!(
                    "network edge '{}' references unknown source asset '{}'",
                    e["id"].as_str().unwrap(),
                    source_asset_id
                ),
            ));
        }
        if !asset_id_set.contains(dest_id) {
            return Err(ValidationError::new(
                codes::UNKNOWN_ASSET_REFERENCE,
                &format!(
                    "network edge '{}' references unknown target asset '{}'",
                    e["id"].as_str().unwrap(),
                    dest_id
                ),
            ));
        }
    }

    for dep in service_dependencies.iter() {
        let d = extract_object(dep, 0, "service dependency")?;
        let dep_id = d["dependent_asset_id"].as_str().unwrap();
        let dep_target = d["dependency_asset_id"].as_str().unwrap();
        if !asset_id_set.contains(dep_id) {
            return Err(ValidationError::new(
                codes::UNKNOWN_ASSET_REFERENCE,
                &format!(
                    "service dependency '{}' references unknown dependent asset '{}'",
                    d["id"].as_str().unwrap(),
                    dep_id
                ),
            ));
        }
        if !asset_id_set.contains(dep_target) {
            return Err(ValidationError::new(
                codes::UNKNOWN_ASSET_REFERENCE,
                &format!(
                    "service dependency '{}' references unknown dependency asset '{}'",
                    d["id"].as_str().unwrap(),
                    dep_target
                ),
            ));
        }
    }

    // Validate attack source references (stage 14).
    for source_id in attack_sources.iter() {
        let sid = source_id.as_str().unwrap();
        if !asset_id_set.contains(sid) {
            return Err(ValidationError::new(
                codes::UNKNOWN_ASSET_REFERENCE,
                &format!("attack source '{}' references unknown asset", sid),
            ));
        }
    }

    // Stage 15: Validate prohibited self-loops.
    for edge in network_edges.iter() {
        let e = extract_object(edge, 0, "network edge")?;
        if e["source_asset_id"] == e["target_asset_id"] {
            return Err(ValidationError::new(
                codes::SELF_LOOP_NOT_ALLOWED,
                &format!(
                    "network edge '{}' is a self-loop on asset '{}'",
                    e["id"].as_str().unwrap(),
                    e["source_asset_id"].as_str().unwrap()
                ),
            ));
        }
    }
    for dep in service_dependencies.iter() {
        let d = extract_object(dep, 0, "service dependency")?;
        if d["dependent_asset_id"] == d["dependency_asset_id"] {
            return Err(ValidationError::new(
                codes::SELF_LOOP_NOT_ALLOWED,
                &format!(
                    "service dependency '{}' is a self-loop on asset '{}'",
                    d["id"].as_str().unwrap(),
                    d["dependent_asset_id"].as_str().unwrap()
                ),
            ));
        }
    }

    // Stage 16: Validate attack-source availability.
    let mut availability = std::collections::HashMap::new();
    for a in assets.iter() {
        let m = extract_object(a, 0, "asset")?;
        availability.insert(
            m["id"].as_str().unwrap(),
            m["availability"].as_str().unwrap(),
        );
    }

    for source in attack_sources.iter() {
        let sid = source.as_str().unwrap();
        if let Some(avail) = availability.get(sid) {
            if *avail == "unavailable" {
                return Err(ValidationError::new(
                    codes::SOURCE_ASSET_UNAVAILABLE,
                    &format!("attack source asset '{}' is unavailable", sid),
                ));
            }
        }
    }

    Ok(value)
}

/// Deserialize the validated `serde_json::Value` into typed request models.
pub fn deserialize_request(
    value: Value,
) -> Result<crate::graph_models::GraphSimulationRequest, ValidationError> {
    serde_json::from_value(value).map_err(|e| {
        ValidationError::new(
            codes::MALFORMED_JSON,
            &format!("failed to deserialize request: {}", e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_json() -> String {
        serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [
                {"id": "A", "availability": "available"},
                {"id": "B", "availability": "unavailable"}
            ],
            "network_edges": [
                {"id": "e1", "source_asset_id": "A", "target_asset_id": "B", "enabled": true}
            ],
            "service_dependencies": [
                {"id": "d1", "dependent_asset_id": "B", "dependency_asset_id": "A"}
            ],
            "attack_source_asset_ids": ["A"]
        })
        .to_string()
    }

    #[test]
    fn nested_missing_asset_id() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"availability": "available"}],
            "network_edges": [],
            "service_dependencies": [],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_missing_availability() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"id": "A"}],
            "network_edges": [],
            "service_dependencies": [],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_missing_edge_fields() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"id": "A", "availability": "available"}],
            "network_edges": [{"id": "e1"}],
            "service_dependencies": [],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_missing_dependency_fields() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"id": "A", "availability": "available"}],
            "network_edges": [],
            "service_dependencies": [{"id": "d1"}],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_non_object_asset_entry() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": ["not an object"],
            "network_edges": [],
            "service_dependencies": [],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_non_object_edge_entry() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"id": "A", "availability": "available"}],
            "network_edges": ["not an object"],
            "service_dependencies": [],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_non_object_dependency_entry() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"id": "A", "availability": "available"}],
            "network_edges": [],
            "service_dependencies": ["not an object"],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_wrong_structural_types() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"id": 123, "availability": "available"}],
            "network_edges": [],
            "service_dependencies": [],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_unknown_fields() {
        let json = serde_json::json!({
            "contract_version": "1.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"id": "A", "availability": "available", "extra": true}],
            "network_edges": [],
            "service_dependencies": [],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn nested_structural_errors_win_over_unsupported_version() {
        let json = serde_json::json!({
            "contract_version": "2.0",
            "request_id": "req-1",
            "scenario_id": "scen-1",
            "assets": [{"id": "A", "availability": "available", "extra_field": 1}],
            "network_edges": [],
            "service_dependencies": [],
            "attack_source_asset_ids": []
        });
        let result = validate_request(&serde_json::to_string(&json).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
    }

    #[test]
    fn valid_request_passes() {
        let result = validate_request(&make_valid_json());
        assert!(result.is_ok());
    }
}

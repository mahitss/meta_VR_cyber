//! Request and response data models for the graph simulation contract.
//!
//! All types use `#[serde(deny_unknown_fields)]` to enforce strict
//! deserialization per the request schema's `additionalProperties: false`.

use serde::{Deserialize, Serialize};

/// The current contract version supported by the graph simulation engine.
pub const CONTRACT_VERSION: &str = "1.0";

// ---------------------------------------------------------------------------
// Resource identifier validation
// ---------------------------------------------------------------------------

/// A resource identifier (asset ID, edge ID, dependency ID, scenario ID) must:
/// - Start with an alphanumeric character
/// - Contain only alphanumeric, `.`, `_`, `:`, or `-` thereafter
/// - Be at most 64 characters
pub fn validate_resource_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == ':' || c == '-')
}

/// A request ID is a correlation identifier (not a resource identifier).
/// It must be printable ASCII, 1–256 characters.
pub fn validate_request_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.is_ascii()
        && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

// ---------------------------------------------------------------------------
// Request models
// ---------------------------------------------------------------------------

/// Graph simulation request (contract version 1.0).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphSimulationRequest {
    pub contract_version: String,
    pub request_id: String,
    pub scenario_id: String,
    pub assets: Vec<Asset>,
    pub network_edges: Vec<NetworkEdge>,
    pub service_dependencies: Vec<ServiceDependency>,
    pub attack_source_asset_ids: Vec<String>,
}

/// An infrastructure asset.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub id: String,
    pub availability: String,
}

/// A directed network relationship.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkEdge {
    pub id: String,
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub enabled: bool,
}

/// A required service dependency.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceDependency {
    pub id: String,
    pub dependent_asset_id: String,
    pub dependency_asset_id: String,
}

// ---------------------------------------------------------------------------
// Response models
// ---------------------------------------------------------------------------

/// Graph simulation response (contract version 1.0).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GraphSimulationResponse {
    pub contract_version: String,
    pub request_id: String,
    pub scenario_id: String,
    pub network_reachability: NetworkReachability,
    pub service_impact: ServiceImpact,
}

/// Network reachability result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NetworkReachability {
    pub reachable_asset_ids: Vec<String>,
    pub unreachable_asset_ids: Vec<String>,
    pub witnesses: Vec<Witness>,
}

/// A deterministic shortest-path witness for a reachable asset.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Witness {
    pub target_asset: String,
    pub source_asset: String,
    pub asset_path: Vec<String>,
    pub edge_path: Vec<String>,
}

/// Service dependency impact result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ServiceImpact {
    pub initially_unavailable_asset_ids: Vec<String>,
    pub impacted_dependent_asset_ids: Vec<String>,
    pub unavailable_asset_ids: Vec<String>,
}

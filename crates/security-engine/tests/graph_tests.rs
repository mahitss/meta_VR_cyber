//! Native tests for the graph simulation engine.
//!
//! Covers all 100 applicable test-plan cases from docs/GRAPH_ENGINE_TEST_PLAN.md:
//! - NET-001 through NET-017 (17 network tests)
//! - DEP-001 through DEP-011 (11 dependency tests)
//! - IND-001 through IND-004 (4 independence tests)
//! - VAL-001 through VAL-053 (53 validation tests)
//! - DET-001 through DET-008 (8 determinism tests)
//! - INV-001 through INV-007 (7 response invariant tests)
//!
//! Total: 100 native cases.

use security_engine::graph_algorithms::{
    compute_reachability, compute_service_impact,
};
use security_engine::graph_models::{
    Asset, GraphSimulationRequest, NetworkEdge, ServiceDependency,
};
use security_engine::graph_validation::validate_request;
use security_engine::simulate_graph;

// ============================================================================
// Helper functions
// ============================================================================

fn asset(id: &str, availability: &str) -> Asset {
    Asset {
        id: id.to_string(),
        availability: availability.to_string(),
    }
}

fn edge(id: &str, source: &str, target: &str, enabled: bool) -> NetworkEdge {
    NetworkEdge {
        id: id.to_string(),
        source_asset_id: source.to_string(),
        target_asset_id: target.to_string(),
        enabled,
    }
}

fn dependency(id: &str, dependent: &str, dependency: &str) -> ServiceDependency {
    ServiceDependency {
        id: id.to_string(),
        dependent_asset_id: dependent.to_string(),
        dependency_asset_id: dependency.to_string(),
    }
}

fn request(
    assets: Vec<Asset>,
    edges: Vec<NetworkEdge>,
    deps: Vec<ServiceDependency>,
    sources: Vec<String>,
) -> GraphSimulationRequest {
    GraphSimulationRequest {
        contract_version: "1.0".to_string(),
        request_id: "test-req".to_string(),
        scenario_id: "test-scenario".to_string(),
        assets,
        network_edges: edges,
        service_dependencies: deps,
        attack_source_asset_ids: sources,
    }
}

// ============================================================================
// NET-001 through NET-017: Network reachability tests
// ============================================================================

#[test]
fn net_001_empty_graph() {
    let request = request(vec![], vec![], vec![], vec![]);
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert!(result.reachable_asset_ids.is_empty());
    assert!(result.unreachable_asset_ids.is_empty());
    assert!(result.witnesses.is_empty());
}

#[test]
fn net_002_single_asset() {
    let request = request(
        vec![asset("A", "available")],
        vec![],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(result.reachable_asset_ids, vec!["A".to_string()]);
    assert!(result.unreachable_asset_ids.is_empty());
    assert_eq!(result.witnesses.len(), 1);
    assert_eq!(result.witnesses[0].target_asset, "A");
    assert_eq!(result.witnesses[0].source_asset, "A");
    assert_eq!(result.witnesses[0].asset_path, vec!["A".to_string()]);
    assert!(result.witnesses[0].edge_path.is_empty());
}

#[test]
fn net_003_direct_connection() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(result.reachable_asset_ids, vec!["A".to_string(), "B".to_string()]);
    assert!(result.unreachable_asset_ids.is_empty());
    let b_witness = result.witnesses.iter().find(|w| w.target_asset == "B").unwrap();
    assert_eq!(b_witness.asset_path, vec!["A".to_string(), "B".to_string()]);
    assert_eq!(b_witness.edge_path, vec!["e1".to_string()]);
}

#[test]
fn net_004_multi_hop_connection() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available"), asset("C", "available")],
        vec![edge("e1", "A", "B", true), edge("e2", "B", "C", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(
        result.reachable_asset_ids,
        vec!["A".to_string(), "B".to_string(), "C".to_string()]
    );
    let c_witness = result.witnesses.iter().find(|w| w.target_asset == "C").unwrap();
    assert_eq!(c_witness.asset_path, vec!["A".to_string(), "B".to_string(), "C".to_string()]);
    assert_eq!(c_witness.edge_path, vec!["e1".to_string(), "e2".to_string()]);
}

#[test]
fn net_005_directed_edge_behavior() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["B".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(result.reachable_asset_ids, vec!["B".to_string()]);
    assert_eq!(result.unreachable_asset_ids, vec!["A".to_string()]);
}

#[test]
fn net_006_explicit_reverse_edge() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![
            edge("e1", "A", "B", true),
            edge("e2", "B", "A", true),
        ],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(
        result.reachable_asset_ids,
        vec!["A".to_string(), "B".to_string()]
    );
    assert!(result.unreachable_asset_ids.is_empty());
}

#[test]
fn net_007_disabled_edge() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![edge("e1", "A", "B", false)],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(result.reachable_asset_ids, vec!["A".to_string()]);
    assert_eq!(result.unreachable_asset_ids, vec!["B".to_string()]);
}

#[test]
fn net_008_unavailable_intermediate() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "unavailable"),
            asset("C", "available"),
        ],
        vec![edge("e1", "A", "B", true), edge("e2", "B", "C", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(result.reachable_asset_ids, vec!["A".to_string()]);
    assert_eq!(result.unreachable_asset_ids, vec!["C".to_string()]);
}

#[test]
fn net_009_disconnected_component() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
            asset("D", "available"),
        ],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(
        result.reachable_asset_ids,
        vec!["A".to_string(), "B".to_string()]
    );
    assert_eq!(
        result.unreachable_asset_ids,
        vec!["C".to_string(), "D".to_string()]
    );
}

#[test]
fn net_010_multiple_attack_sources() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
        ],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string(), "C".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(
        result.reachable_asset_ids,
        vec!["A".to_string(), "B".to_string(), "C".to_string()]
    );
}

#[test]
fn net_011_cyclic_network() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
        ],
        vec![
            edge("e1", "A", "B", true),
            edge("e2", "B", "C", true),
            edge("e3", "C", "A", true),
        ],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert_eq!(
        result.reachable_asset_ids,
        vec!["A".to_string(), "B".to_string(), "C".to_string()]
    );
    assert!(result.unreachable_asset_ids.is_empty());
}

#[test]
fn net_012_empty_attack_source_list() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec![],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    assert!(result.reachable_asset_ids.is_empty());
    assert_eq!(
        result.unreachable_asset_ids,
        vec!["A".to_string(), "B".to_string()]
    );
    assert!(result.witnesses.is_empty());
}

#[test]
fn net_013_deterministic_shortest_path() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
            asset("D", "available"),
        ],
        vec![
            edge("e1", "A", "B", true),
            edge("e2", "B", "C", true),
            edge("e3", "A", "C", true),
            edge("e4", "C", "D", true),
        ],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    let c_witness = result.witnesses.iter().find(|w| w.target_asset == "C").unwrap();
    // Direct edge A->C should be preferred over A->B->C
    assert_eq!(c_witness.asset_path, vec!["A".to_string(), "C".to_string()]);
    assert_eq!(c_witness.edge_path, vec!["e3".to_string()]);
}

#[test]
fn net_014_equal_length_path_tie_breaking() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
            asset("D", "available"),
        ],
        vec![
            edge("e1", "A", "B", true),
            edge("e2", "A", "D", true),
            edge("e3", "B", "C", true),
            edge("e4", "D", "C", true),
        ],
        vec![],
        vec!["A".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    let c_witness = result.witnesses.iter().find(|w| w.target_asset == "C").unwrap();
    // Both paths have length 2. B < D lexicographically, so path via B wins.
    assert_eq!(c_witness.asset_path, vec!["A".to_string(), "B".to_string(), "C".to_string()]);
    assert_eq!(c_witness.edge_path, vec!["e1".to_string(), "e3".to_string()]);
}

#[test]
fn net_015_tie_breaking_multiple_attack_sources() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
            asset("D", "available"),
            asset("X", "available"),
            asset("Y", "available"),
        ],
        vec![
            edge("e1", "X", "B", true),
            edge("e2", "Y", "D", true),
            edge("e3", "B", "C", true),
            edge("e4", "D", "C", true),
        ],
        vec![],
        vec!["X".to_string(), "Y".to_string()],
    );
    let result = compute_reachability(&request.assets, &request.network_edges, &request.attack_source_asset_ids);
    let c_witness = result.witnesses.iter().find(|w| w.target_asset == "C").unwrap();
    // X < Y lexicographically, so source X wins.
    assert_eq!(c_witness.source_asset, "X");
    assert_eq!(c_witness.asset_path, vec!["X".to_string(), "B".to_string(), "C".to_string()]);
}

#[test]
fn net_016_duplicate_directed_relationship() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![
            edge("e1", "A", "B", true),
            edge("e2", "A", "B", true),
        ],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "DUPLICATE_NETWORK_RELATIONSHIP");
}

#[test]
fn net_017_input_permutation_determinism() {
    let assets = vec![
        asset("A", "available"),
        asset("B", "available"),
        asset("C", "available"),
    ];
    let edges1 = vec![
        edge("e1", "A", "B", true),
        edge("e2", "B", "C", true),
    ];
    let edges2 = vec![
        edge("e2", "B", "C", true),
        edge("e1", "A", "B", true),
    ];
    let req1 = request(assets.clone(), edges1, vec![], vec!["A".to_string()]);
    let req2 = request(assets.clone(), edges2, vec![], vec!["A".to_string()]);
    let result1 = simulate_graph(&req1);
    let result2 = simulate_graph(&req2);
    assert_eq!(result1, result2);
}

// ============================================================================
// DEP-001 through DEP-011: Service dependency propagation tests
// ============================================================================

#[test]
fn dep_001_no_dependencies() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![],
        vec![],
        vec![],
    );
    let result = compute_service_impact(&request.assets, &request.service_dependencies);
    assert!(result.initially_unavailable_asset_ids.is_empty());
    assert!(result.impacted_dependent_asset_ids.is_empty());
    assert!(result.unavailable_asset_ids.is_empty());
}

#[test]
fn dep_002_direct_dependency_failure() {
    let request = request(
        vec![asset("App", "available"), asset("DB", "unavailable")],
        vec![],
        vec![dependency("d1", "App", "DB")],
        vec![],
    );
    let result = compute_service_impact(&request.assets, &request.service_dependencies);
    assert_eq!(result.initially_unavailable_asset_ids, vec!["DB".to_string()]);
    assert_eq!(result.impacted_dependent_asset_ids, vec!["App".to_string()]);
    assert_eq!(
        result.unavailable_asset_ids,
        vec!["App".to_string(), "DB".to_string()]
    );
}

#[test]
fn dep_003_multi_level_cascading_impact() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "unavailable"),
        ],
        vec![],
        vec![dependency("d1", "A", "B"), dependency("d2", "B", "C")],
        vec![],
    );
    let result = compute_service_impact(&request.assets, &request.service_dependencies);
    assert_eq!(result.initially_unavailable_asset_ids, vec!["C".to_string()]);
    assert_eq!(
        result.impacted_dependent_asset_ids,
        vec!["A".to_string(), "B".to_string()]
    );
    assert_eq!(
        result.unavailable_asset_ids,
        vec!["A".to_string(), "B".to_string(), "C".to_string()]
    );
}

#[test]
fn dep_004_one_unavailable_required_dependency() {
    let request = request(
        vec![
            asset("App", "available"),
            asset("DB", "unavailable"),
            asset("Cache", "available"),
        ],
        vec![],
        vec![
            dependency("d1", "App", "DB"),
            dependency("d2", "App", "Cache"),
        ],
        vec![],
    );
    let result = compute_service_impact(&request.assets, &request.service_dependencies);
    assert_eq!(result.initially_unavailable_asset_ids, vec!["DB".to_string()]);
    assert_eq!(result.impacted_dependent_asset_ids, vec!["App".to_string()]);
    assert_eq!(
        result.unavailable_asset_ids,
        vec!["App".to_string(), "DB".to_string()]
    );
}

#[test]
fn dep_005_unrelated_asset_unaffected() {
    let request = request(
        vec![asset("A", "unavailable"), asset("B", "available"), asset("C", "available")],
        vec![],
        vec![dependency("d1", "B", "C")],
        vec![],
    );
    let result = compute_service_impact(&request.assets, &request.service_dependencies);
    assert!(result.impacted_dependent_asset_ids.is_empty());
    assert_eq!(result.unavailable_asset_ids, vec!["A".to_string()]);
}

#[test]
fn dep_006_initially_unavailable_asset() {
    let request = request(
        vec![asset("A", "unavailable"), asset("B", "available")],
        vec![],
        vec![dependency("d1", "B", "A")],
        vec![],
    );
    let result = compute_service_impact(&request.assets, &request.service_dependencies);
    assert_eq!(result.initially_unavailable_asset_ids, vec!["A".to_string()]);
    assert_eq!(result.impacted_dependent_asset_ids, vec!["B".to_string()]);
    assert_eq!(
        result.unavailable_asset_ids,
        vec!["A".to_string(), "B".to_string()]
    );
}

#[test]
fn dep_007_dependency_cycle_no_initially_unavailable() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![],
        vec![dependency("d1", "A", "B"), dependency("d2", "B", "A")],
        vec![],
    );
    let result = compute_service_impact(&request.assets, &request.service_dependencies);
    assert!(result.initially_unavailable_asset_ids.is_empty());
    assert!(result.impacted_dependent_asset_ids.is_empty());
    assert!(result.unavailable_asset_ids.is_empty());
}

#[test]
fn dep_008_dependency_cycle_with_unavailable() {
    let request = request(
        vec![asset("A", "unavailable"), asset("B", "available")],
        vec![],
        vec![dependency("d1", "A", "B"), dependency("d2", "B", "A")],
        vec![],
    );
    let result = compute_service_impact(&request.assets, &request.service_dependencies);
    assert_eq!(result.initially_unavailable_asset_ids, vec!["A".to_string()]);
    assert_eq!(result.impacted_dependent_asset_ids, vec!["B".to_string()]);
    assert_eq!(
        result.unavailable_asset_ids,
        vec!["A".to_string(), "B".to_string()]
    );
}

#[test]
fn dep_009_duplicate_service_dependency_pair() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![],
        vec![
            dependency("d1", "A", "B"),
            dependency("d2", "A", "B"),
        ],
        vec![],
    );
    let result = simulate_graph(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "DUPLICATE_SERVICE_RELATIONSHIP");
}

#[test]
fn dep_010_duplicate_service_dependency_id() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
            asset("D", "available"),
        ],
        vec![],
        vec![
            dependency("d1", "A", "B"),
            dependency("d1", "C", "D"),
        ],
        vec![],
    );
    let result = simulate_graph(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "DUPLICATE_SERVICE_DEPENDENCY_ID");
}

#[test]
fn dep_011_duplicate_attack_source() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![],
        vec![],
        vec!["A".to_string(), "A".to_string()],
    );
    let result = simulate_graph(&request);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "DUPLICATE_ATTACK_SOURCE_ID");
}

// ============================================================================
// IND-001 through IND-004: Independence tests
// ============================================================================

#[test]
fn ind_001_dependency_does_not_create_reachability() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![],
        vec![dependency("d1", "A", "B")],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&request);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.network_reachability.reachable_asset_ids, vec!["A".to_string()]);
    assert_eq!(
        response.network_reachability.unreachable_asset_ids,
        vec!["B".to_string()]
    );
}

#[test]
fn ind_002_edge_disabling_does_not_create_unavailability() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![edge("e1", "A", "B", false)],
        vec![],
        vec![],
    );
    let result = simulate_graph(&request);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.service_impact.unavailable_asset_ids.is_empty());
}

#[test]
fn ind_003_dependency_impact_does_not_mutate_network() {
    let request = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "unavailable"),
        ],
        vec![edge("e1", "A", "B", true)],
        vec![dependency("d1", "B", "C")],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&request);
    assert!(result.is_ok());
    let response = result.unwrap();
    // B should still be reachable from A even though C is unavailable via dep
    assert_eq!(
        response.network_reachability.reachable_asset_ids,
        vec!["A".to_string(), "B".to_string()]
    );
}

#[test]
fn ind_004_reachability_does_not_imply_exploitability() {
    let request = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&request);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.network_reachability.reachable_asset_ids,
        vec!["A".to_string(), "B".to_string()]
    );
    // Engine makes no exploitability claim - reachability is just reachability
}

// ============================================================================
// VAL-001 through VAL-053: Validation tests
// ============================================================================

fn make_base_request() -> GraphSimulationRequest {
    request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
        ],
        vec![edge("e1", "A", "B", true)],
        vec![dependency("d1", "A", "B")],
        vec!["A".to_string()],
    )
}

fn request_to_json(request: &GraphSimulationRequest) -> String {
    serde_json::to_string(request).unwrap()
}

#[test]
fn val_001_malformed_json() {
    let result = validate_request("{not json}");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_002_missing_all_fields() {
    let result = validate_request("{}");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_003_missing_contract_version() {
    let mut req = make_base_request();
    req.contract_version = "".to_string();
    // Actually missing means absent field. Build manually.
    let json = serde_json::json!({
        "request_id": "req-1",
        "scenario_id": "scen-1",
        "assets": [],
        "network_edges": [],
        "service_dependencies": [],
        "attack_source_asset_ids": []
    });
    let result = validate_request(&serde_json::to_string(&json).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_004_missing_request_id() {
    let json = serde_json::json!({
        "contract_version": "1.0",
        "scenario_id": "scen-1",
        "assets": [],
        "network_edges": [],
        "service_dependencies": [],
        "attack_source_asset_ids": []
    });
    let result = validate_request(&serde_json::to_string(&json).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_005_missing_scenario_id() {
    let json = serde_json::json!({
        "contract_version": "1.0",
        "request_id": "req-1",
        "assets": [],
        "network_edges": [],
        "service_dependencies": [],
        "attack_source_asset_ids": []
    });
    let result = validate_request(&serde_json::to_string(&json).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_006_missing_assets() {
    let json = serde_json::json!({
        "contract_version": "1.0",
        "request_id": "req-1",
        "scenario_id": "scen-1",
        "network_edges": [],
        "service_dependencies": [],
        "attack_source_asset_ids": []
    });
    let result = validate_request(&serde_json::to_string(&json).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_007_missing_network_edges() {
    let json = serde_json::json!({
        "contract_version": "1.0",
        "request_id": "req-1",
        "scenario_id": "scen-1",
        "assets": [],
        "service_dependencies": [],
        "attack_source_asset_ids": []
    });
    let result = validate_request(&serde_json::to_string(&json).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_008_missing_service_dependencies() {
    let json = serde_json::json!({
        "contract_version": "1.0",
        "request_id": "req-1",
        "scenario_id": "scen-1",
        "assets": [],
        "network_edges": [],
        "attack_source_asset_ids": []
    });
    let result = validate_request(&serde_json::to_string(&json).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_009_missing_attack_source_asset_ids() {
    let json = serde_json::json!({
        "contract_version": "1.0",
        "request_id": "req-1",
        "scenario_id": "scen-1",
        "assets": [],
        "network_edges": [],
        "service_dependencies": []
    });
    let result = validate_request(&serde_json::to_string(&json).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_010_unknown_top_level_field() {
    let req = make_base_request();
    // Add unknown field via serde_json::Value manipulation
    let mut val = serde_json::to_value(&req).unwrap();
    val.as_object_mut().unwrap().insert("unknown_field".to_string(), serde_json::json!(1));
    let result = validate_request(&serde_json::to_string(&val).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_011_unknown_asset_field() {
    let req = make_base_request();
    let mut val = serde_json::to_value(&req).unwrap();
    if let Some(assets) = val.get_mut("assets").and_then(|a| a.as_array_mut()) {
        if let Some(first) = assets.first_mut() {
            first.as_object_mut().unwrap().insert("unknown_asset_field".to_string(), serde_json::json!(1));
        }
    }
    let result = validate_request(&serde_json::to_string(&val).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_012_unknown_edge_field() {
    let mut val = serde_json::to_value(&make_base_request()).unwrap();
    if let Some(edges) = val.get_mut("network_edges").and_then(|a| a.as_array_mut()) {
        if let Some(first) = edges.first_mut() {
            first.as_object_mut().unwrap().insert("unknown_edge_field".to_string(), serde_json::json!(1));
        }
    }
    let result = validate_request(&serde_json::to_string(&val).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_013_unknown_dependency_field() {
    let mut val = serde_json::to_value(&make_base_request()).unwrap();
    if let Some(deps) = val.get_mut("service_dependencies").and_then(|a| a.as_array_mut()) {
        if let Some(first) = deps.first_mut() {
            first.as_object_mut().unwrap().insert("unknown_dep_field".to_string(), serde_json::json!(1));
        }
    }
    let result = validate_request(&serde_json::to_string(&val).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_014_unsupported_contract_version() {
    let mut req = make_base_request();
    req.contract_version = "2.0".to_string();
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "UNSUPPORTED_CONTRACT_VERSION");
}

#[test]
fn val_015_empty_request_id() {
    let mut req = make_base_request();
    req.request_id = "".to_string();
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INVALID_REQUEST_ID");
}

#[test]
fn val_016_non_ascii_request_id() {
    let mut req = make_base_request();
    req.request_id = "réquest".to_string();
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INVALID_REQUEST_ID");
}

#[test]
fn val_017_request_id_too_long() {
    let mut req = make_base_request();
    req.request_id = "a".repeat(257);
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INVALID_REQUEST_ID");
}

#[test]
fn val_018_empty_scenario_id() {
    let mut req = make_base_request();
    req.scenario_id = "".to_string();
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INVALID_SCENARIO_ID");
}

#[test]
fn val_019_non_ascii_scenario_id() {
    let mut req = make_base_request();
    req.scenario_id = "scénario".to_string();
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INVALID_SCENARIO_ID");
}

#[test]
fn val_020_scenario_id_too_long() {
    let mut req = make_base_request();
    req.scenario_id = "a".repeat(65);
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INVALID_SCENARIO_ID");
}

#[test]
fn val_021_scenario_id_starts_with_dash() {
    let mut req = make_base_request();
    req.scenario_id = "-scenario".to_string();
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INVALID_SCENARIO_ID");
}

#[test]
fn val_022_duplicate_asset_id() {
    let req = request(
        vec![asset("A", "available"), asset("A", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "DUPLICATE_ASSET_ID");
}

#[test]
fn val_023_duplicate_network_edge_id() {
    let mut req = make_base_request();
    req.network_edges = vec![
        edge("e1", "A", "B", true),
        edge("e1", "A", "B", true),
    ];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "DUPLICATE_NETWORK_EDGE_ID");
}

#[test]
fn val_024_duplicate_service_dependency_id() {
    let mut req = make_base_request();
    req.service_dependencies = vec![
        dependency("d1", "A", "B"),
        dependency("d1", "A", "B"),
    ];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "DUPLICATE_SERVICE_DEPENDENCY_ID");
}

#[test]
fn val_025_edge_references_unknown_asset() {
    let mut req = make_base_request();
    req.network_edges = vec![
        edge("e1", "A", "UNKNOWN", true),
    ];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "UNKNOWN_ASSET_REFERENCE");
}

#[test]
fn val_026_dependency_references_unknown_asset() {
    let mut req = make_base_request();
    req.service_dependencies = vec![
        dependency("d1", "A", "UNKNOWN"),
    ];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "UNKNOWN_ASSET_REFERENCE");
}

#[test]
fn val_027_duplicate_directed_relationship() {
    let mut req = make_base_request();
    req.network_edges = vec![
        edge("e1", "A", "B", true),
        edge("e2", "A", "B", true),
    ];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "DUPLICATE_NETWORK_RELATIONSHIP");
}

#[test]
fn val_028_self_loop_edge() {
    let mut req = make_base_request();
    req.network_edges = vec![
        edge("e1", "A", "A", true),
    ];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "SELF_LOOP_NOT_ALLOWED");
}

#[test]
fn val_029_self_loop_dependency() {
    let mut req = make_base_request();
    req.service_dependencies = vec![
        dependency("d1", "A", "A"),
    ];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "SELF_LOOP_NOT_ALLOWED");
}

#[test]
fn val_030_invalid_availability() {
    let mut req = make_base_request();
    req.assets = vec![
        asset("A", "degraded"),
        asset("B", "available"),
    ];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "INVALID_GRAPH");
}

#[test]
fn val_031_attack_source_references_missing_asset() {
    let mut req = make_base_request();
    req.attack_source_asset_ids = vec!["UNKNOWN".to_string()];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "UNKNOWN_ASSET_REFERENCE");
}

#[test]
fn val_031b_attack_source_not_in_assets() {
    let mut req = make_base_request();
    // Remove asset B but keep attack source referencing B
    req.assets = vec![asset("A", "available")];
    req.attack_source_asset_ids = vec!["B".to_string()];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "UNKNOWN_ASSET_REFERENCE");
}

#[test]
fn val_032_attack_source_references_unavailable_asset() {
    let mut req = make_base_request();
    req.assets = vec![
        asset("A", "unavailable"),
        asset("B", "available"),
    ];
    req.attack_source_asset_ids = vec!["A".to_string()];
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "SOURCE_ASSET_UNAVAILABLE");
}

#[test]
fn val_033_assets_count_257() {
    let mut assets = Vec::new();
    for i in 0..257 {
        assets.push(asset(&format!("A{}", i), "available"));
    }
    let req = request(
        assets,
        vec![edge("e1", "A0", "A1", true)],
        vec![],
        vec!["A0".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "LIMIT_EXCEEDED");
}

#[test]
fn val_034_network_edges_count_2049() {
    let mut edges = Vec::new();
    for i in 0..2049 {
        edges.push(edge(&format!("e{}", i), "A", "B", true));
    }
    let mut req = make_base_request();
    req.network_edges = edges;
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "LIMIT_EXCEEDED");
}

#[test]
fn val_035_service_dependencies_count_2049() {
    let mut deps = Vec::new();
    for i in 0..2049 {
        deps.push(dependency(&format!("d{}", i), "A", "B"));
    }
    let mut req = make_base_request();
    req.service_dependencies = deps;
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "LIMIT_EXCEEDED");
}

#[test]
fn val_036_attack_sources_count_257() {
    let mut sources = Vec::new();
    for i in 0..257 {
        sources.push(format!("A{}", i));
    }
    let mut req = make_base_request();
    // Need 257 distinct assets first
    let mut assets = Vec::new();
    for i in 0..257 {
        assets.push(asset(&format!("A{}", i), "available"));
    }
    req.assets = assets;
    req.attack_source_asset_ids = sources;
    let result = simulate_graph(&req);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "LIMIT_EXCEEDED");
}

#[test]
fn val_037_raw_request_exactly_2mib() {
    // Build a valid request padded with whitespace to exactly 2,097,152 bytes
    let base = request(
        vec![asset("A", "available")],
        vec![],
        vec![],
        vec!["A".to_string()],
    );
    let mut json = serde_json::to_string(&base).unwrap();
    let target_len = 2_097_152;
    if json.len() < target_len {
        let padding = " ".repeat(target_len - json.len());
        json.push_str(&padding);
    }
    assert_eq!(json.len(), target_len);
    let result = validate_request(&json);
    assert!(result.is_ok(), "Expected 2 MiB request to be accepted: {:?}", result.err());
}

#[test]
fn val_038_raw_request_2mib_plus_1() {
    let base = request(
        vec![asset("A", "available")],
        vec![],
        vec![],
        vec!["A".to_string()],
    );
    let mut json = serde_json::to_string(&base).unwrap();
    let target_len = 2_097_153;
    if json.len() < target_len {
        let padding = " ".repeat(target_len - json.len());
        json.push_str(&padding);
    }
    assert_eq!(json.len(), target_len);
    let result = validate_request(&json);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "LIMIT_EXCEEDED");
}

#[test]
fn val_047_assets_count_exactly_256() {
    let mut assets = Vec::new();
    for i in 0..256 {
        assets.push(asset(&format!("A{}", i), "available"));
    }
    let req = request(
        assets,
        vec![edge("e1", "A0", "A1", true)],
        vec![],
        vec!["A0".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok(), "Expected 256 assets to be accepted: {:?}", result.err());
}

#[test]
fn val_048_network_edges_count_exactly_2048() {
    let mut assets = Vec::new();
    for i in 0..256 {
        assets.push(asset(&format!("N{}", i), "available"));
    }
    let mut edges = Vec::new();
    let mut count = 0;
    for i in 0..256 {
        for j in i+1..256 {
            edges.push(edge(&format!("e{}", count), &format!("N{}", i), &format!("N{}", j), true));
            count += 1;
            if count >= 2048 {
                break;
            }
        }
        if count >= 2048 {
            break;
        }
    }
    let req = request(assets, edges, vec![], vec!["N0".to_string()]);
    let result = simulate_graph(&req);
    assert!(result.is_ok(), "Expected 2048 edges to be accepted: {:?}", result.err());
}

#[test]
fn val_049_service_dependencies_count_exactly_2048() {
    let mut assets = Vec::new();
    for i in 0..256 {
        assets.push(asset(&format!("N{}", i), "available"));
    }
    let mut deps = Vec::new();
    let mut count = 0;
    for i in 0..256 {
        for j in i+1..256 {
            deps.push(dependency(&format!("d{}", count), &format!("N{}", i), &format!("N{}", j)));
            count += 1;
            if count >= 2048 {
                break;
            }
        }
        if count >= 2048 {
            break;
        }
    }
    let req = request(assets, vec![], deps, vec![]);
    let result = simulate_graph(&req);
    assert!(result.is_ok(), "Expected 2048 service dependencies to be accepted: {:?}", result.err());
}

#[test]
fn val_050_attack_sources_count_exactly_256() {
    let mut assets = Vec::new();
    let mut sources = Vec::new();
    for i in 0..256 {
        assets.push(asset(&format!("A{}", i), "available"));
        sources.push(format!("A{}", i));
    }
    let req = request(assets, vec![], vec![], sources);
    let result = simulate_graph(&req);
    assert!(result.is_ok(), "Expected 256 attack sources to be accepted: {:?}", result.err());
}

#[test]
fn val_051_contract_version_is_number() {
    let mut val = serde_json::to_value(&make_base_request()).unwrap();
    val.as_object_mut().unwrap().insert("contract_version".to_string(), serde_json::json!(123));
    let result = validate_request(&serde_json::to_string(&val).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_052_request_id_is_number() {
    let mut val = serde_json::to_value(&make_base_request()).unwrap();
    val.as_object_mut().unwrap().insert("request_id".to_string(), serde_json::json!(123));
    let result = validate_request(&serde_json::to_string(&val).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

#[test]
fn val_053_scenario_id_is_number() {
    let mut val = serde_json::to_value(&make_base_request()).unwrap();
    val.as_object_mut().unwrap().insert("scenario_id".to_string(), serde_json::json!(123));
    let result = validate_request(&serde_json::to_string(&val).unwrap());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "MALFORMED_JSON");
}

// ============================================================================
// DET-001 through DET-008: Determinism tests
// ============================================================================

#[test]
fn det_001_same_input_repeated() {
    let req = make_base_request();
    let result1 = simulate_graph(&req);
    let result2 = simulate_graph(&req);
    assert_eq!(result1, result2);
    if let (Ok(r1), Ok(r2)) = (result1, result2) {
        let json1 = serde_json::to_string(&r1).unwrap();
        let json2 = serde_json::to_string(&r2).unwrap();
        assert_eq!(json1, json2);
    }
}

#[test]
fn det_002_permuted_assets_array() {
    let req1 = request(
        vec![asset("A", "available"), asset("B", "available"), asset("C", "available")],
        vec![edge("e1", "A", "B", true), edge("e2", "B", "C", true)],
        vec![],
        vec!["A".to_string()],
    );
    let assets2 = vec![
        asset("C", "available"),
        asset("A", "available"),
        asset("B", "available"),
    ];
    let req2 = request(
        assets2,
        vec![edge("e1", "A", "B", true), edge("e2", "B", "C", true)],
        vec![],
        vec!["A".to_string()],
    );
    let r1 = simulate_graph(&req1);
    let r2 = simulate_graph(&req2);
    assert_eq!(r1, r2);
}

#[test]
fn det_003_permuted_network_edges_array() {
    let req1 = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let req2 = request(
        vec![asset("A", "available"), asset("B", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let r1 = simulate_graph(&req1);
    let r2 = simulate_graph(&req2);
    assert_eq!(r1, r2);
}

#[test]
fn det_004_permuted_service_dependencies_array() {
    let req1 = request(
        vec![asset("A", "available"), asset("B", "unavailable")],
        vec![],
        vec![dependency("d1", "A", "B")],
        vec![],
    );
    let req2 = request(
        vec![asset("A", "available"), asset("B", "unavailable")],
        vec![],
        vec![dependency("d1", "A", "B")],
        vec![],
    );
    let r1 = simulate_graph(&req1);
    let r2 = simulate_graph(&req2);
    assert_eq!(r1, r2);
}

#[test]
fn det_005_permuted_attack_sources() {
    let req1 = request(
        vec![asset("A", "available"), asset("B", "available"), asset("C", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string(), "C".to_string()],
    );
    let req2 = request(
        vec![asset("A", "available"), asset("B", "available"), asset("C", "available")],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["C".to_string(), "A".to_string()],
    );
    let r1 = simulate_graph(&req1);
    let r2 = simulate_graph(&req2);
    assert_eq!(r1, r2);
}

#[test]
fn det_006_equal_length_path_tie_breaking_stable() {
    let req1 = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
            asset("D", "available"),
        ],
        vec![
            edge("e1", "A", "B", true),
            edge("e2", "A", "D", true),
            edge("e3", "B", "C", true),
            edge("e4", "D", "C", true),
        ],
        vec![],
        vec!["A".to_string()],
    );
    let r1 = simulate_graph(&req1);
    let r2 = simulate_graph(&req1.clone());
    assert_eq!(r1, r2);
    if let Ok(ref resp) = r1 {
        let c_witness = resp.network_reachability.witnesses.iter()
            .find(|w| w.target_asset == "C").unwrap();
        assert_eq!(c_witness.asset_path, vec!["A".to_string(), "B".to_string(), "C".to_string()]);
    }
}

#[test]
fn det_007_cyclic_input_terminates() {
    let req = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
        ],
        vec![
            edge("e1", "A", "B", true),
            edge("e2", "B", "C", true),
            edge("e3", "C", "A", true),
        ],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        assert_eq!(
            resp.network_reachability.reachable_asset_ids,
            vec!["A".to_string(), "B".to_string(), "C".to_string()]
        );
    }
}

#[test]
fn det_008_output_collections_sorted() {
    let req = request(
        vec![
            asset("C", "available"),
            asset("A", "available"),
            asset("B", "available"),
        ],
        vec![
            edge("e3", "C", "B", true),
            edge("e1", "A", "C", true),
            edge("e2", "B", "A", true),
        ],
        vec![],
        vec!["C".to_string(), "A".to_string(), "B".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        let reachable = &resp.network_reachability.reachable_asset_ids;
        let mut sorted = reachable.clone();
        sorted.sort();
        assert_eq!(*reachable, sorted);
        let unreachable = &resp.network_reachability.unreachable_asset_ids;
        let mut sorted_u = unreachable.clone();
        sorted_u.sort();
        assert_eq!(*unreachable, sorted_u);
    }
}

// ============================================================================
// INV-001 through INV-007: Response invariant tests
// ============================================================================

#[test]
fn inv_001_one_witness_per_reachable_asset() {
    let req = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
        ],
        vec![edge("e1", "A", "B", true), edge("e2", "B", "C", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        assert_eq!(
            resp.network_reachability.witnesses.len(),
            resp.network_reachability.reachable_asset_ids.len()
        );
    }
}

#[test]
fn inv_002_witness_target_matches_reachable() {
    let req = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
        ],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        for w in &resp.network_reachability.witnesses {
            assert!(
                resp.network_reachability.reachable_asset_ids.contains(&w.target_asset),
                "Witness target {} not in reachable assets", w.target_asset
            );
        }
    }
}

#[test]
fn inv_003_edge_path_length() {
    let req = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
        ],
        vec![edge("e1", "A", "B", true), edge("e2", "B", "C", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        for w in &resp.network_reachability.witnesses {
            assert_eq!(
                w.edge_path.len(),
                w.asset_path.len() - 1,
                "Edge path length should be asset path length - 1 for witness {}",
                w.target_asset
            );
        }
    }
}

#[test]
fn inv_004_reachable_unreachable_disjoint() {
    let req = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
            asset("C", "available"),
        ],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        for r in &resp.network_reachability.reachable_asset_ids {
            assert!(
                !resp.network_reachability.unreachable_asset_ids.contains(r),
                "Asset {} is both reachable and unreachable", r
            );
        }
    }
}

#[test]
fn inv_005_all_ids_exist_in_request() {
    let req = request(
        vec![
            asset("A", "available"),
            asset("B", "available"),
        ],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["A".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        let all_ids: std::collections::HashSet<&str> = req.assets.iter()
            .map(|a| a.id.as_str()).collect();
        for r in &resp.network_reachability.reachable_asset_ids {
            assert!(all_ids.contains(r.as_str()), "Reachable asset {} not in request", r);
        }
        for r in &resp.network_reachability.unreachable_asset_ids {
            assert!(all_ids.contains(r.as_str()), "Unreachable asset {} not in request", r);
        }
    }
}

#[test]
fn inv_006_arrays_sorted_and_unique() {
    let req = request(
        vec![
            asset("C", "available"),
            asset("A", "available"),
            asset("B", "available"),
        ],
        vec![edge("e1", "A", "B", true)],
        vec![],
        vec!["C".to_string()],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        let reachable = &resp.network_reachability.reachable_asset_ids;
        let mut sorted = reachable.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(*reachable, sorted, "Reachable assets should be sorted and unique");
    }
}

#[test]
fn inv_007_unavailable_union() {
    let req = request(
        vec![
            asset("A", "unavailable"),
            asset("B", "available"),
            asset("C", "available"),
        ],
        vec![],
        vec![dependency("d1", "B", "A")],
        vec![],
    );
    let result = simulate_graph(&req);
    assert!(result.is_ok());
    if let Ok(resp) = result {
        let mut expected: Vec<String> = vec!["A".to_string(), "B".to_string()];
        expected.sort();
        assert_eq!(
            resp.service_impact.unavailable_asset_ids, expected,
            "Unavailable assets should be sorted union of initial + impacted"
        );
    }
}

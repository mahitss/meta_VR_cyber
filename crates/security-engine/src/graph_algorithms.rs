//! Deterministic graph algorithms for the security simulation engine.
//!
//! Implements:
//! - Multi-source BFS for network reachability with shortest-path witnesses
//! - Reverse dependency BFS for service-impact propagation (OR semantics)
//!
//! All algorithms use deterministic ordered collections (BTreeMap, sorted Vecs)
//! and never depend on HashMap iteration order.

use crate::graph_models::{
    Asset, NetworkEdge, ServiceDependency,
};

/// Result of network reachability computation.
#[derive(Debug, Clone)]
pub struct ReachabilityResult {
    pub reachable_asset_ids: Vec<String>,
    pub unreachable_asset_ids: Vec<String>,
    pub witnesses: Vec<Witness>,
}

/// A shortest-path witness for a reachable asset.
#[derive(Debug, Clone)]
pub struct Witness {
    pub target_asset: String,
    pub source_asset: String,
    pub asset_path: Vec<String>,
    pub edge_path: Vec<String>,
}

/// Result of service-impact propagation.
#[derive(Debug, Clone)]
pub struct ImpactResult {
    pub initially_unavailable_asset_ids: Vec<String>,
    pub impacted_dependent_asset_ids: Vec<String>,
    pub unavailable_asset_ids: Vec<String>,
}

/// Compute deterministic multi-source BFS reachability.
///
/// Rules:
/// - Traverse only enabled edges.
/// - Traverse only assets available in the original request.
/// - Begin from all validated attack sources.
/// - Multiple sources produce a union of reachable assets.
/// - Tie-breaking: sorted source IDs, then sorted adjacency (target, edge id).
pub fn compute_reachability(
    assets: &[Asset],
    network_edges: &[NetworkEdge],
    attack_sources: &[String],
) -> ReachabilityResult {
    // Build asset availability map.
    let availability: std::collections::HashMap<&str, &str> = assets
        .iter()
        .map(|a| (a.id.as_str(), a.availability.as_str()))
        .collect();

    // Build sorted asset ID list.
    let mut all_asset_ids: Vec<String> = assets.iter().map(|a| a.id.clone()).collect();
    all_asset_ids.sort();

    // Build adjacency list: source -> sorted vec of (target, edge_id).
    // Only enabled edges are included.
    let mut adj: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for edge in network_edges.iter() {
        if edge.enabled {
            adj.entry(edge.source_asset_id.clone())
                .or_default()
                .push((edge.target_asset_id.clone(), edge.id.clone()));
        }
    }
    // Sort each adjacency list by (target, edge_id) for determinism.
    for list in adj.values_mut() {
        list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    }

    // Sort attack sources ascending for deterministic processing.
    let mut sorted_sources: Vec<String> = attack_sources.iter().cloned().collect();
    sorted_sources.sort();

    // Multi-source BFS.
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut reachable: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut predecessor: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut pred_edge: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();

    for source in &sorted_sources {
        // Only traverse from available sources.
        if availability.get(source.as_str()) == Some(&"available") {
            if visited.insert(source.clone()) {
                reachable.insert(source.clone());
                queue.push_back(source.clone());
            }
        }
    }

    while let Some(u) = queue.pop_front() {
        if let Some(neighbors) = adj.get(&u) {
            for (target, edge_id) in neighbors.iter() {
                // Only traverse to available, unvisited targets.
                if availability.get(target.as_str()) == Some(&"available")
                    && visited.insert(target.clone())
                {
                    reachable.insert(target.clone());
                    predecessor.insert(target.clone(), u.clone());
                    pred_edge.insert(target.clone(), edge_id.clone());
                    queue.push_back(target.clone());
                }
            }
        }
    }

    // Build sorted reachable and unreachable lists.
    let mut reachable_ids: Vec<String> = reachable.iter().cloned().collect();
    reachable_ids.sort();

    let available_ids: Vec<String> = all_asset_ids
        .iter()
        .filter(|id| availability.get(id.as_str()) == Some(&"available"))
        .cloned()
        .collect();

    let unreachable_ids: Vec<String> = available_ids
        .iter()
        .filter(|id| !reachable.contains(*id))
        .cloned()
        .collect();

    // Build witnesses for each reachable asset.
    let mut witnesses: Vec<Witness> = Vec::new();
    for target in &reachable_ids {
        // Reconstruct path by following predecessor chain.
        let mut path: Vec<String> = Vec::new();
        let mut edges: Vec<String> = Vec::new();
        let mut current = target.clone();
        loop {
            path.push(current.clone());
            if let Some(pred) = predecessor.get(&current) {
                edges.push(pred_edge.get(&current).unwrap().clone());
                current = pred.clone();
            } else {
                // current is a source (no predecessor)
                break;
            }
        }
        path.reverse();
        edges.reverse();

        // `current` is now the source asset for this witness.
        let source_asset = current.clone();

        witnesses.push(Witness {
            target_asset: target.clone(),
            source_asset,
            asset_path: path,
            edge_path: edges,
        });
    }

    // Sort witnesses by target_asset.
    witnesses.sort_by(|a, b| a.target_asset.cmp(&b.target_asset));

    ReachabilityResult {
        reachable_asset_ids: reachable_ids,
        unreachable_asset_ids: unreachable_ids,
        witnesses,
    }
}

/// Compute deterministic service-impact propagation using reverse BFS.
///
/// Direction: dependent_asset_id → dependency_asset_id
/// OR semantics: if any one required dependency is unavailable, the dependent
/// becomes impacted.
pub fn compute_service_impact(
    assets: &[Asset],
    service_dependencies: &[ServiceDependency],
) -> ImpactResult {
    // Initially unavailable assets (sorted).
    let mut initially_unavailable: Vec<String> = assets
        .iter()
        .filter(|a| a.availability == "unavailable")
        .map(|a| a.id.clone())
        .collect();
    initially_unavailable.sort();

    // Build forward dependency map: asset -> sorted vec of dependency IDs.
    let mut deps_map: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for dep in service_dependencies.iter() {
        deps_map
            .entry(dep.dependent_asset_id.clone())
            .or_default()
            .push(dep.dependency_asset_id.clone());
    }
    // Sort each dependency list.
    for list in deps_map.values_mut() {
        list.sort();
    }

    // Build reverse adjacency: dependency -> sorted vec of dependents.
    let mut reverse_adj: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for dep in service_dependencies.iter() {
        reverse_adj
            .entry(dep.dependency_asset_id.clone())
            .or_default()
            .push(dep.dependent_asset_id.clone());
    }
    // Sort each reverse adjacency list by dependent.
    for list in reverse_adj.values_mut() {
        list.sort();
    }

    // BFS propagation with OR semantics.
    let mut visited: std::collections::HashSet<String> =
        initially_unavailable.iter().cloned().collect();
    let mut impacted: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<String> =
        initially_unavailable.iter().cloned().collect();

    while let Some(unavailable_asset) = queue.pop_front() {
        // Find all dependents of this unavailable asset.
        if let Some(dependents) = reverse_adj.get(&unavailable_asset) {
            for dependent in dependents.iter() {
                if visited.contains(dependent) {
                    continue;
                }
                // OR semantics: check if ANY of dependent's dependencies is unavailable.
                let dependent_deps = deps_map.get(dependent);
                let any_dep_unavailable = dependent_deps.map_or(false, |deps| {
                    deps.iter().any(|d| visited.contains(d))
                });

                if any_dep_unavailable {
                    visited.insert(dependent.clone());
                    impacted.insert(dependent.clone());
                    queue.push_back(dependent.clone());
                }
            }
        }
    }

    let mut impacted_ids: Vec<String> = impacted.into_iter().collect();
    impacted_ids.sort();

    let mut unavailable_ids: Vec<String> = initially_unavailable.clone();
    unavailable_ids.extend(impacted_ids.iter().cloned());
    unavailable_ids.sort();
    unavailable_ids.dedup();

    ImpactResult {
        initially_unavailable_asset_ids: initially_unavailable,
        impacted_dependent_asset_ids: impacted_ids,
        unavailable_asset_ids: unavailable_ids,
    }
}

# NetVigil XR — Graph Engine Specification

**Document version:** 1.0  
**Status:** Specification — M003.0  
**Scope:** `security-engine` Rust/WASM crate  
**Implementation status:** Not implemented. This document is a specification only.  
**Implementation prohibited in M003.0.**

## 1. Purpose

This specification defines the complete technical contract, domain model, graph semantics,
validation rules, deterministic algorithms, error behavior, and test strategy for the Rust
cybersecurity simulation engine.

The engine supports two independent graph computations:

1. **Network connectivity and attacker reachability** — directed, enabled-edge graph traversal
   from attack sources.
2. **Service dependency and availability propagation** — cascading unavailability through required
   dependency edges.

These graph types are strictly separate. Neither may be inferred from the other.

## 2. Compatibility with Existing Contracts

### Health-check contract (preserved)

The existing `health_check_json` WASM entry point and its contract version 1.0 request/response
schemas are unchanged:

- Request: `{ "contract_version": "1.0", "request_id": "<string>" }`
- Response: `{ "contract_version": "1.0", "request_id": "<string>", "engine": "security-engine", "status": "ok" }`
- Error: `{ "code": "<string>", "message": "<string>" }`

The graph simulation operation uses a **distinct, explicitly named WASM entry point**
(proposed: `simulate_graph_json`) and its own request/response schemas (version 1.0), documented
in Sections 6–7 and the accompanying contract schema files.

No existing schema, module, or WASM export is modified or removed by this specification.

### ADRs referenced

- **ADR-002 (Rust/WASM runtime boundary):** Locked. This specification conforms to it: all data
  crosses the boundary via JSON serialization (serde_json); Rust performs authoritative validation;
  errors return explicit JSON `{ code, message }` objects, never panics.
- **ADR-004 (Determinism):** Proposed. This specification conforms to it: no wall-clock time, no
  random values, no hash-map iteration order dependence, all inputs explicitly versioned and
  validated.
- **ADR-005 (Authoritative Validation):** Proposed. This specification conforms to it: the Rust
  engine validates all inputs authoritatively; TypeScript must not assume Rust accepts arbitrary
  JSON.

## 3. Domain Model

### Core principle: minimal computational model

The graph-engine computational model is minimal. Display names, asset descriptions, colors, visual
coordinates, risk labels, and other UI metadata remain in the client scenario model unless a
demonstrated engine requirement justifies including them.

### Asset

An asset has:

- `id`: unique identifier (ASCII, see Section 3.4).
- `availability`: `"available"` or `"unavailable"`.

### Network edge

A network edge has:

- `id`: unique identifier.
- `source_asset_id`: source asset identifier.
- `target_asset_id`: destination asset identifier.
- `enabled`: boolean (`true` = traversable, `false` = blocked).

Edges are directed. A connection from A to B does not automatically permit B to reach A.
Bidirectional connectivity requires two explicitly modeled directed edges.

### Service dependency

A service dependency has:

- `id`: unique identifier.
- `dependent_asset_id`: the asset that requires the dependency.
- `dependency_asset_id`: the asset being depended upon.

Direction: `dependent_asset_id → dependency_asset_id`. All listed dependencies are required
(AND semantics).

### Attack sources

A list of initially compromised asset IDs from which modeled reachability is calculated.
An empty source list is permitted and produces an empty reachable set.

### Identifier grammar

Resource IDs (asset IDs, edge IDs, dependency IDs, scenario IDs, request IDs) follow this ASCII
grammar:

- Start with an alphanumeric character (`[A-Za-z0-9]`).
- May subsequently contain alphanumeric characters, `.`, `_`, `:`, or `-`.
- Maximum length: 64 characters for resource identifiers; 256 characters for request IDs.
- All characters must be ASCII (`[\x20-\x7E]`).

Formal regex for resource identifiers: `^[A-Za-z0-9][A-Za-z0-9._:\-]{0,63}$`
Formal regex for request IDs: `^[\x20-\x7E]{1,256}$`

## 4. Graph Semantics

### 4.1 Network reachability

Directed edges only.

#### Reachability rules

1. Begin from the supplied attack-source assets.
2. Traverse only enabled network edges.
3. Traverse only assets whose input availability is `available`.
4. An unavailable asset cannot be reached or used as an intermediate traversal node.
5. Disabled edges are excluded.
6. Network cycles are allowed.
7. Multiple attack sources produce the union of their reachable sets.
8. No relationship may be inferred from a service dependency.
9. Reachability does not prove successful exploitation.

#### Result fields

- `reachable_asset_ids`: sorted array of asset IDs reachable from any attack source.
- `unreachable_asset_ids`: sorted array of asset IDs that were `available` in the input but are
  not reachable.
- `witnesses`: deterministic shortest-path witness for every reachable asset.

#### Witness structure

Each witness identifies:

- `target_asset`: the reachable asset ID.
- `source_asset`: the starting attack source ID.
- `asset_path`: ordered array of asset IDs from source to target (inclusive).
- `edge_path`: ordered array of edge IDs traversed (one less than `asset_path` length).

#### Tie-breaking rule

For equal-length paths, deterministic tie-breaking is based on:
1. Sorted source IDs (ascending).
2. Sorted adjacency records: for each node, outgoing edges sorted by `target_asset_id` then `id`.

No path enumeration is performed. Cycles do not cause non-termination because BFS uses a visited
set.

### 4.2 Service dependency propagation

Direction: `dependent_asset_id → dependency_asset_id`.

#### Propagation rules

1. An asset supplied as unavailable is an initial unavailable asset.
2. If an asset's required dependency is unavailable, the dependent asset becomes impacted.
3. Propagate this impact transitively.
4. All listed dependencies are required (AND semantics).
5. Optional dependencies and alternative-provider logic are out of scope.
6. Dependency cycles are permitted; propagation terminates through a visited set.
7. Do not infer service dependencies from network connections.
8. Do not infer network disconnection from service dependency impact.

#### Result fields

- `initially_unavailable_asset_ids`: sorted array of asset IDs supplied as unavailable in input.
- `impacted_dependent_asset_ids`: sorted array of asset IDs that became impacted through
  propagation, excluding initial unavailable assets.
- `unavailable_asset_ids`: sorted union of initially unavailable and impacted assets.

### 4.3 Independence rule

Network reachability is calculated using the availability and enabled-edge values supplied in the
request. Service-impact propagation is calculated separately.

Derived dependency impact must not silently mutate the network graph during the same simulation
operation. Conversely, network reachability results must not influence service-impact results.

### 4.4 Explicitly prohibited conclusions

The engine must not claim that:

- A reachable asset is exploitable.
- A reachable path represents a confirmed attack.
- An unavailable service proves its host is offline.
- A missing modeled edge proves physical network isolation.
- A calculated impact is a real-world outage.
- A containment recommendation has actually been executed.

These are modeled simulation results only.

## 5. Determinism Requirements

The engine is a pure input-to-output computation.

#### Requirements

- No wall-clock time in graph calculations.
- No random values.
- No network calls or external services.
- No dependence on HashMap iteration order. Use `BTreeMap` or sort before iterating.
- Stable ordering of all returned asset IDs and edge IDs (ascending lexicographic).
- Stable shortest-path tie-breaking (Section 4.1).
- Identical valid input produces byte-equivalent canonical JSON output.

#### Input permutation behavior

For semantically equivalent inputs that differ only in array element order, output ordering and
results must remain identical. The engine sorts all input collections before processing.

## 6. Request Contract (graph-simulation-request.v1.schema.json)

Operation name: `graph_simulation` (proposed WASM export: `simulate_graph_json`).

#### Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contract_version` | string | Yes | Must be `"1.0"`. |
| `request_id` | string | Yes | Non-empty ASCII, max 256 chars. |
| `scenario_id` | string | Yes | Non-empty ASCII, max 64 chars, identifier grammar. |
| `assets` | array of Asset | Yes | Max 256 entries. |
| `network_edges` | array of NetworkEdge | Yes | Max 2,048 entries. |
| `service_dependencies` | array of ServiceDependency | Yes | Max 2,048 entries. |
| `attack_source_asset_ids` | array of string | Yes | Max 256 entries. |

Strict deserialization: `additionalProperties: false` at all levels.

#### Asset

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Resource identifier grammar, max 64 chars. |
| `availability` | string | Yes | `"available"` or `"unavailable"`. |

#### NetworkEdge

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Resource identifier grammar, max 64 chars. |
| `source_asset_id` | string | Yes | References an existing asset ID. |
| `target_asset_id` | string | Yes | References an existing asset ID. |
| `enabled` | boolean | Yes | `true` = traversable, `false` = blocked. |

#### ServiceDependency

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Resource identifier grammar, max 64 chars. |
| `dependent_asset_id` | string | Yes | References an existing asset ID. |
| `dependency_asset_id` | string | Yes | References an existing asset ID. |

## 7. Response Contract (graph-simulation-response.v1.schema.json)

#### Success response

| Field | Type | Description |
|-------|------|-------------|
| `contract_version` | string | Echo of request `contract_version`. |
| `request_id` | string | Echo of request `request_id`. |
| `scenario_id` | string | Echo of request `scenario_id`. |
| `network_reachability` | object | Network reachability result (Section 7.1). |
| `service_impact` | object | Service dependency result (Section 7.2). |

#### 7.1 Network reachability result

| Field | Type | Description |
|-------|------|-------------|
| `reachable_asset_ids` | array of string | Sorted ascending. |
| `unreachable_asset_ids` | array of string | Sorted ascending. Available-but-unreachable assets only. |
| `witnesses` | array of Witness | One per reachable asset. Sorted by `target_asset`. |

#### Witness

| Field | Type | Description |
|-------|------|-------------|
| `target_asset` | string | Reachable asset ID. |
| `source_asset` | string | Starting attack source ID. |
| `asset_path` | array of string | Ordered asset IDs from source to target (inclusive). |
| `edge_path` | array of string | Ordered edge IDs traversed. |

#### 7.2 Service impact result

| Field | Type | Description |
|-------|------|-------------|
| `initially_unavailable_asset_ids` | array of string | Sorted ascending. |
| `impacted_dependent_asset_ids` | array of string | Sorted ascending, excludes initial seeds. |
| `unavailable_asset_ids` | array of string | Sorted ascending union. |

#### Error response

All invalid requests return:

```json
{ "code": "<error-code>", "message": "<human-readable description>" }
```

Error codes are defined in Section 8. All errors return JSON, never panic.

## 8. Validation and Error Taxonomy

### Validation precedence (first failure wins)

1. Malformed JSON body → `MALFORMED_JSON`
2. Unsupported `contract_version` → `UNSUPPORTED_CONTRACT_VERSION`
3. Invalid `request_id` → `INVALID_REQUEST_ID`
4. Invalid `scenario_id` → `INVALID_SCENARIO_ID`
5. Missing required field → `MALFORMED_JSON`
6. Unknown field → `MALFORMED_JSON` (via `additionalProperties: false`)
7. Duplicate asset ID → `DUPLICATE_ASSET_ID`
8. Duplicate network-edge ID → `DUPLICATE_NETWORK_EDGE_ID`
9. Duplicate service-dependency ID → `DUPLICATE_SERVICE_DEPENDENCY_ID`
10. Unknown asset reference (edge or dependency) → `UNKNOWN_ASSET_REFERENCE`
11. Duplicate directed network relationship → `DUPLICATE_NETWORK_RELATIONSHIP`
12. Self-referencing relationship → `SELF_LOOP_NOT_ALLOWED`
13. Invalid `availability` value → `INVALID_GRAPH`
14. Excessively large input collection → `LIMIT_EXCEEDED`
15. Attack source references missing asset → `UNKNOWN_ASSET_REFERENCE`
16. Attack source references unavailable asset → `SOURCE_ASSET_UNAVAILABLE`

### Error codes

| Code | Meaning |
|------|---------|
| `MALFORMED_JSON` | Body is not valid JSON, or missing/unknown fields. |
| `UNSUPPORTED_CONTRACT_VERSION` | `contract_version` is not `"1.0"`. |
| `INVALID_REQUEST_ID` | `request_id` is empty, non-ASCII, or > 256 chars. |
| `INVALID_SCENARIO_ID` | `scenario_id` is empty, non-ASCII, > 64 chars, or violates grammar. |
| `INVALID_GRAPH` | Invalid `availability` value or other graph-level semantic violation. |
| `DUPLICATE_ASSET_ID` | Two assets share the same `id`. |
| `DUPLICATE_NETWORK_EDGE_ID` | Two network edges share the same `id`. |
| `DUPLICATE_SERVICE_DEPENDENCY_ID` | Two dependencies share the same `id`. |
| `UNKNOWN_ASSET_REFERENCE` | Edge or dependency references a non-existent asset ID. |
| `DUPLICATE_NETWORK_RELATIONSHIP` | Two edges have the same `(source, target)` pair. |
| `SELF_LOOP_NOT_ALLOWED` | Edge or dependency references the same asset as source and target. |
| `SOURCE_ASSET_UNAVAILABLE` | Attack source asset has `availability: "unavailable"`. |
| `LIMIT_EXCEEDED` | Input collection exceeds MVP bounds (Section 9). |

### MVP bounds

| Input | Maximum | Rationale |
|-------|---------|-----------|
| Assets | 256 | Sufficient for a representative financial-sector incident scenario; keeps BFS O(V+E) trivial. |
| Network edges | 2,048 | Bounded to prevent pathological graph sizes in client-side WASM. |
| Service dependencies | 2,048 | Same rationale as network edges. |
| Attack sources | 256 | Capped at asset count; multi-source BFS is linear in source count. |
| Resource identifier length | 64 ASCII | Balances readability with fixed-size buffer efficiency. |
| Request ID length | 256 ASCII | Matches existing health-check constraint. |

Compatibility concern: If future scenarios require more than 256 assets or 2,048 edges, bounds must
be raised deliberately with a performance review. This is not an engine bug but a design limit.

## 9. Algorithm Specification

### 9.1 Network reachability — deterministic multi-source BFS

Input: assets, network_edges, attack_source_asset_ids.

1. Build adjacency map: for each enabled edge `(source → target, id)`, add `target` to
   `source`'s out-list. Sort each out-list by `(target_asset_id, id)` for determinism.
2. Initialize queue with all attack sources that are `available` and not unavailable.
   Sort sources ascending.
3. Initialize `visited` set, `reachable` set, `predecessor` map, `pred_edge` map.
4. While queue not empty: pop front node `u`. For each neighbor `v` in sorted out-list:
   - If `v` is `available` and not visited: mark visited, add to reachable, set
     `predecessor[v] = u`, `pred_edge[v] = edge_id`, push `v`.
5. `reachable_asset_ids` = sorted reachable set.
6. `unreachable_asset_ids` = sorted available assets not in reachable set.
7. For each reachable asset, reconstruct path by following predecessor chain back to source,
   then reverse. Build `edge_path` from `pred_edge`.

Complexity: O(V + E) time, O(V + E) space.

### 9.2 Service-impact propagation — reverse dependency BFS

Input: assets, service_dependencies.

1. Build reverse adjacency: for each dependency `(dependent → dep)`, add `dependent` to
   `dep`'s reverse out-list (nodes impacted when `dep` becomes unavailable). Sort each list by
   `dependent_asset_id` for determinism.
2. Initialize queue with initially unavailable assets (sorted ascending).
3. Initialize `impacted` set, `visited` set = initially unavailable assets.
4. While queue not empty: pop front node `u`. For each `dependent` in sorted reverse out-list:
   - If `dependent` is not in visited: check AND semantics — all of `dependent`'s dependencies
     must be unavailable. If so, mark visited, add to impacted, push `dependent`.
5. `initially_unavailable_asset_ids` = sorted initial seeds.
6. `impacted_dependent_asset_ids` = sorted impacted set (excludes initial seeds).
7. `unavailable_asset_ids` = sorted union.

Complexity: O(V + E) time, O(V + E) space.

AND-semantics check: when a node `d` has multiple dependencies, `d` becomes impacted only when
all its dependencies are unavailable. The algorithm tracks a count of unavailable dependencies
per node; when the count reaches the total dependency count, the node is impacted.

### 9.3 Deterministic collections

All internal maps use `BTreeMap` (key-sorted) or `Vec` with explicit `.sort()` before iteration.
All output arrays are sorted ascending lexicographically before serialization.

## 10. Complexity Summary

| Algorithm | Time | Space |
|-----------|------|-------|
| Network reachability (BFS) | O(V + E) | O(V + E) |
| Shortest-path witness | O(V + E) (included in BFS) | O(V) |
| Service-impact propagation | O(V + E) | O(V + E) |
| Validation | O(V + E + D) where D = duplicates check | O(V + E) |

No graph libraries are added. Standard library collections only.

## 11. Scope Exclusions

The following are explicitly out of scope for the graph engine:

- Exploitability analysis (reachability ≠ exploitation).
- Real-world outage prediction.
- Physical network isolation verification.
- Containment action execution.
- Risk scoring or business impact quantification.
- Attack-path enumeration beyond shortest-path witness.
- Optional or alternative-provider dependencies.
- Live production network ingestion.
- Multi-user or collaborative simulation.

## 12. WASM Boundary

The graph simulation operation uses a distinct WASM entry point:

- Proposed export name: `simulate_graph_json(input: &str) -> String`
- Input: canonical JSON request (Section 6).
- Output: canonical JSON response (Section 7) or error JSON `{ code, message }`.

The existing `health_check_json` entry point remains unchanged and backward-compatible.

Both entry points follow the same error contract: explicit JSON `{ code, message }`, never panics.

## 13. Open Questions for Review

None identified at specification time. All semantics, validation rules, error codes, and
algorithms are fully specified.
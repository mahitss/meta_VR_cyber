# NetVigil XR — Graph Engine Specification

**Document version:** 1.2  
**Status:** Specification — M003.0.3  
**Scope:** `security-engine` Rust/WASM crate  
**Implementation status:** Not implemented. This document is a specification only.  
M003.1 graph-engine implementation requires explicit principal-architect approval.

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

Two network edges with the same `(source_asset_id, target_asset_id)` pair are invalid, even if
their edge IDs differ. This produces `DUPLICATE_NETWORK_RELATIONSHIP`.

### Service dependency

A service dependency has:

- `id`: unique identifier.
- `dependent_asset_id`: the asset that requires the dependency.
- `dependency_asset_id`: the asset being depended upon.

Direction: `dependent_asset_id → dependency_asset_id`. Every listed dependency is required.
A dependent asset becomes impacted when at least one of its required dependencies is unavailable.
(OR semantics over dependencies: any one unavailable dependency impacts the dependent.)

Two dependency records with the same `(dependent_asset_id, dependency_asset_id)` pair are
invalid, even if their dependency IDs differ. This produces `DUPLICATE_SERVICE_RELATIONSHIP`.

### Attack sources

A list of initially compromised asset IDs from which modeled reachability is calculated.
An empty source list is permitted and produces an empty reachable set. Duplicate source IDs are
rejected with `DUPLICATE_ATTACK_SOURCE_ID`.

### Identifier grammar

Two identifier classes are distinguished:

**Resource identifiers** (asset IDs, network edge IDs, service dependency IDs, scenario IDs):
- Start with an alphanumeric character (`[A-Za-z0-9]`).
- May subsequently contain alphanumeric characters, `.`, `_`, `:`, or `-`.
- Maximum length: 64 characters.
- All characters must be ASCII (`[\x20-\x7E]`).
- Formal regex: `^[A-Za-z0-9][A-Za-z0-9._:\-]{0,63}$`

**Request IDs** (correlation identifiers, not resource identifiers):
- Printable ASCII characters only.
- Minimum 1 character.
- Maximum 256 characters.
- Formal regex: `^[\x20-\x7E]{1,256}$`

Request IDs are not resource identifiers and are not validated against the resource identifier
grammar.

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
2. If at least one of an asset's required dependencies is unavailable, the dependent asset
   becomes impacted. Equivalently: `dependent_available = all(required_dependencies_available)`,
   so `dependent_impacted = any(required_dependency_unavailable)`.
3. Propagate this impact transitively through the reverse dependency graph.
4. All listed dependencies are required for availability; the unavailability of any one
   required dependency impacts the dependent.
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
| `attack_source_asset_ids` | array of string | Yes | Max 256 entries. Duplicate values rejected. |

Strict deserialization: `additionalProperties: false` at all levels.

Raw serialized request size must not exceed 2 MiB (2,097,152 bytes). This check is performed
before JSON parsing and returns `LIMIT_EXCEEDED` if exceeded.

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

The response schema uses Draft-07 `oneOf` to distinguish success from error responses.

### Success response

| Field | Type | Description |
|-------|------|-------------|
| `contract_version` | string | Echo of request `contract_version`. |
| `request_id` | string | Echo of request `request_id`. |
| `scenario_id` | string | Echo of request `scenario_id`. |
| `network_reachability` | object | Network reachability result (Section 7.1). |
| `service_impact` | object | Service dependency result (Section 7.2). |

### 7.1 Network reachability result

| Field | Type | Description |
|-------|------|-------------|
| `reachable_asset_ids` | array of string | Sorted ascending. |
| `unreachable_asset_ids` | array of string | Sorted ascending. Available-but-unreachable assets only. |
| `witnesses` | array of Witness | One per reachable asset. Sorted by `target_asset`. |

### Witness

| Field | Type | Description |
|-------|------|-------------|
| `target_asset` | string | Reachable asset ID. |
| `source_asset` | string | Starting attack source ID. |
| `asset_path` | array of string | Ordered asset IDs from source to target (inclusive). |
| `edge_path` | array of string | Ordered edge IDs traversed. |

### 7.2 Service impact result

| Field | Type | Description |
|-------|------|-------------|
| `initially_unavailable_asset_ids` | array of string | Sorted ascending. |
| `impacted_dependent_asset_ids` | array of string | Sorted ascending, excludes initial seeds. |
| `unavailable_asset_ids` | array of string | Sorted ascending union. |

### Error response

All invalid requests return:

```json
{ "code": "<error-code>", "message": "<human-readable description>" }
```

Error codes are defined in Section 8. All errors return JSON, never panic.

### Response invariants (not all expressible in JSON Schema)

- Exactly one witness per reachable asset.
- Witness `target_asset` equals the corresponding entry in `reachable_asset_ids`.
- `edge_path.length = asset_path.length - 1` for every witness.
- `reachable_asset_ids` and `unreachable_asset_ids` are disjoint.
- All returned identifiers exist in the request.
- All output ID arrays are sorted and unique.
- `unavailable_asset_ids` equals the sorted union of initial and propagated unavailable assets.

## 8. Validation and Error Taxonomy

### Validation precedence (first failure wins)

Staged validation process compatible with strict deserialization:

1. Enforce maximum raw request byte size (2 MiB) → `LIMIT_EXCEEDED`
2. Parse syntactically valid JSON → `MALFORMED_JSON`
3. Validate that the root is a JSON object → `MALFORMED_JSON`
4. Validate required fields are present → `MALFORMED_JSON`
5. Validate unknown fields → `MALFORMED_JSON` (via `additionalProperties: false`)
6. Validate structural JSON types of all fields → `MALFORMED_JSON`
7. Validate `contract_version` is `"1.0"` → `UNSUPPORTED_CONTRACT_VERSION`
8. Validate present string `request_id` is non-empty, printable ASCII, ≤ 256 chars → `INVALID_REQUEST_ID`
9. Validate present string `scenario_id` matches grammar and ≤ 64 chars → `INVALID_SCENARIO_ID`
10. Enforce collection size limits → `LIMIT_EXCEEDED`
11. Validate resource identifiers and availability values → `INVALID_GRAPH`
12. Validate duplicate entity IDs → `DUPLICATE_ASSET_ID`, `DUPLICATE_NETWORK_EDGE_ID`,
    `DUPLICATE_SERVICE_DEPENDENCY_ID`
13. Validate duplicate graph relationships and duplicate attack sources →
    `DUPLICATE_NETWORK_RELATIONSHIP`, `DUPLICATE_SERVICE_RELATIONSHIP`,
    `DUPLICATE_ATTACK_SOURCE_ID`
14. Validate referenced asset existence → `UNKNOWN_ASSET_REFERENCE`
15. Validate prohibited self-loops → `SELF_LOOP_NOT_ALLOWED`
16. Validate attack-source availability → `SOURCE_ASSET_UNAVAILABLE`

**Missing vs. present-but-invalid:** A missing required field (e.g., `request_id` absent from the
object) is caught at step 4 → `MALFORMED_JSON`. A present field with an invalid value (e.g.,
`request_id: ""` or `request_id: 123`) is caught at step 6 → `MALFORMED_JSON` (wrong type) or
step 8 → `INVALID_REQUEST_ID` (right type, invalid value). A missing `contract_version` is caught
at step 4 → `MALFORMED_JSON`; a present but unsupported `contract_version: "2.0"` is caught at
step 7 → `UNSUPPORTED_CONTRACT_VERSION`.

Rust distinguishes error categories as follows:
- **Invalid JSON syntax**: `serde_json::from_str::<serde_json::Value>` fails → `MALFORMED_JSON`
- **Missing required fields**: Checked on the parsed `serde_json::Value` → `MALFORMED_JSON`
- **Unknown JSON properties**: Checked against `additionalProperties: false` → `MALFORMED_JSON`
- **Invalid JSON field types**: Checked against expected types (string, boolean, array) → `MALFORMED_JSON`
- **Invalid availability enum values**: Custom validation after typed deserialization → `INVALID_GRAPH`
  (Serde enum deserialization alone does not produce `INVALID_GRAPH`; a custom match is required)
- **Graph-level semantic errors**: Duplicate IDs, unknown references, self-loops, limits →
  their respective error codes

A practical design parses into `serde_json::Value`, validates the envelope and structural
conditions explicitly, then deserializes into strict typed models and performs semantic graph
validation.

### Error codes

| Code | Meaning |
|------|---------|
| `MALFORMED_JSON` | Body is not valid JSON, or missing/unknown/type-incorrect fields. |
| `UNSUPPORTED_CONTRACT_VERSION` | `contract_version` is not `"1.0"`. |
| `INVALID_REQUEST_ID` | `request_id` is empty, non-ASCII, or > 256 chars. |
| `INVALID_SCENARIO_ID` | `scenario_id` is empty, non-ASCII, > 64 chars, or violates grammar. |
| `INVALID_GRAPH` | Invalid `availability` value or other graph-level semantic violation. |
| `DUPLICATE_ASSET_ID` | Two assets share the same `id`. |
| `DUPLICATE_NETWORK_EDGE_ID` | Two network edges share the same `id`. |
| `DUPLICATE_SERVICE_DEPENDENCY_ID` | Two dependencies share the same `id`. |
| `DUPLICATE_SERVICE_RELATIONSHIP` | Two dependencies share the same `(dependent_asset_id, dependency_asset_id)` pair. |
| `UNKNOWN_ASSET_REFERENCE` | Edge or dependency references a non-existent asset ID. |
| `DUPLICATE_NETWORK_RELATIONSHIP` | Two edges have the same `(source_asset_id, target_asset_id)` pair. |
| `SELF_LOOP_NOT_ALLOWED` | Edge or dependency references the same asset as source and target. |
| `SOURCE_ASSET_UNAVAILABLE` | Attack source asset has `availability: "unavailable"`. |
| `DUPLICATE_ATTACK_SOURCE_ID` | Duplicate value in `attack_source_asset_ids`. |
| `LIMIT_EXCEEDED` | Input collection exceeds MVP bounds or raw request exceeds 2 MiB. |

### MVP bounds

| Input | Maximum | Rationale |
|-------|---------|-----------|
| Assets | 256 | Sufficient for a representative financial-sector incident scenario; keeps BFS O(V+E) trivial. |
| Network edges | 2,048 | Bounded to prevent pathological graph sizes in client-side WASM. |
| Service dependencies | 2,048 | Same rationale as network edges. |
| Attack sources | 256 | Capped at asset count; multi-source BFS is linear in source count. |
| Resource identifier length | 64 ASCII | Balances readability with fixed-size buffer efficiency. |
| Request ID length | 256 ASCII | Matches existing health-check constraint. |
| Raw serialized request size | 2 MiB (2,097,152 bytes) | Bounded to prevent denial-of-service through oversized payloads; checked before parsing. |

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
2. Build forward dependency map: for each asset, collect its required dependency IDs (sorted).
3. Initialize queue with initially unavailable assets (sorted ascending).
4. Initialize `impacted` set (empty), `visited` set = initially unavailable assets.
5. While queue not empty: pop front node `u`. For each `dependent` in sorted reverse out-list:
   - If `dependent` is not in visited: check OR semantics — if at least one of `dependent`'s
     required dependencies is unavailable (i.e., in `visited`), mark `dependent` as impacted,
     add to `impacted`, add to `visited`, push `dependent`.
6. `initially_unavailable_asset_ids` = sorted initial seeds.
7. `impacted_dependent_asset_ids` = sorted impacted set (excludes initial seeds).
8. `unavailable_asset_ids` = sorted union.

Complexity: O(V + E) time, O(V + E) space.

OR-semantics rule: a dependent asset `d` becomes impacted when any of its required dependencies
is unavailable. This is equivalent to `dependent_available = all(required_dependencies_available)`,
so `dependent_impacted = any(required_dependency_unavailable)`. The algorithm does not wait for
all dependencies of a dependent to become unavailable.

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

## 14. Corrections in M003.0.2

The following corrections were applied in M003.0.2:

1. **Request-schema error behavior**: Added `DUPLICATE_SERVICE_RELATIONSHIP`, `DUPLICATE_ATTACK_SOURCE_ID`,
   and raw-request-exceeds-2-MiB → `LIMIT_EXCEEDED` to the request schema's `error_behavior` metadata.
   `DUPLICATE_NETWORK_RELATIONSHIP` remains documented.

2. **Missing-field error precedence**: Clarified that missing required fields are caught before
   format validation (step 4 → `MALFORMED_JSON`), while present-but-invalid values are caught
   at their respective format-validation steps (step 8 → `INVALID_REQUEST_ID`, step 9 →
   `INVALID_SCENARIO_ID`). A missing `contract_version` → `MALFORMED_JSON`; a present but
   unsupported `contract_version` → `UNSUPPORTED_CONTRACT_VERSION`.

3. **Raw request-size boundary tests**: VAL-037 tests exactly 2,097,152 bytes (valid, accepted);
   VAL-038 tests exactly 2,097,153 bytes (`LIMIT_EXCEEDED`).

4. **Maximum-collection acceptance tests**: VAL-047 (256 assets), VAL-048 (2,048 edges),
   VAL-049 (2,048 service dependencies), VAL-050 (256 attack sources) prove exact maximums
   are accepted. Existing over-limit tests VAL-033 through VAL-036 remain.

5. **Wrong JSON type tests**: VAL-051 (`contract_version: 123`), VAL-052 (`request_id: 123`),
   VAL-053 (`scenario_id: 123`) all return `MALFORMED_JSON`.

6. **DEP-010 fixture fix**: Declares assets A, B, C, D (all available) to isolate duplicate
   dependency-ID validation from unknown-asset-reference validation.

7. **Dependency propagation semantics**: Confirmed OR semantics — any one unavailable required
   dependency impacts the dependent. `DEP-007` covers a dependency cycle with no initially
   unavailable assets (no propagated impact).

8. **All four documents aligned**: The request schema, response schema, specification, and test
   plan agree on all 15 error codes and their meanings.

## 15. Corrections in M003.0.3

The following corrections were applied in M003.0.3:

1. **Request-schema structural type errors**: Explicitly documented that
   `contract_version`, `request_id`, and `scenario_id` fields that are not strings produce
   `MALFORMED_JSON`; present string values that violate their constraints produce
   `INVALID_REQUEST_ID` or `INVALID_SCENARIO_ID` respectively; any other field with an incorrect
   structural JSON type produces `MALFORMED_JSON`. Missing required fields continue to produce
   `MALFORMED_JSON`.

2. **Validation test table normalization**: All 53 validation test rows (VAL-001 through VAL-053)
   now use a consistent 4-column structure: `Test ID | Input | Expected outcome | Expected error code`.
   Accepted cases state `Accepted` with `—` for the error code; rejected cases state `Rejected`
   with the exact error code.

3. **Mission labels and approval gates**: Replaced mission-specific implementation prohibitions
   with the durable gate: `M003.1 graph-engine implementation requires explicit principal-architect
   approval.` Updated verification table header from `Status in M003.0.1` to `Status in M003.0.2`.

4. **Document revision metadata**: Specification advanced from version 1.1 to 1.2; test plan
   advanced from version 1.2 to 1.3. JSON contract version remains 1.0.
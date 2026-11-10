# NetVigil XR — Graph Engine Test Plan

**Document version:** 1.3  
**Status:** Specification — M003.0.3  
**Scope:** `security-engine` Rust/WASM crate  
**Implementation status:** Not implemented. This document is a specification only.  
M003.1 graph-engine implementation requires explicit principal-architect approval.

## 1. Purpose

This test plan defines the test matrix, test IDs, preconditions, inputs, expected results,
expected errors, and verification distinctions for the graph simulation engine. It is designed
to be implemented as table-driven native Rust tests initially, with no new testing dependencies.

## 2. Verification Distinctions

| Verification type | Execution environment | Scope | Status in M003.0.2 |
|-------------------|----------------------|-------|--------------------|
| Native Rust tests | Host machine (cargo test) | Pure graph logic, validation, determinism | Specified only, not implemented |
| WASM boundary tests | Node.js (wasm-bindgen) | Raw `simulate_graph_json` entry point via wasm-bindgen | Specified only |
| Browser WASM tests | Physical browser / IWER | End-to-end invocation through generated bindings | Not attempted (blocked in M002 by IWSDK runtime owner error on Windows) |
| Quest headset tests | Physical Meta Quest hardware | Performance (60 FPS target), immersive interaction | Outstanding (no headset available) |

Browser verification is not claimed. Quest headset validation is outstanding.

## 3. Test Matrix — Network Reachability

| Test ID | Precondition | Input summary | Expected result | Error code |
|---------|-------------|---------------|-----------------|------------|
| NET-001 | Empty graph | No assets, no edges, no sources | `reachable_asset_ids: []`, `unreachable_asset_ids: []`, `witnesses: []` | — |
| NET-002 | Single asset | One asset `A: available`, no edges, source `[A]` | `reachable: ["A"]`, `unreachable: []`, `witnesses: [{target: A, source: A, asset_path: [A], edge_path: []}]` | — |
| NET-003 | Direct connection | Assets `A, B` both available; edge `A→B` enabled; source `[A]` | `reachable: ["A","B"]`, `unreachable: []`, witness for B: path `[A,B]` | — |
| NET-004 | Multi-hop connection | Assets `A,B,C` available; edges `A→B`, `B→C` enabled; source `[A]` | `reachable: ["A","B","C"]`; witness for C: asset_path `[A,B,C]`, edge_path `[e1,e2]` | — |
| NET-005 | Directed edge behavior | Assets `A,B` available; edge `A→B` enabled only; source `[B]` | `reachable: ["B"]`, `unreachable: ["A"]`; no witness for A | — |
| NET-006 | Explicit reverse edge | Assets `A,B` available; edges `A→B` and `B→A` both enabled; source `[A]` | `reachable: ["A","B"]`; bidirectional reachability | — |
| NET-007 | Disabled edge | Assets `A,B` available; edge `A→B` enabled=false; source `[A]` | `reachable: ["A"]`, `unreachable: ["B"]` | — |
| NET-008 | Unavailable intermediate | Assets `A,B,C` where `B: unavailable`; edges `A→B`, `B→C` enabled; source `[A]` | `reachable: ["A"]`, `unreachable: ["C"]`; B cannot be traversed | — |
| NET-009 | Disconnected component | Assets `A,B,C,D` available; edge `A→B`; source `[A]` | `reachable: ["A","B"]`, `unreachable: ["C","D"]` | — |
| NET-010 | Multiple attack sources | Assets `A,B,C` available; edges `A→B`; sources `[A, C]` | `reachable: ["A","B","C"]`; union of both sources | — |
| NET-011 | Cyclic network | Assets `A,B,C` available; edges `A→B`, `B→C`, `C→A`; source `[A]` | `reachable: ["A","B","C"]`; terminates (visited set) | — |
| NET-012 | Empty attack-source list | Assets `A,B` available; edge `A→B`; sources `[]` | `reachable: []`, `unreachable: ["A","B"]`, `witnesses: []` | — |
| NET-013 | Deterministic shortest path | Assets `A,B,C,D` available; edges `A→B`, `B→C`, `A→C`, `C→D`; source `[A]` | Witness for C: path `[A,C]` (shorter than `[A,B,C]`) | — |
| NET-014 | Equal-length path tie-breaking | Assets `A,B,C,D` available; edges `A→B`, `A→D`, `B→C`, `D→C`; source `[A]` | Witness for C uses path via B (B < D lexicographically) | — |
| NET-015 | Tie-breaking with multiple attack sources | Assets `A,B,C,X,Y` available; edges `X→B`, `Y→D`, `B→C`, `D→C`; sources `[X, Y]` | Witness for C: source X wins (X < Y), path `[X,B,C]` | — |
| NET-016 | Duplicate directed relationship | Assets `A, B` available; edges `A→B` (id=e1) and `A→B` (id=e2) | `DUPLICATE_NETWORK_RELATIONSHIP` | `DUPLICATE_NETWORK_RELATIONSHIP` |
| NET-017 | Input permutation determinism | Same graph, edges array permuted | Identical canonical output regardless of input order | — |

## 4. Test Matrix — Service Dependency Propagation

| Test ID | Precondition | Input summary | Expected result | Error code |
|---------|-------------|---------------|-----------------|------------|
| DEP-001 | No dependencies | Assets `A, B` available; no dependencies | `initially_unavailable: []`, `impacted: []`, `unavailable: []` | — |
| DEP-002 | Direct dependency failure | Assets `App, DB` where `DB: unavailable`; dependency `App → DB` | `initially_unavailable: ["DB"]`, `impacted: ["App"]`, `unavailable: ["App","DB"]` | — |
| DEP-003 | Multi-level cascading impact | Assets `A, B, C` where `C: unavailable`; deps `A → B`, `B → C` | `initially_unavailable: ["C"]`, `impacted: ["A","B"]`, `unavailable: ["A","B","C"]` | — |
| DEP-004 | One unavailable required dependency (OR semantics) | Assets `App, DB, Cache` where `DB: unavailable`, `Cache: available`; deps `App → DB`, `App → Cache` | `initially_unavailable: ["DB"]`, `impacted: ["App"]`, `unavailable: ["App","DB"]` | — |
| DEP-005 | Unrelated asset unaffected | Assets `A, B, C` where `A: unavailable`; dep `B → C` | `impacted: []`; B and C unaffected by A | — |
| DEP-006 | Initially unavailable asset | Assets `A, B` where `A: unavailable`; dep `B → A` | `initially_unavailable: ["A"]`, `impacted: ["B"]`, `unavailable: ["A","B"]` | — |
| DEP-007 | Dependency cycle, no initially unavailable | Assets `A, B` both available; deps `A → B`, `B → A` | `initially_unavailable: []`, `impacted: []`, `unavailable: []` | — |
| DEP-008 | Dependency cycle with unavailable | Assets `A, B` where `A: unavailable`; deps `A → B`, `B → A` | `initially_unavailable: ["A"]`, `impacted: ["B"]`, terminates (visited set) | — |
| DEP-009 | Duplicate service dependency pair | Assets `A, B` available; deps `A → B` (id=d1) and `A → B` (id=d2) | `DUPLICATE_SERVICE_RELATIONSHIP` | `DUPLICATE_SERVICE_RELATIONSHIP` |
| DEP-010 | Duplicate service dependency ID | Assets `A, B, C, D` all available; deps `A → B` (id=d1) and `C → D` (id=d1) | `DUPLICATE_SERVICE_DEPENDENCY_ID` | `DUPLICATE_SERVICE_DEPENDENCY_ID` |
| DEP-011 | Duplicate attack source | Assets `A, B` available; sources `[A, A]` | `DUPLICATE_ATTACK_SOURCE_ID` | `DUPLICATE_ATTACK_SOURCE_ID` |

## 5. Test Matrix — Independence

| Test ID | Precondition | Input summary | Expected result | Error code |
|---------|-------------|---------------|-----------------|------------|
| IND-001 | Dependency does not create reachability | Assets `A, B` available; dep `A → B` only; no network edges; source `[A]` | `reachable: ["A"]`, `unreachable: ["B"]`; dep alone does not make B reachable | — |
| IND-002 | Edge disabling does not create unavailability | Assets `A, B` available; edge `A→B` enabled=false; no dependencies | `service_impact.unavailable_asset_ids: []`; disabling edge does not impact services | — |
| IND-003 | Dependency impact does not mutate network | Assets `A, B, C` where `C: unavailable`; edge `A→B` enabled; dep `B→C`; source `[A]` | `reachable: ["A","B"]`; B remains reachable despite C being unavailable via dep | — |
| IND-004 | Reachability does not imply exploitability | Assets `A, B` available; edge `A→B` enabled; source `[A]` | `reachable: ["B"]`; engine makes no exploitability claim | — |

## 6. Test Matrix — Validation

| Test ID | Input | Expected outcome | Expected error code |
|---------|-------|-----------------|---------------------|
| VAL-001 | `{not json}` | Rejected | `MALFORMED_JSON` |
| VAL-002 | `{}` (missing all fields) | Rejected | `MALFORMED_JSON` |
| VAL-003 | Missing `contract_version` | Rejected | `MALFORMED_JSON` |
| VAL-004 | Missing `request_id` | Rejected | `MALFORMED_JSON` |
| VAL-005 | Missing `scenario_id` | Rejected | `MALFORMED_JSON` |
| VAL-006 | Missing `assets` | Rejected | `MALFORMED_JSON` |
| VAL-007 | Missing `network_edges` | Rejected | `MALFORMED_JSON` |
| VAL-008 | Missing `service_dependencies` | Rejected | `MALFORMED_JSON` |
| VAL-009 | Missing `attack_source_asset_ids` | Rejected | `MALFORMED_JSON` |
| VAL-010 | Unknown top-level field | Rejected | `MALFORMED_JSON` |
| VAL-011 | Unknown asset field | Rejected | `MALFORMED_JSON` |
| VAL-012 | Unknown edge field | Rejected | `MALFORMED_JSON` |
| VAL-013 | Unknown dependency field | Rejected | `MALFORMED_JSON` |
| VAL-014 | `contract_version: "2.0"` | Rejected | `UNSUPPORTED_CONTRACT_VERSION` |
| VAL-015 | `request_id: ""` | Rejected | `INVALID_REQUEST_ID` |
| VAL-016 | `request_id: "réquest"` (non-ASCII) | Rejected | `INVALID_REQUEST_ID` |
| VAL-017 | `request_id` length 257 | Rejected | `INVALID_REQUEST_ID` |
| VAL-018 | `scenario_id: ""` | Rejected | `INVALID_SCENARIO_ID` |
| VAL-019 | `scenario_id` non-ASCII | Rejected | `INVALID_SCENARIO_ID` |
| VAL-020 | `scenario_id` length 65 | Rejected | `INVALID_SCENARIO_ID` |
| VAL-021 | `scenario_id` starts with `-` (violates grammar) | Rejected | `INVALID_SCENARIO_ID` |
| VAL-022 | Duplicate asset ID | Rejected | `DUPLICATE_ASSET_ID` |
| VAL-023 | Duplicate network-edge ID | Rejected | `DUPLICATE_NETWORK_EDGE_ID` |
| VAL-024 | Duplicate service-dependency ID | Rejected | `DUPLICATE_SERVICE_DEPENDENCY_ID` |
| VAL-025 | Edge references unknown asset | Rejected | `UNKNOWN_ASSET_REFERENCE` |
| VAL-026 | Dependency references unknown asset | Rejected | `UNKNOWN_ASSET_REFERENCE` |
| VAL-027 | Duplicate directed relationship (same source+target) | Rejected | `DUPLICATE_NETWORK_RELATIONSHIP` |
| VAL-028 | Self-loop edge (source == target) | Rejected | `SELF_LOOP_NOT_ALLOWED` |
| VAL-029 | Self-loop dependency (dependent == dependency) | Rejected | `SELF_LOOP_NOT_ALLOWED` |
| VAL-030 | `availability: "degraded"` (invalid enum) | Rejected | `INVALID_GRAPH` |
| VAL-031 | Attack source references missing asset | Rejected | `UNKNOWN_ASSET_REFERENCE` |
| VAL-032 | Attack source references unavailable asset | Rejected | `SOURCE_ASSET_UNAVAILABLE` |
| VAL-033 | Assets count 257 | Rejected | `LIMIT_EXCEEDED` |
| VAL-034 | Network edges count 2,049 | Rejected | `LIMIT_EXCEEDED` |
| VAL-035 | Service dependencies count 2,049 | Rejected | `LIMIT_EXCEEDED` |
| VAL-036 | Attack sources count 257 | Rejected | `LIMIT_EXCEEDED` |
| VAL-037 | Raw request exactly 2,097,152 bytes (valid, padded with whitespace) | Accepted | — |
| VAL-038 | Raw request exactly 2,097,153 bytes | Rejected | `LIMIT_EXCEEDED` |
| VAL-047 | Assets count exactly 256, all valid references | Accepted | — |
| VAL-048 | Network edges exactly 2,048, all valid references | Accepted | — |
| VAL-049 | Service dependencies exactly 2,048, all valid references | Accepted | — |
| VAL-050 | Attack sources exactly 256, all available assets referenced | Accepted | — |
| VAL-051 | `contract_version: 123` (number, not string) | Rejected | `MALFORMED_JSON` |
| VAL-052 | `request_id: 123` (number, not string) | Rejected | `MALFORMED_JSON` |
| VAL-053 | `scenario_id: 123` (number, not string) | Rejected | `MALFORMED_JSON` |
| VAL-039 | Invalid asset ID grammar (starts with `-`) | Rejected | `INVALID_GRAPH` |
| VAL-040 | Invalid network edge ID grammar | Rejected | `INVALID_GRAPH` |
| VAL-041 | Invalid service dependency ID grammar | Rejected | `INVALID_GRAPH` |
| VAL-042 | Missing availability field | Rejected | `MALFORMED_JSON` |
| VAL-043 | Wrong field type (availability as number) | Rejected | `MALFORMED_JSON` |
| VAL-044 | Unknown nested property in asset | Rejected | `MALFORMED_JSON` |
| VAL-045 | Unknown nested property in edge | Rejected | `MALFORMED_JSON` |
| VAL-046 | Unknown nested property in dependency | Rejected | `MALFORMED_JSON` |

## 7. Test Matrix — Determinism

| Test ID | Description | Expected behavior |
|---------|-------------|-------------------|
| DET-001 | Same input repeated | Identical canonical JSON output (byte-equivalent) |
| DET-002 | Permuted assets array | Same sorted output arrays |
| DET-003 | Permuted network_edges array | Same reachable/unreachable/witnesses output |
| DET-004 | Permuted service_dependencies array | Same impact output |
| DET-005 | Permuted attack_source_asset_ids array | Same reachable set (union) |
| DET-006 | Equal-length path tie-breaking stable | Same witness selected across runs |
| DET-007 | Cyclic input terminates | No infinite loop; visited set bounds traversal |
| DET-008 | Output collections sorted | All ID arrays in ascending lexicographic order |

## 8. Test Matrix — WASM Boundary (specified, not browser-executed)

| Test ID | Description | Expected behavior |
|---------|-------------|-------------------|
| WASM-001 | Valid simulation request through raw binding | Returns success JSON with `contract_version: "1.0"` |
| WASM-002 | Malformed JSON through raw binding | Returns `{ code: "MALFORMED_JSON", ... }` |
| WASM-003 | Unsupported contract version through raw binding | Returns `{ code: "UNSUPPORTED_CONTRACT_VERSION", ... }` |
| WASM-004 | Invalid request ID through raw binding | Returns `{ code: "INVALID_REQUEST_ID", ... }` |
| WASM-005 | Unknown asset reference through raw binding | Returns `{ code: "UNKNOWN_ASSET_REFERENCE", ... }` |
| WASM-006 | Limit exceeded through raw binding | Returns `{ code: "LIMIT_EXCEEDED", ... }` |

WASM boundary tests invoke the raw `simulate_graph_json` export directly. No browser execution is
claimed or required for this plan.

## 9. Test Matrix — Response Invariants

| Test ID | Description | Expected invariant |
|---------|-------------|-------------------|
| INV-001 | One witness per reachable asset | `witnesses.length == reachable_asset_ids.length` |
| INV-002 | Witness target matches reachable | Every `witness.target_asset` is in `reachable_asset_ids` |
| INV-003 | Edge path length | `witness.edge_path.length == witness.asset_path.length - 1` |
| INV-004 | Reachable/unreachable disjoint | No asset ID appears in both arrays |
| INV-005 | All IDs exist in request | Every returned ID matches a request input ID |
| INV-006 | Arrays sorted and unique | All ID arrays ascending, no duplicates |
| INV-007 | Unavailable union | `unavailable_asset_ids` == sorted union of initial + impacted |

## 10. Native vs WASM vs Browser Distinctions

| Aspect | Native Rust tests | WASM boundary tests | Browser WASM tests |
|--------|-------------------|---------------------|-------------------|
| Execution | `cargo test --workspace` | Node.js `wasm-bindgen` import | Browser / IWER |
| What is tested | Pure Rust functions (`simulate_graph`, validation) | Raw `simulate_graph_json` WASM export | Full IWSDK app integration |
| Can claim browser execution? | No | No (Node.js only) | Yes, if executed in browser |
| Blocked by IWSDK issue? | No | No | Yes (M002 Windows runtime owner error) |
| Quest headset required? | No | No | Yes (for performance validation) |

## 11. Implementation Notes for M003.1

- Prefer table-driven native Rust tests using the existing `#[cfg(test)]` module pattern.
- Do not add new testing dependencies (e.g., `proptest`, `quickcheck`, `criterion`) unless
  absolutely justified.
- All tests must pass on `cargo test --workspace` with no `#[ignore]` unless documenting a
  known environment limitation.
- WASM boundary tests may be implemented as a separate integration test file that imports the
  crate's CDYLIB through `wasm-bindgen` in a Node.js environment.

## 12. Corrections in M003.0.2

The following corrections were applied in M003.0.2:

1. **Dependency propagation semantics**: Changed from AND semantics (all required dependencies
   must be unavailable) to OR semantics (any one unavailable required dependency impacts the
   dependent). `DEP-004` preserves the one-unavailable-dependency case; `DEP-007` covers a
   dependency cycle with no initially unavailable assets (no propagated impact).

2. **Duplicate relationship validation**: Added `DUPLICATE_NETWORK_RELATIONSHIP` (same
   `(source_asset_id, target_asset_id)` pair), `DUPLICATE_SERVICE_RELATIONSHIP` (same
   `(dependent_asset_id, dependency_asset_id)` pair), and `DUPLICATE_ATTACK_SOURCE_ID`
   (duplicate values in `attack_source_asset_ids`).

3. **Identifier grammar**: Separated resource identifiers (asset, edge, dependency, scenario IDs)
   from request IDs (correlation identifiers). Resource IDs use alphanumeric start with
   `[A-Za-z0-9._:\-]` max 64 chars; request IDs use printable ASCII max 256 chars.

4. **Validation pipeline**: Specified a staged validation process with exact deterministic
   precedence (16 steps), including raw request size check (2 MiB), JSON parsing, required field
   checks, structural type checks, contract version validation, collection size limits, duplicate
   detection, reference validation, self-loop checks, and attack-source availability validation.

5. **Request-size bound**: Added 2 MiB (2,097,152 bytes) maximum raw serialized request size,
   checked before parsing, returning `LIMIT_EXCEEDED`.

6. **Response schema**: Uses Draft-07 `oneOf` to distinguish success from error responses; error
   code constrained to documented taxonomy via enum; added `response_invariants` section.

7. **Test matrix corrections**: Replaced `NET-015` permutation test with duplicate relationship
   case; added equal-length path tie-breaking with multiple attack sources; replaced redundant
   `DEP-009` with cycle-no-unavailable case; added duplicate service dependency pair and duplicate
   attack source validation; fixed `WASM-05` → `WASM-005` typo; added invalid identifier,
   boundary, wrong-type, and response invariant tests.

## 13. Corrections in M003.0.3

The following corrections were applied in M003.0.3:

1. **Request-schema structural type errors**: Explicitly documented that `contract_version`,
   `request_id`, and `scenario_id` fields that are not strings produce `MALFORMED_JSON`; present
   string values that violate their constraints produce `INVALID_REQUEST_ID` or
   `INVALID_SCENARIO_ID` respectively; any other field with an incorrect structural JSON type
   produces `MALFORMED_JSON`. Missing required fields continue to produce `MALFORMED_JSON`.

2. **Validation test table normalization**: All 53 validation test rows (VAL-001 through VAL-053)
   now use a consistent 4-column structure: `Test ID | Input | Expected outcome | Expected error code`.
   Accepted cases state `Accepted` with `—` for the error code; rejected cases state `Rejected`
   with the exact error code.

3. **Mission labels and approval gates**: Replaced mission-specific implementation prohibitions
   with the durable gate: `M003.1 graph-engine implementation requires explicit principal-architect
   approval.` Updated verification table header from `Status in M003.0.1` to `Status in M003.0.2`.

4. **Document revision metadata**: Specification advanced from version 1.1 to 1.2; test plan
   advanced from version 1.2 to 1.3. JSON contract version remains 1.0.

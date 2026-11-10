# NetVigil XR — Graph Engine Test Plan

**Document version:** 1.0  
**Status:** Specification — M003.0  
**Scope:** `security-engine` Rust/WASM crate  
**Implementation status:** Not implemented. This document is a specification only.  
**Implementation prohibited in M003.0.**

## 1. Purpose

This test plan defines the test matrix, test IDs, preconditions, inputs, expected results,
expected errors, and verification distinctions for the graph simulation engine. It is designed
to be implemented as table-driven native Rust tests initially, with no new testing dependencies.

## 2. Verification Distinctions

| Verification type | Execution environment | Scope | Status in M003.0 |
|-------------------|----------------------|-------|------------------|
| Native Rust tests | Host machine (cargo test) | Pure graph logic, validation, determinism | Specified only, not implemented |
| WASM boundary tests | Node.js or browser (wasm-bindgen) | Raw `simulate_graph_json` entry point via wasm-bindgen | Specified only |
| Browser WASM tests | Physical browser / IWER | End-to-end invocation through generated bindings | Not attempted (blocked in M002 by IWSDK runtime owner error on Windows) |
| Quest headset tests | Physical Meta Quest hardware | Performance (60 FPS target), immersive interaction | Outstanding (no headset available) |

Browser verification is not claimed. Quest headset validation is outstanding.

## 3. Test Matrix — Network Reachability

| Test ID | Precondition | Input summary | Expected result | Error code |
|---------|-------------|---------------|-----------------|------------|
| NET-001 | Empty graph | No assets, no edges, no sources | `reachable_asset_ids: []`, `unreachable_asset_ids: []`, `witnesses: []` | — |
| NET-002 | Single available asset | One asset `A: available`, no edges, source `[A]` | `reachable: ["A"]`, `unreachable: []`, `witnesses: [{target: A, source: A, asset_path: [A], edge_path: []}]` | — |
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
| NET-015 | Parallel input relationship handling | Same graph, edges array permuted | Identical canonical output regardless of input order | — |

## 4. Test Matrix — Service Dependency Propagation

| Test ID | Precondition | Input summary | Expected result | Error code |
|---------|-------------|---------------|-----------------|------------|
| DEP-001 | No dependencies | Assets `A, B` available; no dependencies | `initially_unavailable: []`, `impacted: []`, `unavailable: []` | — |
| DEP-002 | Direct dependency failure | Assets `App, DB` where `DB: unavailable`; dependency `App → DB` | `initially_unavailable: ["DB"]`, `impacted: ["App"]`, `unavailable: ["App","DB"]` | — |
| DEP-003 | Multi-level cascading impact | Assets `A, B, C` where `C: unavailable`; deps `A → B`, `B → C` | `initially_unavailable: ["C"]`, `impacted: ["A","B"]`, `unavailable: ["A","B","C"]` | — |
| DEP-004 | Multiple required dependencies (AND) | Assets `App, DB, Cache` where `DB: unavailable`, `Cache: available`; deps `App → DB`, `App → Cache` | `impacted: ["App"]` (AND: one unavailable dep is enough to impact) | — |
| DEP-005 | Unrelated asset unaffected | Assets `A, B, C` where `A: unavailable`; dep `B → C` | `impacted: []`; B and C unaffected by A | — |
| DEP-006 | Initially unavailable asset | Assets `A, B` where `A: unavailable`; dep `B → A` | `initially_unavailable: ["A"]`, `impacted: ["B"]`, `unavailable: ["A","B"]` | — |
| DEP-007 | Dependency cycle termination | Assets `A, B` where `A: unavailable`; deps `A → B`, `B → A` | `initially_unavailable: ["A"]`, `impacted: ["B"]`, terminates (visited set) | — |
| DEP-008 | Impact excludes initial seeds | Assets `A, B` where `A: unavailable`; dep `B → A` | `impacted_dependent_asset_ids: ["B"]` (does not include `A`) | — |
| DEP-009 | AND semantics: all deps must be unavailable | Assets `App, DB1, DB2` where `DB1: unavailable`, `DB2: available`; deps `App → DB1`, `App → DB2` | `impacted: ["App"]` (any unavailable required dep impacts App) | — |

## 5. Test Matrix — Independence

| Test ID | Precondition | Input summary | Expected result | Error code |
|---------|-------------|---------------|-----------------|------------|
| IND-001 | Dependency does not create reachability | Assets `A, B` available; dep `A → B` only; no network edges; source `[A]` | `reachable: ["A"]`, `unreachable: ["B"]`; dep alone does not make B reachable | — |
| IND-002 | Edge disabling does not create unavailability | Assets `A, B` available; edge `A→B` enabled=false; no dependencies | `service_impact.unavailable_asset_ids: []`; disabling edge does not impact services | — |
| IND-003 | Dependency impact does not mutate network | Assets `A, B, C` where `C: unavailable`; edge `A→B` enabled; dep `B→C`; source `[A]` | `reachable: ["A","B"]`; B remains reachable despite C being unavailable via dep | — |
| IND-004 | Reachability does not imply exploitability | Assets `A, B` available; edge `A→B` enabled; source `[A]` | `reachable: ["B"]`; engine makes no exploitability claim | — |

## 6. Test Matrix — Validation

| Test ID | Input | Expected error code |
|---------|-------|---------------------|
| VAL-001 | `{not json}` | `MALFORMED_JSON` |
| VAL-002 | `{}` (missing all fields) | `MALFORMED_JSON` |
| VAL-003 | Missing `contract_version` | `MALFORMED_JSON` |
| VAL-004 | Missing `request_id` | `MALFORMED_JSON` |
| VAL-005 | Missing `scenario_id` | `MALFORMED_JSON` |
| VAL-006 | Missing `assets` | `MALFORMED_JSON` |
| VAL-007 | Missing `network_edges` | `MALFORMED_JSON` |
| VAL-008 | Missing `service_dependencies` | `MALFORMED_JSON` |
| VAL-009 | Missing `attack_source_asset_ids` | `MALFORMED_JSON` |
| VAL-010 | Unknown top-level field | `MALFORMED_JSON` |
| VAL-011 | Unknown asset field | `MALFORMED_JSON` |
| VAL-012 | Unknown edge field | `MALFORMED_JSON` |
| VAL-013 | Unknown dependency field | `MALFORMED_JSON` |
| VAL-014 | `contract_version: "2.0"` | `UNSUPPORTED_CONTRACT_VERSION` |
| VAL-015 | `request_id: ""` | `INVALID_REQUEST_ID` |
| VAL-016 | `request_id: "réquest"` (non-ASCII) | `INVALID_REQUEST_ID` |
| VAL-017 | `request_id` length 257 | `INVALID_REQUEST_ID` |
| VAL-018 | `scenario_id: ""` | `INVALID_SCENARIO_ID` |
| VAL-019 | `scenario_id` non-ASCII | `INVALID_SCENARIO_ID` |
| VAL-020 | `scenario_id` length 65 | `INVALID_SCENARIO_ID` |
| VAL-021 | `scenario_id` starts with `-` (violates grammar) | `INVALID_SCENARIO_ID` |
| VAL-022 | Duplicate asset ID | `DUPLICATE_ASSET_ID` |
| VAL-023 | Duplicate network-edge ID | `DUPLICATE_NETWORK_EDGE_ID` |
| VAL-024 | Duplicate service-dependency ID | `DUPLICATE_SERVICE_DEPENDENCY_ID` |
| VAL-025 | Edge references unknown asset | `UNKNOWN_ASSET_REFERENCE` |
| VAL-026 | Dependency references unknown asset | `UNKNOWN_ASSET_REFERENCE` |
| VAL-027 | Duplicate directed relationship (same source+target) | `DUPLICATE_NETWORK_RELATIONSHIP` |
| VAL-028 | Self-loop edge (source == target) | `SELF_LOOP_NOT_ALLOWED` |
| VAL-029 | Self-loop dependency (dependent == dependency) | `SELF_LOOP_NOT_ALLOWED` |
| VAL-030 | `availability: "degraded"` (invalid enum) | `INVALID_GRAPH` |
| VAL-031 | Attack source references missing asset | `UNKNOWN_ASSET_REFERENCE` |
| VAL-032 | Attack source references unavailable asset | `SOURCE_ASSET_UNAVAILABLE` |
| VAL-033 | Assets count 257 | `LIMIT_EXCEEDED` |
| VAL-034 | Network edges count 2,049 | `LIMIT_EXCEEDED` |
| VAL-035 | Service dependencies count 2,049 | `LIMIT_EXCEEDED` |
| VAL-036 | Attack sources count 257 | `LIMIT_EXCEEDED` |

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
| WASM-05 | Unknown asset reference through raw binding | Returns `{ code: "UNKNOWN_ASSET_REFERENCE", ... }` |
| WASM-006 | Limit exceeded through raw binding | Returns `{ code: "LIMIT_EXCEEDED", ... }` |

WASM boundary tests invoke the raw `simulate_graph_json` export directly. No browser execution is
claimed or required for this plan.

## 9. Native vs WASM vs Browser Distinctions

| Aspect | Native Rust tests | WASM boundary tests | Browser WASM tests |
|--------|-------------------|---------------------|-------------------|
| Execution | `cargo test --workspace` | Node.js `wasm-bindgen` import | Browser / IWER |
| What is tested | Pure Rust functions (`simulate_graph`, validation) | Raw `simulate_graph_json` WASM export | Full IWSDK app integration |
| Can claim browser execution? | No | No (Node.js only) | Yes, if executed in browser |
| Blocked by IWSDK issue? | No | No | Yes (M002 Windows runtime owner error) |
| Quest headset required? | No | No | Yes (for performance validation) |

## 10. Implementation Notes for M003.1

- Prefer table-driven native Rust tests using the existing `#[cfg(test)]` module pattern.
- Do not add new testing dependencies (e.g., `proptest`, `quickcheck`, `criterion`) unless
  absolutely justified.
- All tests must pass on `cargo test --workspace` with no `#[ignore]` unless documenting a
  known environment limitation.
- WASM boundary tests may be implemented as a separate integration test file that imports the
  crate's CDYLIB through `wasm-bindgen` in a Node.js environment.

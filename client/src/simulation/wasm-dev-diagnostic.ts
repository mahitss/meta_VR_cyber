// ============================================================================
// NetVigil XR — Development-only WASM diagnostic
// ============================================================================
//
// This module is a development-only diagnostic that invokes the actual
// Rust/WASM security engine through the generated wasm-bindgen binding and
// logs the results to the browser console.
//
// It is NOT a production feature. It is imported conditionally in src/index.ts
// only when import.meta.env.DEV is true, so it is tree-shaken out of
// production builds.
//
// Test groups:
//   POSITIVE (through wasm-adapter, valid input):
//     1. Valid health request -> { status: "ok", engine: "security-engine" }
//     5. Valid graph request -> GraphSimulationResponse
//
//   NEGATIVE (through raw health_check_json binding, invalid input):
//     2. Unsupported contract version -> UNSUPPORTED_CONTRACT_VERSION
//     3. Empty request ID -> INVALID_REQUEST_ID
//     4. Malformed JSON -> MALFORMED_JSON
//
//   NEGATIVE (through raw simulate_graph_json binding, invalid input):
//     6. Malformed JSON -> MALFORMED_JSON
//     7. Missing nested required field -> MALFORMED_JSON
//     8. Unsupported contract version -> UNSUPPORTED_CONTRACT_VERSION
//     9. Unknown asset reference -> UNKNOWN_ASSET_REFERENCE
//
// Negative tests invoke the raw Rust binding directly, bypassing
// TypeScript-side validation, so they exercise the Rust engine's
// authoritative validation.
//
// The adapter wrapper test verifies that an engine error passed through
// the adapter becomes an EngineRequestError.
// ============================================================================

import {
  initialize,
  healthCheck,
  simulateGraph,
  validateGraphResponse,
  validateGraphRequest,
  CONTRACT_VERSION,
  GraphSimulationRequest,
  GraphSimulationResponse,
  EngineRequestError,
  EngineResponseError,
} from "./wasm-adapter";

type ConsoleMethod = "log" | "info" | "warn" | "error";

const consoleStyles: Record<ConsoleMethod, string> = {
  log: "color: inherit;",
  info: "color: #2196F3; font-weight: bold;",
  warn: "color: #FF9800; font-weight: bold;",
  error: "color: #F44336; font-weight: bold;",
};

function styledLog(method: ConsoleMethod, ...args: unknown[]): void {
  const style = consoleStyles[method];
  // eslint-disable-next-line no-console
  console[method](
    `%c[netvigil-xr-wasm]${style} %c${args.join(" ")}`,
    "color: #666; font-weight: bold;",
    "color: inherit;",
  );
}

/** Parse a JSON response from the raw Rust binding. */
function parseEngineResponse(json: string): { code?: string; message?: string; status?: string; engine?: string } {
  try {
    return JSON.parse(json);
  } catch {
    return {};
  }
}

/** Run the full WASM diagnostic suite in the browser. */
export async function runWasmDevDiagnostic(): Promise<void> {
  styledLog("info", "Initializing WASM security engine...");

  try {
    initialize();
  } catch (error) {
    styledLog(
      "error",
      "WASM initialization failed:",
      error instanceof Error ? error.message : String(error),
    );
    return;
  }

  styledLog("info", "WASM module initialized. Running diagnostic tests...");

  // ========================================================================
  // POSITIVE TESTS — through wasm-adapter (valid input)
  // ========================================================================

  // ------------------------------------------------------------------
  // Test 1: Valid health request
  // ------------------------------------------------------------------
  try {
    const response = healthCheck({
      contract_version: CONTRACT_VERSION,
      request_id: "m002-dev-diagnostic-001",
    });
    styledLog(
      "info",
      `POSITIVE Test 1 (valid request): PASS — status="${response.status}" engine="${response.engine}" request_id="${response.request_id}"`,
    );
  } catch (error) {
    styledLog(
      "error",
      `POSITIVE Test 1 (valid request): FAIL — ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  // ========================================================================
  // NEGATIVE TESTS — through raw health_check_json binding
  // These bypass TypeScript-side validation and exercise Rust's
  // authoritative validation directly.
  // ========================================================================

  const { health_check_json, simulate_graph_json } = await import(
    "../wasm/security_engine/security_engine.js"
  );

  // ------------------------------------------------------------------
  // Test 2: Unsupported contract version
  // ------------------------------------------------------------------
  {
    const result = health_check_json(
      JSON.stringify({ contract_version: "9.9", request_id: "m002-dev-002" }),
    );
    const parsed = parseEngineResponse(result);
    if (parsed.code === "UNSUPPORTED_CONTRACT_VERSION") {
      styledLog(
        "info",
        `NEGATIVE Test 2 (unsupported version): PASS — code="${parsed.code}" message="${parsed.message}"`,
      );
    } else {
      styledLog(
        "error",
        `NEGATIVE Test 2 (unsupported version): FAIL — expected UNSUPPORTED_CONTRACT_VERSION, got code="${parsed.code}"`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 3: Empty request ID
  // ------------------------------------------------------------------
  {
    const result = health_check_json(
      JSON.stringify({ contract_version: CONTRACT_VERSION, request_id: "" }),
    );
    const parsed = parseEngineResponse(result);
    if (parsed.code === "INVALID_REQUEST_ID") {
      styledLog(
        "info",
        `NEGATIVE Test 3 (empty request ID): PASS — code="${parsed.code}" message="${parsed.message}"`,
      );
    } else {
      styledLog(
        "error",
        `NEGATIVE Test 3 (empty request ID): FAIL — expected INVALID_REQUEST_ID, got code="${parsed.code}"`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 4: Malformed JSON
  // ------------------------------------------------------------------
  {
    const result = health_check_json("{not json}");
    const parsed = parseEngineResponse(result);
    if (parsed.code === "MALFORMED_JSON") {
      styledLog(
        "info",
        `NEGATIVE Test 4 (malformed JSON): PASS — code="${parsed.code}" message="${parsed.message}"`,
      );
    } else {
      styledLog(
        "error",
        `NEGATIVE Test 4 (malformed JSON): FAIL — expected MALFORMED_JSON, got code="${parsed.code}"`,
      );
    }
  }

  // ========================================================================
  // POSITIVE TESTS — through wasm-adapter (valid input)
  // ========================================================================

  // ------------------------------------------------------------------
  // Test 5: Valid graph request
  // ------------------------------------------------------------------
  try {
    const graphRequest: GraphSimulationRequest = {
      contract_version: CONTRACT_VERSION,
      request_id: "m003-dev-diagnostic-005",
      scenario_id: "scen-dev-001",
      assets: [
        { id: "asset-01", availability: "available" },
        { id: "asset-02", availability: "available" },
        { id: "asset-03", availability: "unavailable" },
      ],
      network_edges: [
        { id: "net-01", source_asset_id: "asset-01", target_asset_id: "asset-02", enabled: true },
        { id: "net-02", source_asset_id: "asset-02", target_asset_id: "asset-03", enabled: true },
      ],
      service_dependencies: [
        { id: "dep-01", dependent_asset_id: "asset-02", dependency_asset_id: "asset-03" },
      ],
      attack_source_asset_ids: ["asset-01"],
    };

    const graphResponse = simulateGraph(graphRequest);
    if (
      graphResponse.contract_version === CONTRACT_VERSION &&
      graphResponse.request_id === "m003-dev-diagnostic-005" &&
      graphResponse.scenario_id === "scen-dev-001" &&
      Array.isArray(graphResponse.network_reachability.reachable_asset_ids) &&
      Array.isArray(graphResponse.network_reachability.unreachable_asset_ids) &&
      Array.isArray(graphResponse.network_reachability.witnesses) &&
      Array.isArray(graphResponse.service_impact.initially_unavailable_asset_ids) &&
      Array.isArray(graphResponse.service_impact.impacted_dependent_asset_ids) &&
      Array.isArray(graphResponse.service_impact.unavailable_asset_ids)
    ) {
      styledLog(
        "info",
        `POSITIVE Test 5 (valid graph request): PASS — ` +
          `reachable=${graphResponse.network_reachability.reachable_asset_ids.join(",")}, ` +
          `unreachable=${graphResponse.network_reachability.unreachable_asset_ids.join(",")}, ` +
          `witnesses=${graphResponse.network_reachability.witnesses.length}, ` +
          `impacted=${graphResponse.service_impact.impacted_dependent_asset_ids.join(",")}, ` +
          `unavailable=${graphResponse.service_impact.unavailable_asset_ids.join(",")}`,
      );
    } else {
      styledLog(
        "error",
        `POSITIVE Test 5 (valid graph request): FAIL — incomplete response structure`,
      );
    }
  } catch (error) {
    styledLog(
      "error",
      `POSITIVE Test 5 (valid graph request): FAIL — ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  // ========================================================================
  // NEGATIVE TESTS — through raw simulate_graph_json binding
  // These bypass TypeScript-side validation and exercise Rust's
  // authoritative validation directly.
  // ========================================================================

  // ------------------------------------------------------------------
  // Test 6: Malformed JSON
  // ------------------------------------------------------------------
  {
    const result = simulate_graph_json("{not json}");
    const parsed = parseEngineResponse(result);
    if (parsed.code === "MALFORMED_JSON") {
      styledLog(
        "info",
        `NEGATIVE Test 6 (malformed JSON): PASS — code="${parsed.code}" message="${parsed.message}"`,
      );
    } else {
      styledLog(
        "error",
        `NEGATIVE Test 6 (malformed JSON): FAIL — expected MALFORMED_JSON, got code="${parsed.code}"`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 7: Missing nested required field
  // ------------------------------------------------------------------
  {
    const result = simulate_graph_json(
      JSON.stringify({
        contract_version: CONTRACT_VERSION,
        request_id: "m003-dev-007",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01" }], // missing availability
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      }),
    );
    const parsed = parseEngineResponse(result);
    if (parsed.code === "MALFORMED_JSON") {
      styledLog(
        "info",
        `NEGATIVE Test 7 (missing nested required field): PASS — code="${parsed.code}" message="${parsed.message}"`,
      );
    } else {
      styledLog(
        "error",
        `NEGATIVE Test 7 (missing nested required field): FAIL — expected MALFORMED_JSON, got code="${parsed.code}"`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 8: Unsupported contract version
  // ------------------------------------------------------------------
  {
    const result = simulate_graph_json(
      JSON.stringify({
        contract_version: "9.9",
        request_id: "m003-dev-008",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      }),
    );
    const parsed = parseEngineResponse(result);
    if (parsed.code === "UNSUPPORTED_CONTRACT_VERSION") {
      styledLog(
        "info",
        `NEGATIVE Test 8 (unsupported contract version): PASS — code="${parsed.code}" message="${parsed.message}"`,
      );
    } else {
      styledLog(
        "error",
        `NEGATIVE Test 8 (unsupported contract version): FAIL — expected UNSUPPORTED_CONTRACT_VERSION, got code="${parsed.code}"`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 9: Unknown asset reference
  // ------------------------------------------------------------------
  {
    const result = simulate_graph_json(
      JSON.stringify({
        contract_version: CONTRACT_VERSION,
        request_id: "m003-dev-009",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }],
        network_edges: [
          { id: "net-01", source_asset_id: "asset-01", target_asset_id: "nonexistent", enabled: true },
        ],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      }),
    );
    const parsed = parseEngineResponse(result);
    if (parsed.code === "UNKNOWN_ASSET_REFERENCE") {
      styledLog(
        "info",
        `NEGATIVE Test 9 (unknown asset reference): PASS — code="${parsed.code}" message="${parsed.message}"`,
      );
    } else {
      styledLog(
        "error",
        `NEGATIVE Test 9 (unknown asset reference): FAIL — expected UNKNOWN_ASSET_REFERENCE, got code="${parsed.code}"`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 10: Engine error through adapter becomes EngineRequestError
  // ------------------------------------------------------------------
  try {
    simulateGraph({
      contract_version: CONTRACT_VERSION,
      request_id: "m003-dev-010",
      scenario_id: "scen-dev-001",
      assets: [{ id: "asset-01", availability: "available" }],
      network_edges: [],
      service_dependencies: [],
      attack_source_asset_ids: ["nonexistent"], // unknown asset reference
    });
    styledLog(
      "error",
      "NEGATIVE Test 10 (adapter wraps engine error): FAIL — expected EngineRequestError, but simulateGraph succeeded",
    );
  } catch (error) {
    if (error instanceof EngineRequestError && error.code === "UNKNOWN_ASSET_REFERENCE") {
      styledLog(
        "info",
        `NEGATIVE Test 10 (adapter wraps engine error): PASS — code="${error.code}" message="${error.message}"`,
      );
    } else {
      styledLog(
        "error",
        `NEGATIVE Test 10 (adapter wraps engine error): FAIL — expected EngineRequestError with UNKNOWN_ASSET_REFERENCE, got ${error instanceof Error ? error.constructor.name : typeof error}`,
      );
    }
  }

  // ========================================================================
  // RESPONSE VALIDATION TESTS — through validateGraphResponse directly
  // ========================================================================

  // ------------------------------------------------------------------
  // Test 11: Valid non-empty witness list accepted
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-11",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01", "asset-02"],
        unreachable_asset_ids: [],
        witnesses: [
          { target_asset: "asset-01", source_asset: "asset-01", asset_path: ["asset-01"], edge_path: [] },
          { target_asset: "asset-02", source_asset: "asset-01", asset_path: ["asset-01", "asset-02"], edge_path: ["net-01"] },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-11",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "available" },
        ],
        network_edges: [{ id: "net-01", source_asset_id: "asset-01", target_asset_id: "asset-02", enabled: true }],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "info",
        "POSITIVE Test 11 (valid witness list): PASS — validateGraphResponse accepted valid response",
      );
    } catch (error) {
      styledLog(
        "error",
        `POSITIVE Test 11 (valid witness list): FAIL — ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 12: Correctly ordered witnesses accepted
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-12",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01", "asset-02", "asset-03"],
        unreachable_asset_ids: [],
        witnesses: [
          { target_asset: "asset-01", source_asset: "asset-01", asset_path: ["asset-01"], edge_path: [] },
          { target_asset: "asset-02", source_asset: "asset-01", asset_path: ["asset-01", "asset-02"], edge_path: ["net-01"] },
          { target_asset: "asset-03", source_asset: "asset-01", asset_path: ["asset-01", "asset-02", "asset-03"], edge_path: ["net-01", "net-02"] },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-12",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "available" },
          { id: "asset-03", availability: "available" },
        ],
        network_edges: [
          { id: "net-01", source_asset_id: "asset-01", target_asset_id: "asset-02", enabled: true },
          { id: "net-02", source_asset_id: "asset-02", target_asset_id: "asset-03", enabled: true },
        ],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "info",
        "POSITIVE Test 12 (ordered witnesses): PASS — validateGraphResponse accepted sorted witnesses",
      );
    } catch (error) {
      styledLog(
        "error",
        `POSITIVE Test 12 (ordered witnesses): FAIL — ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 13: Duplicate witness target rejected
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-13",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01", "asset-02"],
        unreachable_asset_ids: [],
        witnesses: [
          { target_asset: "asset-01", source_asset: "asset-01", asset_path: ["asset-01"], edge_path: [] },
          { target_asset: "asset-01", source_asset: "asset-01", asset_path: ["asset-01"], edge_path: [] },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-13",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }, { id: "asset-02", availability: "available" }],
        network_edges: [{ id: "net-01", source_asset_id: "asset-01", target_asset_id: "asset-02", enabled: true }],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 13 (duplicate witness target): FAIL — validateGraphResponse should have rejected duplicate witness targets",
      );
    } catch (error) {
      if (error instanceof EngineResponseError) {
        styledLog(
          "info",
          `NEGATIVE Test 13 (duplicate witness target): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 13 (duplicate witness target): FAIL — expected EngineResponseError, got ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 14: Missing witness rejected
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-14",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01", "asset-02"],
        unreachable_asset_ids: [],
        witnesses: [
          { target_asset: "asset-01", source_asset: "asset-01", asset_path: ["asset-01"], edge_path: [] },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-14",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "available" },
        ],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 14 (missing witness): FAIL — validateGraphResponse should have rejected missing witness for asset-02",
      );
    } catch (error) {
      if (error instanceof EngineResponseError) {
        styledLog(
          "info",
          `NEGATIVE Test 14 (missing witness): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 14 (missing witness): FAIL — expected EngineResponseError, got ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 15: Null witness rejected with EngineResponseError
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-15",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01"],
        unreachable_asset_ids: [],
        witnesses: [null as any],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-15",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 15 (null witness): FAIL — validateGraphResponse should have rejected null witness",
      );
    } catch (error) {
      if (error instanceof EngineResponseError) {
        styledLog(
          "info",
          `NEGATIVE Test 15 (null witness): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 15 (null witness): FAIL — expected EngineResponseError, got ${error instanceof Error ? error.constructor.name : typeof error}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 16: Array witness rejected with EngineResponseError
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-16",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01"],
        unreachable_asset_ids: [],
        witnesses: [[] as any],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-16",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 16 (array witness): FAIL — validateGraphResponse should have rejected array witness",
      );
    } catch (error) {
      if (error instanceof EngineResponseError) {
        styledLog(
          "info",
          `NEGATIVE Test 16 (array witness): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 16 (array witness): FAIL — expected EngineResponseError, got ${error instanceof Error ? error.constructor.name : typeof error}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 17: Incorrect edge-to-asset path rejected
  // Uses an existing edge whose endpoints do not match the witness path.
  // Two witnesses: valid self-witness for asset-01, then asset-02 witness
  // whose edge endpoints are reversed.
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-17",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01", "asset-02"],
        unreachable_asset_ids: [],
        witnesses: [
          {
            target_asset: "asset-01",
            source_asset: "asset-01",
            asset_path: ["asset-01"],
            edge_path: [],
          },
          {
            target_asset: "asset-02",
            source_asset: "asset-01",
            asset_path: ["asset-01", "asset-02"],
            edge_path: ["net-01"],
          },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-17",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "available" },
        ],
        // net-01 connects asset-02 -> asset-01, but witness claims net-01
        // connects asset-01 -> asset-02 (swapped endpoints).
        network_edges: [{ id: "net-01", source_asset_id: "asset-02", target_asset_id: "asset-01", enabled: true }],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 17 (incorrect edge-to-asset path): FAIL — validateGraphResponse should have rejected mismatched edge-path",
      );
    } catch (error) {
      if (
        error instanceof EngineResponseError &&
        error.code === "INVALID_RESPONSE_SHAPE" &&
        error.message === "edge 'net-01' source 'asset-02' does not match asset_path[0] 'asset-01'"
      ) {
        styledLog(
          "info",
          `NEGATIVE Test 17 (incorrect edge-to-asset path): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 17 (incorrect edge-to-asset path): FAIL — expected EngineResponseError code=INVALID_RESPONSE_SHAPE message="edge 'net-01' source 'asset-02' does not match asset_path[0] 'asset-01'", got ${error instanceof Error ? error.constructor.name : typeof error}${(error as any).code ? ` code="${(error as any).code}"` : ""}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 18: Disabled edge in witness rejected
  // Two witnesses: valid self-witness for asset-01, then asset-02 witness
  // whose edge is disabled.
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-18",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01", "asset-02"],
        unreachable_asset_ids: [],
        witnesses: [
          {
            target_asset: "asset-01",
            source_asset: "asset-01",
            asset_path: ["asset-01"],
            edge_path: [],
          },
          {
            target_asset: "asset-02",
            source_asset: "asset-01",
            asset_path: ["asset-01", "asset-02"],
            edge_path: ["net-01"],
          },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-18",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "available" },
        ],
        network_edges: [{ id: "net-01", source_asset_id: "asset-01", target_asset_id: "asset-02", enabled: false }],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 18 (disabled edge in witness): FAIL — validateGraphResponse should have rejected disabled edge",
      );
    } catch (error) {
      if (
        error instanceof EngineResponseError &&
        error.code === "INVALID_RESPONSE_SHAPE" &&
        error.message === "edge 'net-01' in witness path is not enabled"
      ) {
        styledLog(
          "info",
          `NEGATIVE Test 18 (disabled edge in witness): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 18 (disabled edge in witness): FAIL — expected EngineResponseError code=INVALID_RESPONSE_SHAPE message="edge 'net-01' in witness path is not enabled", got ${error instanceof Error ? error.constructor.name : typeof error}${(error as any).code ? ` code="${(error as any).code}"` : ""}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 19: Witness source not in attack-source list rejected
  // Source is a valid request asset, asset_path starts with source,
  // target matches final path element, edges are valid/enabled/connected,
  // but source is absent from attack_source_asset_ids.
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-19",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01"],
        unreachable_asset_ids: ["asset-02"],
        witnesses: [
          {
            target_asset: "asset-01",
            source_asset: "asset-01",
            asset_path: ["asset-01"],
            edge_path: [],
          },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-19",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "available" },
        ],
        network_edges: [],
        service_dependencies: [],
        // asset-01 is NOT in attack_source_asset_ids -> should be rejected
        attack_source_asset_ids: ["asset-02"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 19 (witness source not in attack sources): FAIL — validateGraphResponse should have rejected witness with source not in attack sources",
      );
    } catch (error) {
      if (
        error instanceof EngineResponseError &&
        error.code === "INVALID_RESPONSE_SHAPE" &&
        error.message === "witness source 'asset-01' is not in attack_source_asset_ids"
      ) {
        styledLog(
          "info",
          `NEGATIVE Test 19 (witness source not in attack sources): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 19 (witness source not in attack sources): FAIL — expected EngineResponseError code=INVALID_RESPONSE_SHAPE message="witness source 'asset-01' is not in attack_source_asset_ids", got ${error instanceof Error ? error.constructor.name : typeof error}${(error as any).code ? ` code="${(error as any).code}"` : ""}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 20: Missing initially unavailable asset rejected
  // asset-02 is marked unavailable in the request but omitted from
  // response's initially_unavailable_asset_ids.
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-20",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01"],
        unreachable_asset_ids: ["asset-02"],
        witnesses: [
          {
            target_asset: "asset-01",
            source_asset: "asset-01",
            asset_path: ["asset-01"],
            edge_path: [],
          },
        ],
      },
      service_impact: {
        // asset-02 is missing from initially_unavailable_asset_ids
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: ["asset-02"],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-20",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "unavailable" },
        ],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 20 (missing initially unavailable): FAIL — validateGraphResponse should have rejected missing initially unavailable asset",
      );
    } catch (error) {
      if (
        error instanceof EngineResponseError &&
        error.code === "INVALID_RESPONSE_SHAPE" &&
        error.message === "initially_unavailable_asset_ids is missing unavailable asset 'asset-02'"
      ) {
        styledLog(
          "info",
          `NEGATIVE Test 20 (missing initially unavailable): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 20 (missing initially unavailable): FAIL — expected EngineResponseError code=INVALID_RESPONSE_SHAPE message="initially_unavailable_asset_ids is missing unavailable asset 'asset-02'", got ${error instanceof Error ? error.constructor.name : typeof error}${(error as any).code ? ` code="${(error as any).code}"` : ""}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 21: Unknown ID in reachable_asset_ids rejected
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-21",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01", "asset-99"], // asset-99 not in request
        unreachable_asset_ids: [],
        witnesses: [
          {
            target_asset: "asset-01",
            source_asset: "asset-01",
            asset_path: ["asset-01"],
            edge_path: [],
          },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-21",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "available" },
        ],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 21 (unknown reachable ID): FAIL — validateGraphResponse should have rejected unknown ID in reachable_asset_ids",
      );
    } catch (error) {
      if (
        error instanceof EngineResponseError &&
        error.code === "INVALID_RESPONSE_SHAPE" &&
        error.message === "reachable_asset_ids contains unknown asset 'asset-99'"
      ) {
        styledLog(
          "info",
          `NEGATIVE Test 21 (unknown reachable ID): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 21 (unknown reachable ID): FAIL — expected EngineResponseError code=INVALID_RESPONSE_SHAPE message="reachable_asset_ids contains unknown asset 'asset-99'", got ${error instanceof Error ? error.constructor.name : typeof error}${(error as any).code ? ` code="${(error as any).code}"` : ""}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 22: Unknown ID in unreachable_asset_ids rejected
  // ------------------------------------------------------------------
  {
    const resp: GraphSimulationResponse = {
      contract_version: CONTRACT_VERSION,
      request_id: "diag-22",
      scenario_id: "scen-dev-001",
      network_reachability: {
        reachable_asset_ids: ["asset-01"],
        unreachable_asset_ids: ["asset-99"], // asset-99 not in request
        witnesses: [
          {
            target_asset: "asset-01",
            source_asset: "asset-01",
            asset_path: ["asset-01"],
            edge_path: [],
          },
        ],
      },
      service_impact: {
        initially_unavailable_asset_ids: [],
        impacted_dependent_asset_ids: [],
        unavailable_asset_ids: [],
      },
    };
    try {
      validateGraphResponse(resp, {
        contract_version: CONTRACT_VERSION,
        request_id: "diag-22",
        scenario_id: "scen-dev-001",
        assets: [
          { id: "asset-01", availability: "available" },
          { id: "asset-02", availability: "available" },
        ],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      });
      styledLog(
        "error",
        "NEGATIVE Test 22 (unknown unreachable ID): FAIL — validateGraphResponse should have rejected unknown ID in unreachable_asset_ids",
      );
    } catch (error) {
      if (
        error instanceof EngineResponseError &&
        error.code === "INVALID_RESPONSE_SHAPE" &&
        error.message === "unreachable_asset_ids contains unknown asset 'asset-99'"
      ) {
        styledLog(
          "info",
          `NEGATIVE Test 22 (unknown unreachable ID): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 22 (unknown unreachable ID): FAIL — expected EngineResponseError code=INVALID_RESPONSE_SHAPE message="unreachable_asset_ids contains unknown asset 'asset-99'", got ${error instanceof Error ? error.constructor.name : typeof error}${(error as any).code ? ` code="${(error as any).code}"` : ""}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ========================================================================
  // REQUEST VALIDATION TESTS — through validateGraphRequest directly
  // ========================================================================

  // ------------------------------------------------------------------
  // Test 23: Null request rejected
  // ------------------------------------------------------------------
  {
    try {
      validateGraphRequest(null as any);
      styledLog(
        "error",
        "NEGATIVE Test 23 (null request): FAIL — validateGraphRequest should have rejected null request",
      );
    } catch (error) {
      if (error instanceof EngineRequestError) {
        styledLog(
          "info",
          `NEGATIVE Test 23 (null request): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 23 (null request): FAIL — expected EngineRequestError, got ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 24: Missing assets array rejected
  // ------------------------------------------------------------------
  {
    try {
      validateGraphRequest({
        contract_version: "1.0",
        request_id: "diag-24",
        scenario_id: "scen-dev-001",
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: [],
      } as any);
      styledLog(
        "error",
        "NEGATIVE Test 24 (missing assets array): FAIL — validateGraphRequest should have rejected missing assets array",
      );
    } catch (error) {
      if (error instanceof EngineRequestError) {
        styledLog(
          "info",
          `NEGATIVE Test 24 (missing assets array): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 24 (missing assets array): FAIL — expected EngineRequestError, got ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 25: Null asset entry rejected
  // ------------------------------------------------------------------
  {
    try {
      validateGraphRequest({
        contract_version: "1.0",
        request_id: "diag-25",
        scenario_id: "scen-dev-001",
        assets: [null as any],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: [],
      } as any);
      styledLog(
        "error",
        "NEGATIVE Test 25 (null asset entry): FAIL — validateGraphRequest should have rejected null asset entry",
      );
    } catch (error) {
      if (error instanceof EngineRequestError) {
        styledLog(
          "info",
          `NEGATIVE Test 25 (null asset entry): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 25 (null asset entry): FAIL — expected EngineRequestError, got ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 26: Null edge entry rejected
  // ------------------------------------------------------------------
  {
    try {
      validateGraphRequest({
        contract_version: "1.0",
        request_id: "diag-26",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }],
        network_edges: [null as any],
        service_dependencies: [],
        attack_source_asset_ids: [],
      } as any);
      styledLog(
        "error",
        "NEGATIVE Test 26 (null edge entry): FAIL — validateGraphRequest should have rejected null edge entry",
      );
    } catch (error) {
      if (error instanceof EngineRequestError) {
        styledLog(
          "info",
          `NEGATIVE Test 26 (null edge entry): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 26 (null edge entry): FAIL — expected EngineRequestError, got ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 27: Null dependency entry rejected
  // ------------------------------------------------------------------
  {
    try {
      validateGraphRequest({
        contract_version: "1.0",
        request_id: "diag-27",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }],
        network_edges: [],
        service_dependencies: [null as any],
        attack_source_asset_ids: [],
      } as any);
      styledLog(
        "error",
        "NEGATIVE Test 27 (null dependency entry): FAIL — validateGraphRequest should have rejected null dependency entry",
      );
    } catch (error) {
      if (error instanceof EngineRequestError) {
        styledLog(
          "info",
          `NEGATIVE Test 27 (null dependency entry): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 27 (null dependency entry): FAIL — expected EngineRequestError, got ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 28: Missing attack_source_asset_ids array rejected
  // ------------------------------------------------------------------
  {
    try {
      validateGraphRequest({
        contract_version: "1.0",
        request_id: "diag-28",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }],
        network_edges: [],
        service_dependencies: [],
      } as any);
      styledLog(
        "error",
        "NEGATIVE Test 28 (missing attack_source_asset_ids): FAIL — validateGraphRequest should have rejected missing attack_source_asset_ids array",
      );
    } catch (error) {
      if (error instanceof EngineRequestError) {
        styledLog(
          "info",
          `NEGATIVE Test 28 (missing attack_source_asset_ids): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 28 (missing attack_source_asset_ids): FAIL — expected EngineRequestError, got ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 29: Backslash-containing identifiers rejected
  // ------------------------------------------------------------------
  {
    try {
      validateGraphRequest({
        contract_version: "1.0",
        request_id: "diag-29",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset\\01", availability: "available" }],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      } as any);
      styledLog(
        "error",
        "NEGATIVE Test 29 (backslash identifier): FAIL — validateGraphRequest should have rejected backslash in identifier",
      );
    } catch (error) {
      if (error instanceof EngineRequestError && error.code === "INVALID_GRAPH") {
        styledLog(
          "info",
          `NEGATIVE Test 29 (backslash identifier): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 29 (backslash identifier): FAIL — expected EngineRequestError INVALID_GRAPH, got ${error instanceof Error ? error.constructor.name : typeof error}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  // ------------------------------------------------------------------
  // Test 30: Serialization failure becomes EngineRequestError
  // Structurally valid request (all required collections present),
  // then a circular reference is added so JSON.stringify fails.
  // This proves: request validation passes -> serialization attempted
  // -> serialization fails -> REQUEST_SERIALIZATION_FAILED thrown.
  // ------------------------------------------------------------------
  {
    try {
      const cyclic: any = {
        contract_version: "1.0",
        request_id: "diag-30",
        scenario_id: "scen-dev-001",
        assets: [{ id: "asset-01", availability: "available" }],
        network_edges: [],
        service_dependencies: [],
        attack_source_asset_ids: ["asset-01"],
      };
      cyclic.self = cyclic;
      simulateGraph(cyclic as GraphSimulationRequest);
      styledLog(
        "error",
        "NEGATIVE Test 30 (serialization failure): FAIL — simulateGraph should have thrown REQUEST_SERIALIZATION_FAILED",
      );
    } catch (error) {
      if (error instanceof EngineRequestError && error.code === "REQUEST_SERIALIZATION_FAILED") {
        styledLog(
          "info",
          `NEGATIVE Test 30 (serialization failure): PASS — code="${error.code}" message="${error.message}"`,
        );
      } else {
        styledLog(
          "error",
          `NEGATIVE Test 30 (serialization failure): FAIL — expected EngineRequestError REQUEST_SERIALIZATION_FAILED, got ${error instanceof Error ? error.constructor.name : typeof error}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  styledLog("info", "WASM diagnostic suite complete.");
}

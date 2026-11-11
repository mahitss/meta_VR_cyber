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
  CONTRACT_VERSION,
  GraphSimulationRequest,
  EngineRequestError,
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

  styledLog("info", "WASM diagnostic suite complete.");
}

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
//
//   NEGATIVE (through raw health_check_json binding, invalid input):
//     2. Unsupported contract version -> UNSUPPORTED_CONTRACT_VERSION
//     3. Empty request ID -> INVALID_REQUEST_ID
//     4. Malformed JSON -> MALFORMED_JSON
//
// Negative tests invoke the raw Rust binding directly, bypassing
// TypeScript-side validation, so they exercise the Rust engine's
// authoritative validation.
// ============================================================================

import { initialize, healthCheck, CONTRACT_VERSION } from "./wasm-adapter";

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

  const { health_check_json } = await import(
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

  styledLog("info", "WASM diagnostic suite complete.");
}

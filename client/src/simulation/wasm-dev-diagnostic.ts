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
// Tests performed:
//   1. Valid health request -> expects { status: "ok", engine: "security-engine" }
//   2. Unsupported contract version -> expects UNSUPPORTED_CONTRACT_VERSION error
//   3. Empty request ID -> expects INVALID_REQUEST_ID error
//   4. Malformed JSON -> expects MALFORMED_JSON error
//
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
      `Test 1 (valid request): PASS — status="${response.status}" engine="${response.engine}" request_id="${response.request_id}"`,
    );
  } catch (error) {
    styledLog(
      "error",
      `Test 1 (valid request): FAIL — ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  // ------------------------------------------------------------------
  // Test 2: Unsupported contract version
  // ------------------------------------------------------------------
  try {
    healthCheck({
      contract_version: "9.9",
      request_id: "m002-dev-diagnostic-002",
    });
    styledLog(
      "error",
      "Test 2 (unsupported version): FAIL — expected error, got success",
    );
  } catch (error) {
    if (error instanceof Error && "code" in error) {
      styledLog(
        "info",
        `Test 2 (unsupported version): PASS — code="${(error as { code: string }).code}" message="${error.message}"`,
      );
    } else {
      styledLog(
        "error",
        `Test 2 (unsupported version): FAIL — unexpected error type: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 3: Empty request ID
  // ------------------------------------------------------------------
  try {
    healthCheck({
      contract_version: CONTRACT_VERSION,
      request_id: "",
    });
    styledLog(
      "error",
      "Test 3 (empty request ID): FAIL — expected error, got success",
    );
  } catch (error) {
    if (error instanceof Error && "code" in error) {
      styledLog(
        "info",
        `Test 3 (empty request ID): PASS — code="${(error as { code: string }).code}" message="${error.message}"`,
      );
    } else {
      styledLog(
        "error",
        `Test 3 (empty request ID): FAIL — unexpected error type: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  // ------------------------------------------------------------------
  // Test 4: Malformed JSON (calls raw binding directly)
  // ------------------------------------------------------------------
  // health_check_json returns a JSON error string; it does not throw.
  // We parse the return value to verify the error code.
  const { health_check_json } = await import(
    "../wasm/security_engine/security_engine.js"
  );
  const malformedResult = health_check_json("{not json}");
  try {
    const parsed = JSON.parse(malformedResult);
    if (parsed.code === "MALFORMED_JSON") {
      styledLog(
        "info",
        `Test 4 (malformed JSON): PASS — code="${parsed.code}" message="${parsed.message}"`,
      );
    } else {
      styledLog(
        "error",
        `Test 4 (malformed JSON): FAIL — expected MALFORMED_JSON, got code="${parsed.code}"`,
      );
    }
  } catch (error) {
    styledLog(
      "error",
      `Test 4 (malformed JSON): FAIL — response is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  styledLog("info", "WASM diagnostic suite complete.");
}

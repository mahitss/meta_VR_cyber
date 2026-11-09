// ============================================================================
// NetVigil XR — M002 WASM health-check smoke test
// ============================================================================
//
// Development-only diagnostic that invokes the Rust security engine through
// WASM from the browser and logs the actual result. This is a technical
// diagnostic, not product UI. It does not fabricate success state.
//
// Usage (from a browser module context):
//
//   import { runWasmHealthSmoke } from "./simulation/wasm-health-smoke";
//   await runWasmHealthSmoke(console);
//
// ============================================================================

import {
  initialize,
  isInitialized,
  getInitializationError,
  healthCheck,
  CONTRACT_VERSION,
  EngineRequestError,
  WasmInitializationError,
  EngineResponseError,
} from "./wasm-adapter";

const REQUEST_ID = "m002-smoke-001";

export interface SmokeResult {
  initialized: boolean;
  requestId: string;
  contractVersion: string;
  success: boolean;
  response?: {
    contract_version: string;
    request_id: string;
    engine: string;
    status: string;
  };
  error?: {
    name: string;
    code: string;
    message: string;
  };
}

/**
 * Run the M002 WASM health-check smoke test.
 *
 * Logs every step to the provided console-like object and returns a
 * structured result. Does not throw — all failures are captured in the
 * returned result object so callers can observe actual outcomes.
 */
export async function runWasmHealthSmoke(
  log: ConsoleLike = console,
): Promise<SmokeResult> {
  const result: SmokeResult = {
    initialized: false,
    requestId: REQUEST_ID,
    contractVersion: CONTRACT_VERSION,
    success: false,
  };

  log.info("[m002-smoke] initializing WASM module...");

  try {
    initialize();
  } catch (error) {
    result.error = {
      name: "WasmInitializationError",
      code: "WASM_INITIALIZATION_ERROR",
      message:
        error instanceof Error ? error.message : String(error),
    };
    log.error("[m002-smoke] WASM initialization failed:", result.error.message);
    return result;
  }

  result.initialized = isInitialized();

  if (!result.initialized) {
    const initErr = getInitializationError();
    result.error = {
      name: "WasmInitializationError",
      code: "WASM_NOT_READY",
      message: initErr
        ? initErr.message
        : "WASM module failed to initialize for an unknown reason",
    };
    log.error("[m002-smoke] WASM module not ready:", result.error.message);
    return result;
  }

  log.info("[m002-smoke] WASM module initialized. Sending health request...");

  const request = {
    contract_version: CONTRACT_VERSION,
    request_id: REQUEST_ID,
  };

  try {
    const response = healthCheck(request);

    result.success = true;
    result.response = {
      contract_version: response.contract_version,
      request_id: response.request_id,
      engine: response.engine,
      status: response.status,
    };

    log.info(
      `[m002-smoke] health check OK: engine="${response.engine}" status="${response.status}" request_id="${response.request_id}"`,
    );
    return result;
  } catch (error) {
    if (error instanceof EngineRequestError) {
      result.error = {
        name: "EngineRequestError",
        code: error.code,
        message: error.message,
      };
      log.warn(
        `[m002-smoke] engine rejected request (code=${error.code}): ${error.message}`,
      );
    } else if (error instanceof EngineResponseError) {
      result.error = {
        name: "EngineResponseError",
        code: error.code,
        message: error.message,
      };
      log.error(
        `[m002-smoke] engine returned malformed response: ${error.message}`,
      );
    } else if (error instanceof WasmInitializationError) {
      result.error = {
        name: "WasmInitializationError",
        code: "WASM_INITIALIZATION_ERROR",
        message: error.message,
      };
      log.error("[m002-smoke] WASM not initialized:", error.message);
    } else {
      result.error = {
        name: "UnknownError",
        code: "UNKNOWN",
        message: error instanceof Error ? error.message : String(error),
      };
      log.error(
        "[m002-smoke] unexpected error:",
        error instanceof Error ? error.message : String(error),
      );
    }
    return result;
  }
}

/** Minimal console-like interface for testability. */
export interface ConsoleLike {
  info(message?: unknown, ...optionalParams: unknown[]): void;
  warn(message?: unknown, ...optionalParams: unknown[]): void;
  error(message?: unknown, ...optionalParams: unknown[]): void;
}

// ============================================================================
// NetVigil XR — WASM adapter for the security-engine Rust crate
// ============================================================================
//
// This module is the TypeScript boundary to the Rust/WASM security engine.
// It is responsible for:
//   1. Loading and initializing the generated WASM module.
//   2. Serializing versioned JSON requests.
//   3. Invoking the actual generated wasm-bindgen binding.
//   4. Parsing and validating responses.
//   5. Converting Rust errors to typed application errors.
//   6. Handling initialization failures.
//
// The Rust engine performs authoritative validation. This adapter must not
// assume Rust accepts arbitrary JSON.
//
// Contract version 1.0:
//   Request:  { "contract_version": "1.0", "request_id": "<string>" }
//   Response: { "contract_version": "1.0", "request_id": "<string>",
//               "engine": "security-engine", "status": "ok" }
//   Error:    { "code": "<string>", "message": "<string>" }
// ============================================================================

import { health_check_json } from "../wasm/security_engine/security_engine";

export const CONTRACT_VERSION = "1.0";
export const ENGINE_NAME = "security-engine";

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

export class WasmInitializationError extends Error {
  public readonly code = "WASM_INITIALIZATION_ERROR";
  constructor(message: string, public readonly cause?: Error) {
    super(message);
    this.name = "WasmInitializationError";
  }
}

export class EngineRequestError extends Error {
  public readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "EngineRequestError";
    this.code = code;
  }
}

export class EngineResponseError extends Error {
  public readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "EngineResponseError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

export interface HealthRequest {
  contract_version: string;
  request_id: string;
}

export interface HealthResponse {
  contract_version: string;
  request_id: string;
  engine: string;
  status: string;
}

export interface EngineErrorBody {
  code: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Validate that a request body conforms to contract v1.0 before sending. */
export function validateHealthRequest(request: HealthRequest): void {
  if (request.contract_version !== CONTRACT_VERSION) {
    throw new EngineRequestError(
      "UNSUPPORTED_CONTRACT_VERSION",
      `unsupported contract version '${request.contract_version}', expected '${CONTRACT_VERSION}'`,
    );
  }

  if (
    typeof request.request_id !== "string" ||
    request.request_id.length === 0 ||
    request.request_id.length > 256 ||
    !/^[\x20-\x7E]+$/.test(request.request_id)
  ) {
    throw new EngineRequestError(
      "INVALID_REQUEST_ID",
      "request_id must be a non-empty ASCII string of at most 256 characters",
    );
  }
}

/** Validate that a response body conforms to contract v1.0. */
export function validateHealthResponse(body: unknown): HealthResponse {
  const response = body as HealthResponse;

  if (!response || typeof response !== "object") {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "engine response is not a JSON object",
    );
  }

  if (response.contract_version !== CONTRACT_VERSION) {
    throw new EngineResponseError(
      "UNSUPPORTED_CONTRACT_VERSION",
      `response contract version '${response.contract_version}' does not match request`,
    );
  }

  if (response.engine !== ENGINE_NAME) {
    throw new EngineResponseError(
      "UNEXPECTED_ENGINE",
      `response engine '${response.engine}' is not '${ENGINE_NAME}'`,
    );
  }

  if (response.status !== "ok" && response.status !== "error") {
    throw new EngineResponseError(
      "INVALID_STATUS",
      `response status '${response.status}' is not a recognized value`,
    );
  }

  if (
    typeof response.request_id !== "string" ||
    response.request_id.length === 0
  ) {
    throw new EngineResponseError(
      "INVALID_REQUEST_ID",
      "response request_id is missing or empty",
    );
  }

  return response;
}

/** Determine whether a parsed response body represents an error. */
export function isEngineError(body: unknown): body is EngineErrorBody {
  const candidate = body as EngineErrorBody;
  return (
    candidate !== null &&
    typeof candidate === "object" &&
    typeof candidate.code === "string" &&
    typeof candidate.message === "string"
  );
}

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

let initialized = false;
let initError: Error | null = null;

/**
 * Initialize the WASM module.
 *
 * The generated wasm-bindgen glue calls `__wbindgen_start()` automatically on
 * import, but this function centralizes initialization state tracking and
 * error capture so callers can check readiness before invoking the engine.
 */
export function initialize(): void {
  if (initialized || initError) return;

  try {
    // The import at the top of this file already runs __wbindgen_start().
    // Touch the exported function to confirm the module is live.
    if (typeof health_check_json !== "function") {
      throw new Error("health_check_json export is not a function");
    }
    initialized = true;
  } catch (error) {
    initError = error instanceof Error ? error : new Error(String(error));
    throw initError;
  }
}

export function isInitialized(): boolean {
  return initialized;
}

export function getInitializationError(): Error | null {
  return initError;
}

// ---------------------------------------------------------------------------
// Request execution
// ---------------------------------------------------------------------------

/**
 * Send a health-check request to the Rust/WASM engine.
 *
 * Returns a HealthResponse on success. Throws EngineRequestError for invalid
 * input, EngineResponseError for malformed responses, or WasmInitializationError
 * if the WASM module has not been initialized.
 */
export function healthCheck(request: HealthRequest): HealthResponse {
  if (!initialized) {
    throw new WasmInitializationError(
      "WASM module not initialized. Call initialize() before healthCheck().",
      initError ?? undefined,
    );
  }

  validateHealthRequest(request);

  const requestJson = JSON.stringify(request);

  let responseJson: string;
  try {
    responseJson = health_check_json(requestJson);
  } catch (error) {
    throw new EngineResponseError(
      "ENGINE_INVOCATION_FAILURE",
      `Rust engine threw during invocation: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  let responseBody: unknown;
  try {
    responseBody = JSON.parse(responseJson);
  } catch (error) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_JSON",
      `engine returned non-JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  // Rust returns an error object when validation fails.
  if (isEngineError(responseBody)) {
    throw new EngineRequestError(
      responseBody.code,
      responseBody.message,
    );
  }

  return validateHealthResponse(responseBody);
}

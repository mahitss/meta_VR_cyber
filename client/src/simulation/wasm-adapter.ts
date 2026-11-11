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

import { health_check_json, simulate_graph_json } from "../wasm/security_engine/security_engine";

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
// Graph simulation request/response types
// ---------------------------------------------------------------------------

export interface Asset {
  id: string;
  availability: "available" | "unavailable";
}

export interface NetworkEdge {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  enabled: boolean;
}

export interface ServiceDependency {
  id: string;
  dependent_asset_id: string;
  dependency_asset_id: string;
}

export interface GraphSimulationRequest {
  contract_version: string;
  request_id: string;
  scenario_id: string;
  assets: Asset[];
  network_edges: NetworkEdge[];
  service_dependencies: ServiceDependency[];
  attack_source_asset_ids: string[];
}

export interface Witness {
  target_asset: string;
  source_asset: string;
  asset_path: string[];
  edge_path: string[];
}

export interface NetworkReachability {
  reachable_asset_ids: string[];
  unreachable_asset_ids: string[];
  witnesses: Witness[];
}

export interface ServiceImpact {
  initially_unavailable_asset_ids: string[];
  impacted_dependent_asset_ids: string[];
  unavailable_asset_ids: string[];
}

export interface GraphSimulationResponse {
  contract_version: string;
  request_id: string;
  scenario_id: string;
  network_reachability: NetworkReachability;
  service_impact: ServiceImpact;
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
// Graph request validation
// ---------------------------------------------------------------------------

/** Validate that a graph simulation request body conforms to contract v1.0. */
export function validateGraphRequest(request: GraphSimulationRequest): void {
  // Runtime structural guards — reject malformed input before touching fields
  if (request === null) {
    throw new EngineRequestError(
      "INVALID_GRAPH",
      "request is null",
    );
  }
  if (typeof request !== "object" || Array.isArray(request)) {
    throw new EngineRequestError(
      "INVALID_GRAPH",
      "request must be a non-null object",
    );
  }
  if (
    typeof request.contract_version !== "string" ||
    request.contract_version.length === 0 ||
    request.contract_version.length > 256 ||
    !/^[\x20-\x7E]+$/.test(request.contract_version)
  ) {
    throw new EngineRequestError(
      "INVALID_CONTRACT_VERSION",
      "contract_version must be a non-empty ASCII string of at most 256 characters",
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

  if (
    typeof request.scenario_id !== "string" ||
    request.scenario_id.length === 0 ||
    request.scenario_id.length > 64 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(request.scenario_id)
  ) {
    throw new EngineRequestError(
      "INVALID_SCENARIO_ID",
      "scenario_id must start with an alphanumeric character and contain only alphanumeric, '.', '_', ':', or '-', max 64 characters",
    );
  }

  // Validate assets array
  if (!Array.isArray(request.assets)) {
    throw new EngineRequestError(
      "INVALID_GRAPH",
      "assets must be an array",
    );
  }
  for (const [i, asset] of request.assets.entries()) {
    if (asset === null || typeof asset !== "object" || Array.isArray(asset)) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `asset at index ${i} must be a non-null object`,
      );
    }
    if (
      typeof asset.id !== "string" ||
      asset.id.length === 0 ||
      asset.id.length > 64 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(asset.id)
    ) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `asset at index ${i} has invalid id '${asset.id}'`,
      );
    }
    if (asset.availability !== "available" && asset.availability !== "unavailable") {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `asset at index ${i} has invalid availability '${asset.availability}'`,
      );
    }
  }

  // Validate network edges array
  if (!Array.isArray(request.network_edges)) {
    throw new EngineRequestError(
      "INVALID_GRAPH",
      "network_edges must be an array",
    );
  }
  for (const [i, edge] of request.network_edges.entries()) {
    if (edge === null || typeof edge !== "object" || Array.isArray(edge)) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `network edge at index ${i} must be a non-null object`,
      );
    }
    if (
      typeof edge.id !== "string" ||
      edge.id.length === 0 ||
      edge.id.length > 64 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(edge.id)
    ) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `network edge at index ${i} has invalid id '${edge.id}'`,
      );
    }
    if (
      typeof edge.source_asset_id !== "string" ||
      edge.source_asset_id.length === 0 ||
      edge.source_asset_id.length > 64 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(edge.source_asset_id)
    ) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `network edge at index ${i} has invalid source_asset_id '${edge.source_asset_id}'`,
      );
    }
    if (
      typeof edge.target_asset_id !== "string" ||
      edge.target_asset_id.length === 0 ||
      edge.target_asset_id.length > 64 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(edge.target_asset_id)
    ) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `network edge at index ${i} has invalid target_asset_id '${edge.target_asset_id}'`,
      );
    }
    if (typeof edge.enabled !== "boolean") {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `network edge at index ${i} has invalid enabled field`,
      );
    }
  }

  // Validate service dependencies array
  if (!Array.isArray(request.service_dependencies)) {
    throw new EngineRequestError(
      "INVALID_GRAPH",
      "service_dependencies must be an array",
    );
  }
  for (const [i, dep] of request.service_dependencies.entries()) {
    if (dep === null || typeof dep !== "object" || Array.isArray(dep)) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `service dependency at index ${i} must be a non-null object`,
      );
    }
    if (
      typeof dep.id !== "string" ||
      dep.id.length === 0 ||
      dep.id.length > 64 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(dep.id)
    ) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `service dependency at index ${i} has invalid id '${dep.id}'`,
      );
    }
    if (
      typeof dep.dependent_asset_id !== "string" ||
      dep.dependent_asset_id.length === 0 ||
      dep.dependent_asset_id.length > 64 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(dep.dependent_asset_id)
    ) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `service dependency at index ${i} has invalid dependent_asset_id '${dep.dependent_asset_id}'`,
      );
    }
    if (
      typeof dep.dependency_asset_id !== "string" ||
      dep.dependency_asset_id.length === 0 ||
      dep.dependency_asset_id.length > 64 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(dep.dependency_asset_id)
    ) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `service dependency at index ${i} has invalid dependency_asset_id '${dep.dependency_asset_id}'`,
      );
    }
  }

  // Validate attack sources array
  if (!Array.isArray(request.attack_source_asset_ids)) {
    throw new EngineRequestError(
      "INVALID_GRAPH",
      "attack_source_asset_ids must be an array",
    );
  }
  for (const [i, source_id] of request.attack_source_asset_ids.entries()) {
    if (
      typeof source_id !== "string" ||
      source_id.length === 0 ||
      source_id.length > 64 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(source_id)
    ) {
      throw new EngineRequestError(
        "INVALID_GRAPH",
        `attack_source_asset_ids at index ${i} has invalid id '${source_id}'`,
      );
    }
  }
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
    // Touch both exported functions to confirm the module is live.
    if (typeof health_check_json !== "function") {
      throw new Error("health_check_json export is not a function");
    }
    if (typeof simulate_graph_json !== "function") {
      throw new Error("simulate_graph_json export is not a function");
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
// Graph response validation
// ---------------------------------------------------------------------------

/** Validate that a graph simulation response body conforms to contract v1.0. */
export function validateGraphResponse(
  body: unknown,
  request: GraphSimulationRequest,
): GraphSimulationResponse {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "graph response is not a JSON object",
    );
  }

  const response = body as GraphSimulationResponse;

  if (
    typeof response.contract_version !== "string" ||
    response.contract_version !== request.contract_version
  ) {
    throw new EngineResponseError(
      "UNSUPPORTED_CONTRACT_VERSION",
      `response contract version '${response.contract_version}' does not match request`,
    );
  }

  if (response.request_id !== request.request_id) {
    throw new EngineResponseError(
      "INVALID_REQUEST_ID",
      `response request_id '${response.request_id}' does not match request '${request.request_id}'`,
    );
  }

  if (response.scenario_id !== request.scenario_id) {
    throw new EngineResponseError(
      "INVALID_SCENARIO_ID",
      `response scenario_id '${response.scenario_id}' does not match request '${request.scenario_id}'`,
    );
  }

  // Validate network reachability
  const reachability = response.network_reachability;
  if (!reachability || typeof reachability !== "object") {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "network_reachability is missing or not an object",
    );
  }

  const reachable_ids = reachability.reachable_asset_ids;
  const unreachable_ids = reachability.unreachable_asset_ids;
  const witnesses = reachability.witnesses;

  if (!Array.isArray(reachable_ids) || !reachable_ids.every((id) => typeof id === "string")) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "reachable_asset_ids must be an array of strings",
    );
  }
  if (!Array.isArray(unreachable_ids) || !unreachable_ids.every((id) => typeof id === "string")) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "unreachable_asset_ids must be an array of strings",
    );
  }
  if (!Array.isArray(witnesses) || !witnesses.every((w) => typeof w === "object")) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "witnesses must be an array of objects",
    );
  }

  // Reachable IDs sorted and unique
  const reachableSorted = [...reachable_ids].sort();
  const reachableUnique = [...new Set(reachable_ids)];
  if (reachable_ids.join("\n") !== reachableSorted.join("\n") || reachable_ids.length !== reachableUnique.length) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "reachable_asset_ids must be sorted and unique",
    );
  }

  // Unreachable IDs sorted and unique
  const unreachableSorted = [...unreachable_ids].sort();
  const unreachableUnique = [...new Set(unreachable_ids)];
  if (unreachable_ids.join("\n") !== unreachableSorted.join("\n") || unreachable_ids.length !== unreachableUnique.length) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "unreachable_asset_ids must be sorted and unique",
    );
  }

  // Reachable and unreachable must be disjoint
  const unreachableSet = new Set(unreachable_ids);
  for (const id of reachable_ids) {
    if (unreachableSet.has(id)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `asset '${id}' is both reachable and unreachable`,
      );
    }
  }

  // Witnesses sorted by target_asset — validate each witness first before
  // extracting target_asset, so null/array/non-object entries throw
  // EngineResponseError instead of TypeError.
  const witnessTargets: string[] = [];
  for (const w of witnesses) {
    if (
      w === null ||
      typeof w !== "object" ||
      Array.isArray(w) ||
      typeof w.target_asset !== "string" ||
      typeof w.source_asset !== "string" ||
      !Array.isArray(w.asset_path) ||
      !w.asset_path.every((id) => typeof id === "string") ||
      !Array.isArray(w.edge_path) ||
      !w.edge_path.every((id) => typeof id === "string")
    ) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `witness has invalid fields`,
      );
    }
    witnessTargets.push(w.target_asset);
  }
  const witnessesSorted = [...witnessTargets].sort();
  if (
    witnessTargets.join("\n") !== witnessesSorted.join("\n")
  ) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "witnesses must be sorted by target_asset",
    );
  }

  // Exactly one witness per reachable target, unique targets, all targets in reachable
  const witnessTargetSet = new Set(witnessTargets);
  if (witnessTargets.length !== witnessTargetSet.size) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "witness targets must be unique",
    );
  }
  if (witnessTargets.length !== reachable_ids.length) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "number of witnesses must equal number of reachable assets",
    );
  }
  const reachableSet = new Set(reachable_ids);
  const attackSourceSet = new Set(request.attack_source_asset_ids);
  const edgeById = new Map(request.network_edges.map((e) => [e.id, e]));
  for (const t of witnessTargets) {
    if (!reachableSet.has(t)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `witness target '${t}' is not in reachable_asset_ids`,
      );
    }
  }
  for (const id of reachable_ids) {
    if (!witnessTargetSet.has(id)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `reachable asset '${id}' has no witness`,
      );
    }
  }
  for (const w of witnesses) {
    if (
      w === null ||
      typeof w !== "object" ||
      Array.isArray(w) ||
      typeof w.target_asset !== "string" ||
      typeof w.source_asset !== "string" ||
      !Array.isArray(w.asset_path) ||
      !w.asset_path.every((id) => typeof id === "string") ||
      !Array.isArray(w.edge_path) ||
      !w.edge_path.every((id) => typeof id === "string")
    ) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `witness has invalid fields`,
      );
    }
    // Asset path must begin at source and end at target
    if (w.asset_path.length === 0 || w.asset_path[0] !== w.source_asset) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `witness asset_path must start with source_asset '${w.source_asset}'`,
      );
    }
    if (w.asset_path[w.asset_path.length - 1] !== w.target_asset) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `witness asset_path must end with target_asset '${w.target_asset}'`,
      );
    }
    // edge_path.length must equal asset_path.length - 1
    if (w.edge_path.length !== w.asset_path.length - 1) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `witness edge_path length must equal asset_path.length - 1`,
      );
    }
    // All asset path IDs must exist in request
    const assetIds = new Set(request.assets.map((a) => a.id));
    for (const id of w.asset_path) {
      if (!assetIds.has(id)) {
        throw new EngineResponseError(
          "INVALID_RESPONSE_SHAPE",
          `asset_path contains unknown asset '${id}'`,
        );
      }
    }
    // All edge path IDs must exist in request
    const edgeIds = new Set(request.network_edges.map((e) => e.id));
    for (const id of w.edge_path) {
      if (!edgeIds.has(id)) {
        throw new EngineResponseError(
          "INVALID_RESPONSE_SHAPE",
          `edge_path contains unknown edge '${id}'`,
        );
      }
    }
    // Witness target must be reachable
    if (!reachableSet.has(w.target_asset)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `witness target '${w.target_asset}' is not reachable`,
      );
    }
    // Witness source must be an attack source
    if (!attackSourceSet.has(w.source_asset)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `witness source '${w.source_asset}' is not in attack_source_asset_ids`,
      );
    }
    // Every edge in path must exist, be enabled, and connect consecutive assets
    for (let i = 0; i < w.edge_path.length; i++) {
      const edgeId = w.edge_path[i];
      const edge = edgeById.get(edgeId);
      if (!edge) {
        throw new EngineResponseError(
          "INVALID_RESPONSE_SHAPE",
          `edge '${edgeId}' in witness path does not exist`,
        );
      }
      if (!edge.enabled) {
        throw new EngineResponseError(
          "INVALID_RESPONSE_SHAPE",
          `edge '${edgeId}' in witness path is not enabled`,
        );
      }
      if (edge.source_asset_id !== w.asset_path[i]) {
        throw new EngineResponseError(
          "INVALID_RESPONSE_SHAPE",
          `edge '${edgeId}' source '${edge.source_asset_id}' does not match asset_path[${i}] '${w.asset_path[i]}'`,
        );
      }
      if (edge.target_asset_id !== w.asset_path[i + 1]) {
        throw new EngineResponseError(
          "INVALID_RESPONSE_SHAPE",
          `edge '${edgeId}' target '${edge.target_asset_id}' does not match asset_path[${i + 1}] '${w.asset_path[i + 1]}'`,
        );
      }
    }
  }

  // Validate service impact
  const impact = response.service_impact;
  if (!impact || typeof impact !== "object") {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "service_impact is missing or not an object",
    );
  }

  const assetIds = new Set(request.assets.map((a) => a.id));

  const initial_ids = impact.initially_unavailable_asset_ids;
  const impacted_ids = impact.impacted_dependent_asset_ids;
  const unavailable_ids = impact.unavailable_asset_ids;

  if (!Array.isArray(initial_ids) || !initial_ids.every((id) => typeof id === "string")) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "initially_unavailable_asset_ids must be an array of strings",
    );
  }
  if (!Array.isArray(impacted_ids) || !impacted_ids.every((id) => typeof id === "string")) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "impacted_dependent_asset_ids must be an array of strings",
    );
  }
  if (!Array.isArray(unavailable_ids) || !unavailable_ids.every((id) => typeof id === "string")) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "unavailable_asset_ids must be an array of strings",
    );
  }

  // Initially unavailable IDs sorted and unique
  const initialSorted = [...initial_ids].sort();
  const initialUnique = [...new Set(initial_ids)];
  if (initial_ids.join("\n") !== initialSorted.join("\n") || initial_ids.length !== initialUnique.length) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "initially_unavailable_asset_ids must be sorted and unique",
    );
  }

  // Impacted IDs sorted and unique
  const impactedSorted = [...impacted_ids].sort();
  const impactedUnique = [...new Set(impacted_ids)];
  if (impacted_ids.join("\n") !== impactedSorted.join("\n") || impacted_ids.length !== impactedUnique.length) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "impacted_dependent_asset_ids must be sorted and unique",
    );
  }

  // Unavailable IDs sorted and unique
  const unavailableSorted = [...unavailable_ids].sort();
  const unavailableUnique = [...new Set(unavailable_ids)];
  if (unavailable_ids.join("\n") !== unavailableSorted.join("\n") || unavailable_ids.length !== unavailableUnique.length) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "unavailable_asset_ids must be sorted and unique",
    );
  }

  // All IDs must refer to requested assets
  for (const id of initial_ids) {
    if (!assetIds.has(id)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `initially_unavailable_asset_ids contains unknown asset '${id}'`,
      );
    }
  }
  for (const id of impacted_ids) {
    if (!assetIds.has(id)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `impacted_dependent_asset_ids contains unknown asset '${id}'`,
      );
    }
  }
  for (const id of unavailable_ids) {
    if (!assetIds.has(id)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `unavailable_asset_ids contains unknown asset '${id}'`,
      );
    }
  }

  // Initially unavailable must agree with input availability
  const assetAvailability = new Map(request.assets.map((a) => [a.id, a.availability]));
  for (const id of initial_ids) {
    if (assetAvailability.get(id) !== "unavailable") {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `initially_unavailable_asset_ids contains available asset '${id}'`,
      );
    }
  }
  // Every unavailable asset in the request must appear in initially_unavailable_asset_ids
  for (const a of request.assets) {
    if (a.availability === "unavailable" && !initial_ids.includes(a.id)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `initially_unavailable_asset_ids is missing unavailable asset '${a.id}'`,
      );
    }
  }

  // Impacted must exclude initially unavailable
  const initialSet = new Set(initial_ids);
  for (const id of impacted_ids) {
    if (initialSet.has(id)) {
      throw new EngineResponseError(
        "INVALID_RESPONSE_SHAPE",
        `impacted_dependent_asset_ids contains initially unavailable asset '${id}'`,
      );
    }
  }

  // unavailable_asset_ids must equal sorted union of initial + impacted
  const expectedUnavailable = [...new Set([...initial_ids, ...impacted_ids])].sort();
  if (unavailable_ids.join("\n") !== expectedUnavailable.join("\n")) {
    throw new EngineResponseError(
      "INVALID_RESPONSE_SHAPE",
      "unavailable_asset_ids does not equal sorted union of initial and impacted",
    );
  }

  return response;
}

// ---------------------------------------------------------------------------
// Graph simulation execution
// ---------------------------------------------------------------------------

/**
 * Submit a graph simulation request to the Rust/WASM engine.
 *
 * Serializes the request to JSON, invokes simulate_graph_json, parses and
 * validates the response, and returns a fully typed GraphSimulationResponse.
 * Throws EngineRequestError for invalid input or engine errors, and
 * EngineResponseError for malformed or inconsistent responses.
 */
export function simulateGraph(
  request: GraphSimulationRequest,
): GraphSimulationResponse {
  if (!initialized) {
    throw new WasmInitializationError(
      "WASM module not initialized. Call initialize() before simulateGraph().",
      initError ?? undefined,
    );
  }

  validateGraphRequest(request);

  let requestJson: string;
  try {
    requestJson = JSON.stringify(request);
  } catch (error) {
    throw new EngineRequestError(
      "REQUEST_SERIALIZATION_FAILED",
      `failed to serialize request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  let responseJson: string;
  try {
    responseJson = simulate_graph_json(requestJson);
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

  return validateGraphResponse(responseBody, request);
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

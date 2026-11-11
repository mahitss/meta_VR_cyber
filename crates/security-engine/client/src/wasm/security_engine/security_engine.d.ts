/* tslint:disable */
/* eslint-disable */

/**
 * Raw JSON health request handler exported to JavaScript.
 *
 * Accepts a JSON string, validates it strictly, and returns a JSON string.
 * Invalid input produces an error JSON object, never a Rust panic.
 */
export function health_check_json(input: string): string;

/**
 * Raw JSON graph simulation request handler exported to JavaScript.
 *
 * Accepts raw JSON, runs the strict graph request validation pipeline,
 * deserializes only after successful validation, invokes the typed graph
 * simulation, and returns the graph response as JSON. Invalid input returns
 * a structured error JSON object — never a Rust panic.
 */
export function simulate_graph_json(input: string): string;

/* tslint:disable */
/* eslint-disable */

/**
 * Raw JSON health request handler exported to JavaScript.
 *
 * Accepts a JSON string, validates it strictly, and returns a JSON string.
 * Invalid input produces an error JSON object, never a Rust panic.
 */
export function health_check_json(input: string): string;

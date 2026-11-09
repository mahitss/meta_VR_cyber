# ADR-002: Rust/WASM Runtime Boundary

## Status

Locked

## Decision

Use Rust compiled to WebAssembly (wasm32-unknown-unknown) via wasm-bindgen/wasm-pack for the security simulation engine, with a versioned JSON contract between TypeScript and Rust.

## Context

The security engine needs deterministic graph traversal, reachability calculation, and service dependency propagation. Rust provides strong type safety, zero-cost abstractions, and deterministic execution. WebAssembly allows running Rust in the browser.

## Contract Design

- All data crosses the boundary via JSON serialization (serde_json).
- Contract version 1.0 is the initial version.
- Rust performs authoritative validation; TypeScript must not assume Rust accepts arbitrary JSON.
- Errors return explicit JSON `{ code, message }` objects, never panics.

## Alternatives Considered

- **TypeScript-only engine:** Would work but lacks the determinism and performance guarantees of Rust for graph algorithms.
- **Rust compiled to native + WebSocket backend:** Adds infrastructure complexity not justified for single-user MVP.

## Consequences

- Positive: Deterministic simulation, type-safe boundary, testable pure functions.
- Negative: WASM/JS serialization overhead; requires wasm-pack build step.

## References

- wasm-bindgen v0.2.130
- wasm-pack v0.15.1

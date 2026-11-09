# ADR-005: Authoritative Validation

## Status

Proposed

## Decision

The Rust engine performs authoritative validation of all inputs. The TypeScript adapter must not assume Rust accepts arbitrary JSON.

## Context

AC-001 requires invalid scenarios to produce clear errors. AC-005 requires unsupported findings to not silently appear as verified facts. Validation at the Rust boundary ensures correctness regardless of client implementation.

## Implementation Rules

- All JSON requests are strictly deserialized with serde.
- Contract version is checked before processing.
- Request IDs are validated (non-empty, ASCII, max 256 chars).
- Malformed JSON returns `MALFORMED_JSON` error.
- Unsupported contract version returns `UNSUPPORTED_CONTRACT_VERSION`.
- Invalid request ID returns `INVALID_REQUEST_ID`.
- All errors return JSON `{ code, message }`, never panic.

## Consequences

- Positive: Correctness guaranteed at the engine boundary, defense in depth.
- Negative: TypeScript must duplicate some validation for early user feedback.

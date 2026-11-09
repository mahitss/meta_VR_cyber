# ADR-004: Determinism

## Status

Proposed

## Decision

The Rust simulation engine must be a pure function of input → output. Identical inputs produce identical outputs.

## Context

AC-003 requires deterministic reachability analysis. AC-007 requires reproducible comparison. Non-determinism would undermine trust in the simulation results.

## Implementation Rules

- No `std::time::SystemTime` or `Instant` in calculation logic.
- No random number generation (`rand`, `fastrand`, etc.).
- No hash-map iteration order dependence (use `BTreeMap` or sort before iterating).
- All WASM inputs are explicitly versioned and validated.

## Consequences

- Positive: Reproducible results, testable, auditable.
- Negative: Cannot use wall-clock timestamps or random sampling in calculations.

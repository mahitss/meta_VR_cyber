# NetVigil XR — Testing Strategy

## Rust (security-engine)

- Graph unit tests (models, validation)
- Scenario validation tests
- Reachability tests
- Isolation tests
- Dependency propagation tests
- Branch independence tests (Plan A vs Plan B)
- Determinism tests
- Malformed input tests

**M002 status:** 18 tests passing (13 unit + 5 integration).

## TypeScript (client)

- WASM adapter tests
- Schema validation tests
- Application state tests
- UI interaction tests
- Persistence tests

## Integration

- Rust/WASM execution in browser
- Scenario loading
- Plan A versus Plan B
- Error handling
- Full user workflow

## XR

- IWER hand-input testing
- Selection and manipulation
- Seated interaction
- Field-of-view usability
- Quest performance (when hardware available)

## CI

GitHub Actions workflow (`.github/workflows/ci.yml`) runs:
- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo build --workspace --target wasm32-unknown-unknown`
- `pnpm run typecheck`
- `pnpm run build`

**Note:** Browser-based verification cannot be executed in CI without a headless WebXR runtime. The M002 smoke test is verified locally in a browser.

## Test Evidence Principle

No test result may be reported as PASS without actual execution evidence.

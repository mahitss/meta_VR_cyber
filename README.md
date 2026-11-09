# NetVigil XR — Incident Decision Workspace

**Project:** NetVigil XR  
**Competition:** Meta VR Start Developer Competition 2026  
**Proposed track:** Productivity  
**Proposed platform:** Meta Quest / WebXR  
**Status:** M002 — Repository Foundation + Technical Spike (implementation authorized)

## Product

NetVigil XR is a spatial cybersecurity incident-response decision workspace.

It enables cybersecurity professionals to investigate a simulated security incident, inspect network and service dependencies, construct alternative containment strategies, and compare the consequences of those decisions in an interactive spatial environment.

The MVP demonstrates one complete incident investigation and decision-comparison workflow:

1. Launch the immersive workspace.
2. Load the Asterion Financial incident scenario.
3. Understand the baseline infrastructure (assets, network relationships, service dependencies).
4. Investigate a compromised asset and inspect findings/evidence.
5. Create two independent response plans (Plan A and Plan B).
6. Apply modeled containment actions to each plan.
7. The Rust simulation engine calculates deterministic consequences for each plan.
8. Compare blocked attack paths, remaining reachable paths, affected assets, unavailable services, and residual exposure.
9. Review and record an investigation summary.

## Architecture

| Layer | Technology | Responsibility |
|-------|-----------|----------------|
| XR client | TypeScript + IWSDK + Three.js + WebXR | Spatial rendering, hand interactions, UI, session orchestration |
| Simulation engine | Rust + wasm-bindgen + wasm-pack | Deterministic graph traversal, reachability, dependency impact |
| Persistence | IndexedDB (local-first) | Scenario data, saved sessions, plan history |
| Backend | None (MVP) | Deferred until collaboration/remote persistence is justified |

Key architectural decisions (see `docs/ADR/`):

- **ADR-001**: IWSDK + TypeScript XR client (locked)
- **ADR-002**: Rust/WASM security engine (locked)
- **ADR-003**: Go backend deferred until justified (locked)
- **ADR-004**: No blockchain (locked)
- **ADR-005**: Local-first MVP (proposed)
- **ADR-006**: Separate connectivity and dependency graphs (proposed)
- **ADR-007**: Independent response-plan branches (proposed)
- **ADR-008**: Seated VR environment (proposed)
- **ADR-009**: One built-in fictional scenario (proposed)
- **ADR-010**: No production network integrations (proposed)

## Repository Structure

```
meta_VR_cyber/
├── Cargo.toml                  # Rust workspace manifest
├── Cargo.lock                  # Rust dependency lockfile
├── .cargo/config.toml          # Cargo linker configuration (Windows MinGW)
├── contracts/                  # Versioned JSON contract schemas
│   ├── engine-health-request.v1.schema.json
│   └── engine-health-response.v1.schema.json
├── crates/
│   └── security-engine/        # Rust WASM simulation engine
│       ├── Cargo.toml
│       ├── Cargo.lock
│       ├── src/
│       │   ├── lib.rs          # WASM entry point + health check
│       │   ├── models.rs       # Request/response data models
│       │   └── validation.rs   # Strict request validation
│       └── tests/
│           └── health_check_test.rs
├── client/                     # IWSDK XR client (TypeScript + Vite)
│   ├── package.json
│   ├── pnpm-lock.yaml
│   ├── iwsdk.config.json       # IWSDK project authority
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   ├── src/
│   │   ├── index.ts            # World.create() + system registration
│   │   ├── assets.ts           # Asset manifest (shared runtime/editor)
│   │   ├── components.ts       # ECS component declarations
│   │   ├── simulation/         # WASM adapter + smoke test
│   │   │   ├── wasm-adapter.ts
│   │   │   └── wasm-health-smoke.ts
│   │   └── wasm/security_engine/  # Generated Rust/WASM bindings
│   └── public/
│       └── scenes/
│           └── main.iwsdk.scene.json
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI
└── docs/
    ├── PRD.md
    ├── ARCHITECTURE.md
    ├── SECURITY.md
    ├── TESTING.md
    ├── COMPETITION_ELIGIBILITY.md
    └── ADR/
```

## Getting Started

### Prerequisites

- Node.js v24 (required by IWSDK @1.0.1 engines field)
- pnpm v12+
- Rust stable toolchain with `wasm32-unknown-unknown` target
- On Windows: MinGW-w64 at `C:\mingw64` (required for the GNU Rust toolchain linker)

### Install

```bash
# Client dependencies
cd client
pnpm install

# Rust dependencies are resolved by cargo automatically
cd ..
cargo build --workspace
```

### Run TypeScript typecheck

```bash
cd client
pnpm run typecheck
```

### Build frontend for production

```bash
cd client
pnpm run build
```

### Run Rust tests

```bash
cargo test --workspace
```

### Build Rust to WebAssembly

```bash
wasm-pack build crates/security-engine \
  --target bundler \
  --dev \
  --out-dir client/src/wasm/security_engine \
  --out-name security_engine
```

### Start the XR development server

```bash
cd client
pnpm run dev
```

This launches the IWSDK-managed development server with the IWER (IWSDK WebXR Emulator).

## Technology Versions (pinned)

| Dependency | Version |
|------------|---------|
| Node.js | 24.x |
| pnpm | 12.18.0 |
| @iwsdk/core | 1.0.1 |
| @iwsdk/cli | 1.0.1 |
| @iwsdk/vite-plugin-dev | 1.0.1 |
| @iwsdk/reference | 1.0.1 |
| three (super-three) | 0.181.0 |
| TypeScript | 5.9.3 |
| Vite | 7.3.7 |
| Rust | 1.99.1 |
| wasm-bindgen | 0.2.130 |
| wasm-pack | 0.15.1 |
| serde | 1 |
| serde_json | 1 |

## Security

- The MVP is local-first single-user. No backend, no remote transmission of investigation content.
- No production credentials are embedded in the application.
- The demonstration scenario uses fictional infrastructure data only.
- The Rust engine performs authoritative validation of all JSON inputs.
- All errors produce explicit JSON error objects, never panics.

## Competition Eligibility

Competition entry classification (New Experience vs. existing project) is unresolved. See `docs/COMPETITION_ELIGIBILITY.md`.

## License

MIT

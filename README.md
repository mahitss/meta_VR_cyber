# NetVigil XR — Incident Decision Workspace

**Project:** NetVigil XR  
**Competition:** Meta VR Start Developer Competition 2026  
**Proposed track:** Productivity  
**Proposed platform:** Meta Quest / WebXR  
**Status:** M002.1 — Engineering Corrections (CI portability + browser WASM verification)

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
├── contracts/                  # Versioned JSON contract schemas
│   ├── engine-health-request.v1.schema.json
│   └── engine-health-response.v1.schema.json
├── crates/
│   └── security-engine/        # Rust WASM simulation engine
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs          # WASM entry point + health check
│       │   ├── models.rs       # Request/response data models
│       │   └── validation.rs   # Strict request validation
│       └── tests/
│           └── health_check_test.rs
├── client/                     # IWSDK XR client (TypeScript + Vite)
│   ├── package.json            # Includes packageManager: pnpm@12.18.0
│   ├── pnpm-lock.yaml          # Pinned dependency lockfile
│   ├── iwsdk.config.json       # IWSDK project authority
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   ├── src/
│   │   ├── index.ts            # World.create() + system registration (+ dev WASM diagnostic)
│   │   ├── assets.ts           # Asset manifest (shared runtime/editor)
│   │   ├── components.ts       # ECS component declarations
│   │   ├── panel.ts
│   │   ├── robot-component.ts
│   │   ├── robot.ts
│   │   ├── vite-env.d.ts
│   │   ├── simulation/         # WASM adapter + smoke test + dev diagnostic
│   │   │   ├── wasm-adapter.ts
│   │   │   ├── wasm-health-smoke.ts
│   │   │   └── wasm-dev-diagnostic.ts   # dev-only, tree-shaken in production
│   │   └── wasm/security_engine/  # Generated Rust/WASM bindings
│   └── public/
│       └── scenes/
│           └── main.iwsdk.scene.json
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI (rust + frontend jobs)
├── .gitignore                  # Excludes .cargo/config.toml (local machine paths)
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
- pnpm v12.18.0 (exact version declared in `client/package.json` `packageManager`)
- Rust stable toolchain with `wasm32-unknown-unknown` target
- wasm-pack (for building the Rust crate to WebAssembly)

### Platform assumptions

CI runs on `windows-latest` using the Rust MSVC toolchain (installed via
`dtolnay/rust-toolchain`), which provides `link.exe` for native linking. No
MinGW-w64 or `C:/mingw64` dependency is required in CI.

Local development on Windows with the GNU Rust toolchain (`x86_64-pc-windows-gnu`)
may require a MinGW linker workaround if the system MinGW runtime is incomplete.
This is a local machine configuration only — `.cargo/config.toml` is git-ignored
and must not be committed. See the "Windows MinGW linker workaround" section below.

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
  --out-dir ../../client/src/wasm/security_engine \
  --out-name security_engine
```

### Start the XR development server

```bash
cd client
pnpm run dev
```

This launches the IWSDK-managed development server with the IWER (IWSDK WebXR Emulator).
In development mode, a WASM diagnostic runs automatically and logs results to the
browser console (see `client/src/simulation/wasm-dev-diagnostic.ts`). It is
tree-shaken out of production builds.

### Windows MinGW linker workaround (local development only)

If you are developing on Windows with the GNU Rust toolchain and the system
MinGW-w64 runtime is incomplete (missing `crtbegin.o`, `crtend.o`, `dllcrt2.o`),
create a local `.cargo/config.toml` (not committed) pointing `LIBRARY_PATH` at
the Rust toolchain's bundled `self-contained` runtime directory and your MinGW
GCC library directory. This file is git-ignored and must never contain personal
machine paths.

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

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs two jobs on `windows-latest`:

1. **rust** — `cargo fmt --all -- --check`, `cargo test --workspace`
   (native Rust unit + integration tests), `cargo build --workspace --target
   wasm32-unknown-unknown` (WASM compilation)

2. **frontend** — pnpm/action-setup (pnpm@12.18.0) → setup-node with pnpm
   caching → `pnpm install --frozen-lockfile` → `pnpm run typecheck` →
   `pnpm run build`

### Test distinction

- **Native Rust tests** (`cargo test --workspace`): Run on the host machine.
  Exercise the pure Rust logic (`health_check`, validation) without wasm-bindgen.
  18 tests pass locally.

- **Browser WASM tests** (`wasm-dev-diagnostic.ts`): Development-only diagnostic
  that runs in the browser, importing the generated wasm-bindgen module and
  invoking the actual `health_check_json` binding. Tests positive (valid request
  through adapter) and negative (unsupported version, empty request ID, malformed
  JSON through raw binding) cases. Not executed in CI — requires a browser/XR
  runtime. Tree-shaken out of production builds.

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

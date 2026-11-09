# NetVigil XR — Architecture

## System Overview

NetVigil XR is a local-first, single-user XR application with a Rust/WASM simulation engine and a TypeScript/IWSDK client.

### Three-Tier Architecture

| Tier | Technology | Responsibility |
|------|-----------|----------------|
| Presentation | IWSDK + Three.js + WebXR | Spatial rendering, hand interactions, UI panels |
| Business Logic | Rust/WASM (security-engine) | Graph validation, reachability, dependency propagation |
| Data | IndexedDB (browser) | Scenario data, saved sessions, plan history |

## Client Architecture

The IWSDK project follows the ECS (Entity-Component-System) pattern:

- `src/index.ts` — `World.create()` + system registration
- `src/assets.ts` — `defineAssets()` — shared runtime/editor catalog
- `src/components.ts` — `defineComponents()` — shared runtime/editor catalog
- `public/scenes/main.iwsdk.scene.json` — scene composition only

**Key IWSDK rules (from AGENTS.md):**
- Import Three.js from `@iwsdk/core`, never from `three`.
- `iwsdk.config.json` is the project authority, not `vite.config.ts`.
- `src/assets.ts` is evaluated in two JS realms — must be deterministic and side-effect free.
- Components must be declared in a system-free module and exported from `src/components.ts`.
- No barrel `index.ts` files.

## Simulation Engine Architecture

The `security-engine` Rust crate exposes a versioned JSON contract via wasm-bindgen.

**Contract v1.0:**
- Request: `{ "contract_version": "1.0", "request_id": "<string>" }`
- Response: `{ "contract_version": "1.0", "request_id": "<string>", "engine": "security-engine", "status": "ok" }`
- Error: `{ "code": "<string>", "message": "<string>" }`

**Modules:**
- `models.rs` — Request/response data models (serde)
- `validation.rs` — Strict request validation
- `lib.rs` — WASM entry point + health check handler

**Determinism guarantees:**
- Pure functions of input → output
- No `System::time`, no random number generation
- No hash-map iteration order dependence

## Two-Graph Model

| Graph | Represents | Used For |
|-------|-----------|----------|
| Network connectivity | Explicitly modeled communication/reachability | Reachability, modeled lateral movement, path removal |
| Service dependency | Application/infrastructure dependencies | Service availability, cascading impact, business continuity |

**Critical:** A service dependency is not evidence of network reachability. Network reachability is not proof of successful exploitation.

## Response Plans

Each plan operates on an independent cloned graph snapshot from the same immutable baseline. Plan A never mutates Plan B or the baseline.

## WASM/JS Boundary

Defined in `client/src/simulation/wasm-adapter.ts`:
- `initialize()` — load and verify WASM module
- `healthCheck(request)` — send validated request, parse response
- Strict JSON serialization/deserialization
- Typed error classes for each failure mode

## Persistence

Local-first using IndexedDB. No server database for MVP. Backend (Go) deferred until collaboration or remote persistence is justified.

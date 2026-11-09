# NetVigil XR — Security Model

## Threat Model

The MVP is a local single-user application. Threats include:

1. **Malformed scenario input** — Invalid JSON or schema violations in loaded scenarios.
2. **Malformed serialized simulation requests** — Invalid JSON sent to the Rust engine.
3. **Invalid graph relationships** — Duplicate asset IDs, missing relationship references.
4. **Dependency vulnerabilities** — Vulnerable npm or crates.io dependencies.
5. **Unsafe rendering of user-provided text** — XSS via scenario descriptions or evidence text.
6. **Accidental storage of sensitive infrastructure information** — Local IndexedDB storage of scenario data.

## Controls

| Control | Implementation |
|---------|---------------|
| Strict schema validation | Rust engine validates all JSON inputs authoritatively |
| Safe text rendering | No dynamic code evaluation; text rendered as plain content |
| No dynamic code evaluation | No `eval()`, no `Function()`, no WASM module compilation from strings |
| Dependency pinning | Lockfiles (`package-lock.json`/pnpm-lock.yaml, `Cargo.lock`) |
| No secrets embedded | No credentials, API keys, or secrets in client code |
| No live production data | Demonstration scenario uses fictional infrastructure |
| No remote transmission | Investigation content stays in the browser |
| Local-first persistence | IndexedDB only; no server database |
| Explicit error handling | All errors return JSON `{ code, message }`, never panics |
| Separate graphs | Network connectivity ≠ service dependency; neither implies the other |
| Independent plans | Plan A cannot mutate Plan B or the baseline |

## Authentication / Authorization

No authentication or authorization in MVP (single-user local application). Future versions may add enterprise identity integration.

## Audit Logging

The `AuditEvent` entity is defined in the data model (PRD Section 12) for recording investigation decisions. Implementation deferred to M007.

## Dependency Security

- npm dependencies pinned via pnpm-lock.yaml
- Rust dependencies pinned via Cargo.lock
- No prerelease dependencies adopted silently (IWSDK 1.1.0-rc.* not used)

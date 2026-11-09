# ADR-003: Local-First MVP

## Status

Proposed

## Decision

Use IndexedDB for local persistence. No backend server for MVP.

## Context

The product is a single-user incident investigation workspace. All data (scenarios, saved sessions, plan history) can be stored locally in the browser's IndexedDB.

## Alternatives Considered

- **Backend + database:** Adds infrastructure, authentication, and operational complexity not justified for MVP.
- **localStorage:** Limited storage capacity (5MB) and no structured querying.
- **IndexedDB:** Larger storage, structured data, available in all modern browsers including Quest's WebXR.

## Consequences

- Positive: No server costs, works offline, no authentication needed for MVP.
- Negative: No multi-user collaboration, no remote persistence, data limited to single device.

## References

- Data model: PRD Section 12 (Scenario, Asset, NetworkEdge, Service, Finding, Evidence, ResponsePlan, SimulationResult, AuditEvent)

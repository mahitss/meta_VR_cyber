# ADR-001: XR Client Stack

## Status

Locked

## Decision

Use TypeScript + Meta IWSDK + Three.js + WebXR for the XR client.

## Context

The product requires an immersive VR environment with hands-first interaction on Meta Quest / WebXR. The Meta IWSDK provides the official framework for building immersive web experiences with hand tracking, grabbing, and spatial UI.

## Alternatives Considered

- **Three.js + WebXR directly:** Would require building hand tracking, grabbing, and spatial UI from scratch. More work, less integration with Meta's ecosystem.
- **A-Frame:** Simpler but less control over ECS architecture and hand interaction details.
- **Unity/Unreal:** Not web-based, doesn't match the WebXR platform goal.

## Consequences

- Positive: Official Meta SDK, hand tracking, grabbing, spatial UI, IWER emulator for development.
- Negative: IWSDK availability on npm must be verified; stable version is 1.0.1 (prerelease 1.1.0-rc.* not adopted).

## References

- IWSDK packages: `@iwsdk/core@1.0.1`, `@iwsdk/cli@1.0.1`, `@iwsdk/vite-plugin-dev@1.0.1`

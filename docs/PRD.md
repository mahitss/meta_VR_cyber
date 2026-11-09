# NetVigil XR — Product Requirements Document (PRD v0.1)

**Status:** Draft — awaiting product-owner approval  
**Product:** NetVigil XR — Incident Decision Workspace  
**Competition:** Meta VR Start Developer Competition 2026

## Executive Summary

NetVigil XR is a spatial cybersecurity incident-response decision workspace. It enables cybersecurity professionals to investigate a simulated security incident, inspect network and service dependencies, construct alternative containment strategies, and compare the consequences of those decisions in an interactive spatial environment.

## Product Vision

Build a spatial workspace for investigating cybersecurity incidents and rehearsing containment decisions.

## Target Users

**Primary:** Incident Response Lead — investigates security incidents, coordinates response strategies, evaluates containment options.

**Secondary:** Security Architect — reviews infrastructure dependencies, identifies critical assets, assesses network exposure.

## MVP Scope (Must Have)

1. Immersive VR environment
2. Hands-first interaction
3. Spatial network topology
4. Asset and relationship inspection
5. Evidence inspection
6. Two alternative response plans
7. Deterministic network reachability calculation
8. Deterministic service dependency calculation
9. Before-and-after comparison
10. Investigation decision history
11. Final incident summary

## Core Workflow

Launch → Select scenario → Understand baseline → Investigate → Create response plans (Plan A, Plan B) → Apply decisions → Calculate consequences → Compare → Review and record.

## Key Acceptance Criteria

- Plan A starts from the original baseline; Plan B starts from the original baseline.
- Actions in Plan A cannot mutate Plan B.
- Only explicitly modeled connectivity relationships are considered for reachability.
- Blocked relationships are excluded.
- Results are deterministic.
- Service dependencies are separate from network connectivity.
- Every finding has an identifier, severity, and evidence provenance.

## Non-Functional Requirements

- Performance: Target at least 60 FPS on Quest hardware
- Determinism: Identical inputs produce identical outputs
- Privacy: Local-first processing
- Security: No production credentials in client
- Accessibility: Seated usage and readable interface

## Explicitly Out of Scope

- Real production network isolation
- Actual endpoint remediation
- Live exploitation
- Autonomous security actions
- Blockchain and smart contracts
- Mandatory paid AI APIs
- Mandatory cloud infrastructure
- Enterprise-grade multi-tenant backend

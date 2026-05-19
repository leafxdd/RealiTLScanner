---
title: "Architecture Constraints"
readMode: required
priority: high
category: arch
keywords:
  - architecture
  - module
  - layer
  - boundary
  - dependency
  - structure
---

# Architecture Constraints

Auto-generated from project structure. Update manually as architecture evolves.

## Module Structure
- Type: multi-package (cmd/ + internal/ standard Go layout)
- Key modules:
  - cmd/realitlscanner/ — CLI entry point, subcommand routing, flag parsing
  - internal/types/ — shared types (Host, HostType, ScanResult, detector result types)
  - internal/scanner/ — TLS scanning logic (ScanTLS, host iteration, CSV escape)
  - internal/detector/ — Detector interface + 7 detector implementations + Runner
  - internal/pipeline/ — three-stage Channel orchestration (scan → detect → output)
  - internal/output/ — multi-format output (CSV, JSON, JSONL, progress reporting)
  - internal/data/ — data file management (embed + download, DataManager)
  - internal/geo/ — GeoIP lookup wrapper (thread-safe, no mutex needed)

## Layer Boundaries
- cmd/ orchestrates: parses flags → constructs pipeline config → calls pipeline.Run
- internal/pipeline connects: scanner workers → detector runner → output channel
- internal/scanner produces: ScanResult from TLS connections
- internal/detector enhances: ScanResult with CDN/GFW/redirect/hotsite detection
- internal/output consumes: ScanResult → formatted output (CSV/JSON/JSONL)
- internal/data provides: data files to detectors (embedded + downloaded)
- internal/types is leaf: no internal dependencies, imported by all other packages

## Dependency Rules
- internal/types MUST NOT depend on any other internal package (leaf node)
- internal/geo depends on: types (net.IP only)
- internal/scanner depends on: types, geo
- internal/detector depends on: types, geo
- internal/pipeline depends on: types, scanner, detector, geo
- internal/output depends on: types, scanner (CsvEscape only)
- internal/data depends on: nothing internal (standalone)
- cmd/ depends on: all internal packages (orchestrator)
- No circular dependencies allowed

## Technology Constraints
- Runtime: Go >= 1.21
- Module system: Go modules (go.mod)
- Build output: single static binary via `go build ./cmd/realitlscanner`
- Container: Docker multi-stage (golang:1.22-alpine build → alpine:latest runtime)
- External deps: geoip2-golang only (minimal dependency footprint)
- Small data files: go:embed into binary (cdn_keywords.txt, hot_websites.txt)
- Large data files: runtime download with 30s timeout (Country.mmdb, gfwlist.conf)

## Entries


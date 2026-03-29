# Web UI Design (Ops Console)

## Problem

The dashboard must support security workflow, not generic cards.

## Principles

- Scan-centric navigation: left panel index of scans.
- Decision-oriented center: overview, assets, findings, raw.
- Operational context: stage yield + geo heat map.
- Fast keyboard/filter path for triage.

## Layout

1. Top bar: system state + indexed scan count.
2. Left rail: searchable scan list.
3. Main panel tabs:
   - Overview
   - Assets
   - Findings
   - Raw JSON

## Data contracts

- `/api/scans`: summary index
- `/api/results?id=...`: full scan payload
- `/api/heat`: global geolocation aggregation

## Visual language

- Dark SOC-inspired palette.
- Monospace for artifacts, sans-serif for navigation.
- High contrast severity colors.

## Mobile behavior

- Collapse to single-column stack.
- Keep scan list first, details second.

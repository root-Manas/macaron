# Contributing Guide

## Branching

Use one branch per focused change.

Naming:
- `feat/<topic>`
- `fix/<topic>`
- `docs/<topic>`
- `chore/<topic>`

## PR checklist

- [ ] scope is focused and small
- [ ] tests pass (`go test ./...`)
- [ ] lint/vet pass (`go vet ./...`)
- [ ] user-facing behavior documented in README/docs

## Commit style

- `feat(...)`
- `fix(...)`
- `docs(...)`
- `chore(...)`

## Local workflow

```bash
go test ./...
go vet ./...
go build ./cmd/macaron
```

## Design expectations

- Prefer intent-first UX: setup -> scan -> inspect -> export.
- Keep default output concise.
- Keep deep detail queryable via status/results/dashboard.

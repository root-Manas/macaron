# Release Checklist

## Pre-release

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `go build ./cmd/macaron`
- [ ] smoke test: setup, scan, status, results, serve
- [ ] README updated for changed flags/workflows

## Tag & publish

- [ ] bump changelog/release notes
- [ ] `git tag vX.Y.Z`
- [ ] `git push origin vX.Y.Z`
- [ ] verify GitHub release artifacts (linux/darwin/windows)

## Post-release

- [ ] announce release in launch channels
- [ ] monitor CI and issue tracker for 24h
- [ ] cut patch release if critical regression appears

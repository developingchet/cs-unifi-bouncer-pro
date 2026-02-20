# Contributing to cs-unifi-bouncer-pro

Thank you for your interest in contributing! This document describes how to report bugs, suggest features, and submit code changes.

## Table of Contents

- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Documentation Improvements](#documentation-improvements)
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Areas Needing Help](#areas-needing-help)

---

## Reporting Bugs

Before opening an issue:

1. Check that you are running the **latest release**
2. Search [existing issues](https://github.com/developingchet/cs-unifi-bouncer-pro/issues) to avoid duplicates
3. Enable debug logging (`LOG_LEVEL=debug`) and reproduce the problem

A good bug report includes:

- Sanitised Docker logs (`docker logs cs-unifi-bouncer-pro 2>&1 | grep -v "API_KEY\|PASSWORD"`)
- UniFi controller version and firmware channel
- CrowdSec version (`docker exec crowdsec cscli version`)
- Firewall mode in use (`FIREWALL_MODE`)
- Exact reproduction steps
- Expected vs. actual behaviour

**Security vulnerabilities** must be reported privately. See [SECURITY.md](SECURITY.md).

---

## Suggesting Features

Open a GitHub issue with:

1. **Problem statement** — what pain point does this solve?
2. **Proposed solution** — how should it work?
3. **Alternatives considered** — what other approaches exist?
4. **Trade-offs** — what does this add in complexity or scope?

Large features benefit from early discussion before a pull request is drafted.

---

## Documentation Improvements

Documentation PRs are always welcome — from typo fixes to new deployment examples. For minor fixes, submit a PR directly. For substantial rewrites or new guides, open an issue first.

---

## Development Setup

**Requirements**

| Tool | Minimum version |
|------|----------------|
| Go | 1.24 |
| Docker | 20.10 |
| Docker Compose | v2 |

**Getting started**

```bash
# Fork and clone
git clone https://github.com/<your-fork>/cs-unifi-bouncer-pro.git
cd cs-unifi-bouncer-pro

# Download dependencies
go mod download

# Build
go build ./cmd/bouncer/

# Run unit tests (no live controller required — all dependencies mocked)
go test ./...

# Run with race detector
go test -race ./...

# Lint
golangci-lint run ./...
```

All unit tests run without a live CrowdSec instance or UniFi controller. External API calls are replaced with `httptest` servers.

---

## Code Standards

### Formatting

All Go code must be formatted with `gofmt` and pass `go vet` before submission. The CI lint job (`golangci-lint`) enforces additional rules.

```bash
gofmt -w ./...
go vet ./...
```

### Error Handling

- Wrap errors with context: `fmt.Errorf("creating firewall group: %w", err)`
- Do not use `panic` or `log.Fatal` in library code — return errors to the caller
- Typed sentinel errors (`var ErrNotFound = errors.New(...)`) are preferred over string matching

### Logging

Logging uses [zerolog](https://github.com/rs/zerolog) with structured key-value fields:

```go
log.Info().Str("ip", ip).Str("site", site).Msg("ban applied")
```

- Never log API keys, passwords, or Bearer tokens — the `RedactWriter` provides a safety net but is not a substitute for care
- Use `log.Debug()` for per-decision trace output
- Use `log.Warn()` for recoverable issues, `log.Error()` for failures

### Dependencies

The project maintains a minimal dependency list intentionally. Adding a new `go.mod` dependency requires discussion in the relevant issue before the PR is opened. Prefer stdlib where practical.

### Naming Templates

Changes to firewall naming (group, rule, policy templates) affect all existing deployments. Treat these as breaking changes and document migration steps.

---

## Testing

Every new exported function must have a test. Use table-driven patterns:

```go
func TestParseAndSanitize(t *testing.T) {
    cases := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid IPv4", "1.2.3.4", "1.2.3.4", false},
        {"valid CIDR", "10.0.0.0/8", "10.0.0.0/8", false},
        {"private", "192.168.1.1", "", true},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, err := ParseAndSanitize(tc.input)
            if (err != nil) != tc.wantErr {
                t.Fatalf("unexpected error: %v", err)
            }
            if got != tc.want {
                t.Errorf("got %q, want %q", got, tc.want)
            }
        })
    }
}
```

Use temporary directories for tests that write to disk. Clean them up with `t.TempDir()`.

**Manual testing checklist before PR:**

- [ ] `docker compose build && docker compose up -d` succeeds
- [ ] Bouncer appears in `docker exec crowdsec cscli bouncers list`
- [ ] A test decision (`cscli decisions add -i 203.0.113.42 -t ban -d 1h`) appears in logs
- [ ] Firewall group or zone policy is created/updated in the UniFi controller
- [ ] `GET /healthz` returns 200
- [ ] `GET /readyz` returns 200 (controller reachable)
- [ ] `dry_run=true` produces log output but no UniFi API calls

---

## Submitting a Pull Request

1. Fork the repository and create a feature branch: `git checkout -b feat/my-change`
2. Make your changes following the code standards above
3. Run tests and lint:
   ```bash
   go test ./...
   go test -race ./...
   golangci-lint run ./...
   ```
4. Commit with a clear message describing the **why**, not just the what
5. Open a PR against `main` with:
   - A clear title (≤ 70 characters)
   - Description of the problem and solution
   - Reference to the related issue (`Fixes #123`)
   - Testing steps reviewers can follow

**PR checklist**

- [ ] `gofmt -w ./...` applied
- [ ] `go test -race ./...` passes
- [ ] New exported functions have tests
- [ ] Documentation updated if behaviour changed
- [ ] No API keys, passwords, or sensitive data in commits

Maintainers aim to review PRs within **one week**.

---

## Areas Needing Help

- **Firewall edge cases** — unusual zone configurations, non-standard site names, older firmware compatibility
- **Multi-instance deployments** — testing with two bouncer instances sharing the same controller
- **Documentation** — deployment guides for Kubernetes, Unraid, or bare-metal setups
- **CI/CD** — additional linting rules, integration test harness against a mock UniFi API
- **Observability** — Grafana dashboard for the Prometheus metrics

---

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

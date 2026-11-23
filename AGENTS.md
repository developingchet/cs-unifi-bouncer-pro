# AGENTS.md

cs-unifi-bouncer-pro is a Go service that turns CrowdSec ban decisions into firewall objects on UniFi Network controllers. It runs as one daemon or container, talks to a CrowdSec LAPI and a UniFi controller, and keeps ban state in an embedded bbolt database.

## Layout

| Path | Contents |
|---|---|
| `cmd/bouncer/` | Cobra commands and the daemon startup, reload and shutdown wiring |
| `internal/config/` | Environment variable parsing and validation |
| `internal/lapihttp/`, `internal/decision/` | CrowdSec LAPI client and decision stream |
| `internal/controller/`, `internal/firewall/` | UniFi API client and zone or legacy firewall objects |
| `internal/banstate/`, `internal/storage/` | Claims, shards, ban history and bbolt persistence |
| `internal/bouncer/` | Batch processing, reconcile, health and status endpoints |
| `internal/testutil/` | Fake UniFi server and mock controller used by unit tests |
| `security/seccomp-unifi.json` | Seccomp profile applied by the Compose files |
| `docs/` | Setup, configuration, design, upgrading and troubleshooting guides |

`README.md` is the user-facing entry point. `CONTRIBUTING.md` covers the review process, `SECURITY.md` covers private vulnerability reporting, and `SUPPORT.md` routes usage questions.

## Setup and checks

Go 1.27.4 (from `go.mod`), Docker Engine 20.10 or newer and Docker Compose v2 are the documented toolchain. Run these from the repository root:

```bash
go mod download
go build ./cmd/bouncer/
go test ./...
go test -race ./... -count=1 -timeout=120s
go vet ./...
gofmt -l .
golangci-lint run ./...
bash scripts/validate-seccomp.sh security/seccomp-unifi.json
```

`make test`, `make race`, `make lint`, `make build`, `make docker-build` and `make docker-test` wrap the same commands. `make docker-test` builds the image and starts it under the seccomp profile with documentation addresses and placeholder keys; it makes no connection to a real controller.

`version` and `validate` need no network access. `diagnose`, `reconcile`, `ban`, `unban` and `drain` contact the configured UniFi controller, and `drain --force` removes managed firewall objects. Keep those commands out of automated checks unless the target is a disposable local lab.

Unit tests replace the LAPI and the UniFi API with `httptest` servers and the fixtures in `internal/testutil/`. They do not need credentials, a running CrowdSec instance or a controller. An end-to-end run that creates a decision and inspects the resulting firewall object is optional and belongs in a disposable local lab, never against a production controller or a real CrowdSec deployment.

## Conventions

- Format Go with `gofmt` and keep `go vet` clean. Wrap errors with `%w` and context; return errors instead of calling `panic` or `log.Fatal` in library code.
- Log through zerolog with structured fields. Never log API keys, passwords or tokens; the logger redacts known sensitive values, but sanitizing before it is still required.
- Use `t.TempDir()` for tests that write to disk. Keep external calls behind the existing mock interfaces.
- Pin GitHub Actions to commit SHAs. Keep workflow permissions at `contents: read` unless a job needs more.
- A change that alters user-visible behaviour updates `docs/UPGRADING.md` and the relevant guide. Commits describe why the change is needed.
- `SECURITY.md` is the only intake for vulnerabilities. Do not put exploit details in a public issue or PR.

## Boundaries

`.env`, API keys and the bbolt database are local state and must never be committed. Before sharing logs or configuration, remove controller addresses, keys and private network details.

The image runs as UID 65532 with a read-only root filesystem, dropped capabilities and a seccomp profile. Changes to `security/seccomp-unifi.json` need `bash scripts/validate-seccomp.sh` and `make docker-test`, because a too-strict profile can stop the container before the daemon starts.

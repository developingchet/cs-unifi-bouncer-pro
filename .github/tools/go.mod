// CI tools, kept out of the bouncer's own go.mod so they never change the
// dependency versions that ship in the binary. Dependabot keeps them current.
// Run from the repository root, for example:
//   go run -modfile=.github/tools/go.mod golang.org/x/vuln/cmd/govulncheck ./...
module github.com/developingchet/cs-unifi-bouncer-pro/.github/tools

go 1.27.1

tool golang.org/x/vuln/cmd/govulncheck

require (
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/telemetry v0.0.0-20260908163034-4bcc4b2ee518 // indirect
	golang.org/x/tools v0.50.0 // indirect
	golang.org/x/vuln v1.8.0 // indirect
)

## Summary

<!-- What does this PR do and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] CI / build change
- [ ] Documentation update

## Testing

<!-- Commands, environment and observed results. Include arch (amd64/arm64) if relevant. -->

- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `golangci-lint run ./...`
- [ ] `make docker-test` (required for image or seccomp profile changes)
- [ ] CI passes

Tests not run, and why:

<!-- List skipped checks and the reason, for example live controller integration. -->

## Compatibility

<!-- Effects on configuration defaults, authentication, stored state, firewall objects or supported versions. Write "none" when there is no user-visible change. -->

## Rollback

<!-- How to return to the previous release, including any database or firewall state that needs restoring. -->

## Checklist

- [ ] Commit messages are clear and scoped
- [ ] No secrets, tokens, or credentials in code, logs, examples or commit messages
- [ ] Security and privacy impact considered; no unsanitized sensitive values in code, logs or examples
- [ ] `docs/UPGRADING.md` and the affected docs updated if behaviour changes for users

## Related issues

<!-- Closes #, Fixes #, or N/A -->

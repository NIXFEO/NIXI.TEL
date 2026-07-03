# Contributing

Thanks for your interest in NIXI SBC!

## Building

```bash
# cmake is required (bundled Opus build)
cargo build --workspace
cargo test --workspace
```

If your cmake is 4.x, set `CMAKE_POLICY_VERSION_MINIMUM=3.5` (the vendored
libopus CMakeLists declares an older minimum).

## Ground rules

- `cargo test --workspace` must stay green; add tests with your change.
  SIP message construction is tested by re-parsing through rsip.
- No new required external services: the SBC must keep running with just
  its binary, a TOML file and the embedded SQLite store.
- Dynamic config changes go through the store + hydration path
  (`sbc-core/src/sbc/hydrate.rs`) so API writes stay instantaneous —
  never add a second source of truth.
- Security-sensitive changes (auth, TLS, ban logic) need a test that
  demonstrates the failure mode they prevent.
- Keep the API backward compatible under `/api/v1`; breaking changes go
  to a new version prefix.

## Pull requests

1. Fork, branch from `main`.
2. Make your change with tests and docs (`docs/API.md` for endpoints).
3. `cargo fmt`, `cargo clippy --workspace` (warnings tolerated, errors not).
4. Open the PR with a description of the behavior change and how you
   verified it (unit tests, SIPp scenario, real trunk/browser test).

## Reporting security issues

Please do NOT open a public issue — see [SECURITY.md](SECURITY.md).

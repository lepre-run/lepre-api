# lepre-api

Single Rust Lambda fronting `api.lepre.run`. Implements three routes:

- `GET /v1/healthz`
- `GET /v1/auth/strava/start`
- `GET /v1/auth/strava/callback`

See `plans/001-strava-join.md` for the full ADR.

## Build

```bash
cargo build
cargo test
```

Integration tests (`tests/callback.rs`) need a working Docker daemon —
`testcontainers` spins up a real MongoDB for them.

## Lint

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

## Deploy

CI handles `cargo lambda build --release --arm64` and
`aws lambda update-function-code` on push to `main`. See
`.github/workflows/ci.yml`.

The first-time bootstrap zip — uploaded to
`s3://francescobarbera-releases/lepre/bootstrap.zip` once before the
CloudFormation stack is first created — comes from
`scripts/build-placeholder.sh`.

## Module layout

```
src/
  main.rs        # lambda_http::run entrypoint
  lib.rs         # re-exports modules for the integration test
  handler.rs     # route match + per-route handlers (§2)
  config.rs      # SSM-loaded Config struct, OnceCell pattern (§5)
  crypto.rs      # AES-256-GCM with AAD-bound to athlete + kind + version (§4)
  db.rs          # Mongo client + upsert + cleanup (§4)
  strava.rs      # Strava OAuth: token exchange, deauthorize (§2)
  headers.rs     # security-header helper for responses (§2)
  cookie.rs      # state cookie set/clear helpers (§2)
  redirect.rs    # callback exit helper — always clears state cookie (§2)
tests/
  callback.rs    # full handler integration: wiremock + testcontainers
scripts/
  build-placeholder.sh  # builds the first-deploy bootstrap.zip
```

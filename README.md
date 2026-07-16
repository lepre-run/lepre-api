# lepre-api

Thin Rust Lambda fronting `api.lepre.run`. Workout records remain in the
browser. DynamoDB contains only provider connections with encrypted tokens,
browser sessions, external-account lookups and short-lived webhook events.

Routes:

- `GET /v1/healthz`
- `GET /v1/auth/strava/start`
- `GET /v1/auth/strava/callback`
- `GET /v1/session`
- `GET /v1/workouts`
- `POST /v1/disconnect`
- `GET|POST /v1/webhooks/strava`

`GET /v1/workouts` returns newest-first synchronization batches containing
detailed `Run`, `TrailRun`, and `VirtualRun` activities. The initial window is
one year and can be changed with `historyDays`. Each activity includes the
selected original fields Lepre needs: identity, date, name, public description,
sport, moving and elapsed duration, distance, and laps. The Lambda fetches this
content transiently from Strava and never persists or classifies it.

Code follows the Clean Architecture dependency rule:

- `domain.rs` contains provider-independent entities and value objects.
- `application.rs` contains use cases and outbound port traits.
- `strava.rs` and `db.rs` implement provider and persistence adapters.
- `handler.rs` maps API Gateway requests and DTOs into application operations.
- `main.rs` is the composition root.

## Local verification

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Deploy

CI builds an arm64 Lambda zip and updates `lepre-api` after a push to `main`.
Infrastructure and its DynamoDB table are managed in
`~/opt/aws-infrastructure/lepre`.

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

`GET /v1/workouts` returns synchronization batches containing the provider-
independent workout entity: id, performed time, name, moving-duration seconds
and distance meters. It never persists those workouts.

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

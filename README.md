# lepre-api

Thin Rust Lambda fronting `api.lepre.run`. Workout records remain in the
browser. DynamoDB contains only encrypted Strava tokens, browser sessions and
short-lived webhook events.

Routes:

- `GET /v1/healthz`
- `GET /v1/auth/strava/start`
- `GET /v1/auth/strava/callback`
- `GET /v1/session`
- `GET /v1/workouts`
- `POST /v1/disconnect`
- `GET|POST /v1/webhooks/strava`

`GET /v1/workouts` returns only the Strava activity id, date and name. The id
is synchronization metadata; the date and name are the only workout content
persisted by the browser.

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

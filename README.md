# lepre-api

Thin Rust Lambda fronting `api.lepre.run`. Workout records remain in the
browser. DynamoDB contains only provider connections with encrypted tokens and
the athlete's display name, browser sessions, external-account lookups and
short-lived webhook events. It also holds expiring synchronization queue markers
and conservative quota reservations, but never workout payloads. Session reads
are served entirely from DynamoDB and do not consume Strava requests.

Routes:

- `GET /v1/healthz`
- `GET /v1/auth/strava/start`
- `GET /v1/auth/strava/callback`
- `GET /v1/session`
- `GET /v1/workouts`
- `POST /v1/disconnect`
- `GET|POST /v1/webhooks/strava/{webhook_path_secret}`

`GET /v1/workouts` returns newest-first synchronization batches containing
detailed `Run`, `TrailRun`, and `VirtualRun` activities. The initial window is
one year and can be changed with `historyDays`. Each activity includes the
selected original fields Lepre needs: identity, date, name, public description,
sport, workout/race type, moving and elapsed duration, distance, activity heart
rate, and laps with their heart-rate aggregates. The Lambda fetches this content
transiently from Strava and never persists it.
Each browser request enters a fair, fixed-cost synchronization queue. HTTP 202
means that the browser keeps its local checkpoint and retries after the supplied
interval; HTTP 429 provides the same pause-and-resume behavior if Strava reports
a limit directly.

Code follows the Clean Architecture dependency rule:

- `domain.rs` contains provider-independent entities and value objects.
- `application.rs` contains use cases and outbound port traits.
- `strava.rs` and `db.rs` implement provider and persistence adapters.
- `handler.rs` maps API Gateway requests and DTOs into application operations.
- `main.rs` is the composition root.


## Strava webhook security

Strava does not sign webhook event bodies. Ingress is authenticated by a
shared secret path segment plus the existing `hub.verify_token` challenge.

Required SSM SecureString parameters (loaded on Lambda cold start):

| Parameter | Purpose |
| --- | --- |
| `/lepre/api/webhook_path_secret` | Single URL path segment in the callback URL. Must be non-empty and must not contain `/`, `?`, or `#`. |
| `/lepre/api/webhook_verify_token` | Value Strava sends as `hub.verify_token` during subscription verification. |

Optional environment variable:

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEBHOOK_RATE_LIMIT_PER_MINUTE` | `120` | Process-local cap on authenticated webhook POSTs per rolling 60s window (per Lambda instance). |

### Registering the subscription

Callback URL (must include the path secret):

```text
https://api.lepre.run/v1/webhooks/strava/<webhook_path_secret>
```

Example `curl` against Strava's push subscription API (replace client id/secret
and tokens):

```bash
curl -X POST https://www.strava.com/api/v3/push_subscriptions \
  -F client_id="$STRAVA_CLIENT_ID" \
  -F client_secret="$STRAVA_CLIENT_SECRET" \
  -F callback_url="https://api.lepre.run/v1/webhooks/strava/$WEBHOOK_PATH_SECRET" \
  -F verify_token="$WEBHOOK_VERIFY_TOKEN"
```

Strava issues `GET ...?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...`
against that URL; the Lambda echoes `hub.challenge` only when both the path
secret and verify token match.

### Behaviour after hardening

- Requests to `/v1/webhooks/strava` (no secret) or with a wrong secret return
  HTTP 404 and never revoke connections or write EVENT rows.
- Athlete `authorized=false` revoke deletes a connection only after the path
  secret validates (proof the caller knows the registered subscription URL).
- Activity events accept only `aspect_type` values `create`, `update`, and
  `delete`; other aspects are acknowledged with HTTP 200 and ignored.
- Authenticated POSTs exceeding `WEBHOOK_RATE_LIMIT_PER_MINUTE` receive HTTP
  429. Pair with API Gateway stage throttling for cross-instance limits.

Rotate `webhook_path_secret` by creating a new Strava subscription with the new
callback URL, then deleting the old subscription.

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

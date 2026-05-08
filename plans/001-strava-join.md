# 008 — Slice 1: Strava join button → Lambda → Atlas

- **Status**: proposed
- **Date**: 2026-05-08

## Context

Project reboot. The prior `lepre` codebase (single-repo Astro + Rust
crate at `~/opt/adventures/lepre`) and prior ADRs 001–007 in this
folder describe a now-retired iteration; Implementation step 1
deletes them as files (rather than retiring them in place per
CLAUDE.md, since the entire codebase they describe is being
wiped — decision history is preserved via the archived
`francescobarbera/lepre` GitHub repo). Conventions carry forward
from `~/opt/aws-infrastructure` (CloudFormation, GitHub OIDC,
`customers/<project>/deployer-role.yml`) and from prior ADRs
where they don't conflict (single AWS account `018532615177`,
region `eu-west-1`, SSM SecureString prefix `/lepre/`,
Atlas M0).

Two deliberate convention overrides, hoisted here for
implementer visibility:

- **Infra stack.** `rules/infrastructure.md` mandates Terraform +
  GitLab CI + Docker. This project uses CloudFormation +
  GitHub Actions + Lambda zip deploys, matching the existing
  `~/opt/aws-infrastructure` repo. Override is reasoned and
  cross-repo-consistent.
- **ADR length.** This ADR runs ~410 lines vs. CLAUDE.md's
  ~40-line target. The §2 OAuth flow, §3 IAM scope, §4 token
  encryption, and §5 deployer-role permissions are tightly
  coupled — splitting into multiple ADRs creates cross-references
  that hurt clarity more than length does. Same call ADR 006
  made for the same reason.

Slice 1 is the smallest end-to-end path that proves the four
moving parts wire up correctly:

1. A page on AWS Amplify with a `Join with Strava` button.
2. Strava OAuth Authorization Code grant — initiated server-side
   (a Lambda `/start` route generates state and sets the
   anti-CSRF cookie; the SPA cannot do this safely with
   `HttpOnly`).
3. A Rust Lambda that handles the Strava redirect, exchanges
   the `code`, encrypts tokens with AAD-bound AES-256-GCM,
   upserts into MongoDB Atlas, and 302-redirects the browser.
4. The app shows static "Connected ✓" on success or
   "Connect failed: {reason}" on failure.

No name display, no session, no `/me` endpoint. Slice 1 succeeds
when the Strava callback either lands a row in Mongo and the
browser ends on `/connected`, or fails cleanly to
`/connect-failed?reason=…` with the Strava grant best-effort
deauthorized.

Codex round 1 flagged that three repos for "one button + one
callback + one row" is heavier than the slice itself needs.
Acknowledged, kept on purpose: slice 1 also serves as proof of
the deployment topology slice 2+ will extend without
restructuring. The cost is paid once.

## Decision

**Three repos, one CloudFormation stack on a single Rust Lambda
fronted by API Gateway HTTP API at `api.lepre.run`, Vite +
React on Amplify at apex `lepre.run`, Atlas M0 with tokens
encrypted at rest using AAD-bound AES-256-GCM, secrets in
SSM, OAuth state set by a Lambda-served `/start` route.**

### 1. Repos

- **`lepre-web`** (new GitHub repo) — Vite + React + TS strict,
  Biome, Vitest, `@testing-library/react`, Husky pre-commit
  (Biome + Vitest run on commit). All exported functions carry
  explicit return types per `rules/typescript.md`. React rules
  per `rules/react.md`: functional components only, props
  interfaces named `{ComponentName}Props`, no class
  components, no `React.memo` without profiling, styles
  colocated. Three pages: `/` (the button — anchor tag with
  static `href="https://api.lepre.run/v1/auth/strava/start"`),
  `/connected` (static "Connected ✓"), `/connect-failed`
  (reads `?reason=…` from query, renders a known message for
  recognized slugs, a generic fallback for unrecognized
  values). Deployed to Amplify via Amplify's GitHub source
  integration (Amplify pulls from `main` on push). No GitHub
  Actions in this repo for slice 1 — Amplify's build runs
  Biome + Vitest before deploy; a follow-up adds a PR
  workflow once branching matters.
- **`lepre-api`** (new GitHub repo) — single Rust crate, runtime
  `provided.al2023`, arch `arm64`, built with `cargo-lambda`.
  Routing inside one Lambda; route selection by a
  `match req.uri().path()` block in the `lambda_http` handler
  (no `axum` for slice 1 — three routes don't justify the
  framework). Application errors via `anyhow`; library-style
  errors via `thiserror` if extracted. All public items carry
  `///` doc comments per `rules/rust.md`. Crate layout:

  ```
  lepre-api/
    Cargo.toml
    src/
      main.rs        # lambda_http::run entrypoint
      handler.rs     # route match + per-route handlers
      config.rs      # Config struct, single OnceCell<Config>
      crypto.rs      # AES-256-GCM with AAD binding (§4)
      db.rs          # Mongo client (OnceCell), upsert, cleanup
      strava.rs      # Strava HTTP client (token exchange,
                     # deauthorize), explicit timeouts
      headers.rs     # security-header helper for responses
      cookie.rs      # state cookie set/clear helpers
      redirect.rs    # callback exit helper (always clears state cookie)
    tests/
      callback.rs    # integration: wiremock + testcontainers
  ```

  Routes:
  - `GET /v1/healthz` → `200 OK`,
    `Content-Type: application/json`, body `{"ok":true}`.
  - `GET /v1/auth/strava/start` → §2 (cookie + 302).
  - `GET /v1/auth/strava/callback` → §2.
  - Any other path → `404 Not Found`,
    `{"error":"not_found","code":404}` matching the
    `node-backend.md` error shape.

  CI builds the zip and calls `aws lambda update-function-code
  --zip-file fileb://…` directly (no S3 round-trip after the
  one-time bootstrap, see §3).
- **`aws-infrastructure`** (existing) — gains
  `customers/lepre/lepre-web.yaml` (the actual stack, see §3),
  `customers/lepre/api-deployer-role.yml` (new narrow role,
  see §5), edits to `customers/lepre/deployer-role.yml`
  (Amplify domain perms + OIDC trust + tighter SSM/ACM perms,
  §5), edits to `ci-deployer-role.yml` (add `lepre-deployer`
  and `lepre-api-deployer` ARNs to the
  `iam-manage-roles-and-oidc` policy — without this,
  `infra-deployer` cannot create or update those roles), and
  three new deploy steps in `.github/workflows/deploy.yml`.

The CFN stack name remains `lepre-web` (pinned by the existing
`lepre-deployer` role's resource ARN). The name covers Amplify
*and* Lambda *and* API Gateway — a documented misnomer; renaming
forces a stack replacement and is not worth slice 1's churn.
Solid-reviewer raised splitting into two stacks (`lepre-web` =
Amplify; `lepre-api` = Lambda + API GW). Deferred: trigger is
"the API stack needs a deploy cadence different from Amplify",
not yet true.

Codex raised DynamoDB instead of Atlas to avoid the
plaintext+open-allowlist combo. Rejected: tokens are encrypted
in slice 1 with AAD-bound AES-256-GCM (§4), which substantially
reduces the combined risk; Atlas is chosen by ADR 006 carry-over
and the project's data needs are naturally relational.

### 2. OAuth flow

**`/v1/auth/strava/start`** is the *only* entry point — the
button on `lepre-web` is a plain anchor. The SPA generates
nothing.

Handler:
1. Mint 32 random bytes via `rand::rngs::OsRng` (CSPRNG).
2. Encode `base64url`. Set
   `Set-Cookie: lepre_oauth_state=<value>; Path=/v1/auth/strava;
   Max-Age=600; Secure; HttpOnly; SameSite=Lax` — host-only
   (no `Domain=` attribute, so the cookie is bound to
   `api.lepre.run` exactly and not its subdomains).
3. 302 to Strava authorize URL with `client_id`,
   `response_type=code`, `redirect_uri=
   https://api.lepre.run/v1/auth/strava/callback`,
   `scope=read,activity:read_all,profile:read_all`,
   `state=<value>`.

**`/v1/auth/strava/callback`** uses a `redirect_helper` that
*always* sets `Set-Cookie: lepre_oauth_state=;
Path=/v1/auth/strava; Max-Age=0; Secure; HttpOnly;
SameSite=Lax` (matching the original Path so the deletion
takes) on every exit, success or failure. Logic:

1. If query has `error` (e.g. `error=access_denied`) →
   `redirect_helper("/connect-failed?reason=user_denied")`.
2. Read `state` cookie + `state` query param. Compare with
   `subtle::ConstantTimeEq` (matches the project pattern
   established by commit b843921). Any mismatch (missing
   cookie, missing param, unequal) → `redirect_helper(
   "/connect-failed?reason=state_invalid")`.
3. Read `code` query. Missing → `redirect_helper(
   "/connect-failed?reason=missing_code")`.
4. POST to `https://www.strava.com/oauth/token` with
   `client_id`, `client_secret` (from SSM), `code`,
   `grant_type=authorization_code`, **explicit 5 s timeout, no
   automatic retry** (the `code` is single-use; retrying after
   a network blip risks an unrecoverable failure mode). Non-2xx
   or timeout → log a correlation id, →
   `redirect_helper("/connect-failed?reason=
   strava_exchange_failed&id=<correlation_id>")`.
5. **Validate accepted scope.** Strava may return a narrowed
   `scope` query param if the user unchecked boxes on the
   consent screen (Codex: `Strava docs §authorization`).
   Parse the callback's `scope` as a comma-separated set; if
   it does not contain all three of `read`,
   `activity:read_all`, `profile:read_all`, best-effort POST
   `/oauth/deauthorize` with the access token, →
   `redirect_helper("/connect-failed?reason=scope_insufficient")`.
6. Mint a `connection_attempt_id` (UUIDv4). Encrypt
   `access_token` and `refresh_token` separately with AAD
   binding (§4). Build the Mongo doc (§4) and `replace_one`
   with `upsert: true` keyed on `strava_athlete_id`.
7. **On Mongo failure** (network error, write concern timeout,
   driver error): the write may have succeeded server-side.
   Best-effort cleanup: `delete_one({connection_attempt_id})`
   to drop any partially-written document; then call
   `best_effort_deauthorize(access_token)` (Strava
   `/oauth/deauthorize`, swallowing its errors); log
   `correlation_id`; →
   `redirect_helper("/connect-failed?reason=db_failure&id=<id>")`.
   Residual ambiguity (delete failed too) is logged for manual
   reconciliation; the user always sees the failure page.
8. **On success** → `redirect_helper("/connected")`.

The callback's `id=<correlation_id>` query param is an opaque
UUID for log lookup — `/connect-failed` may render it dimly
beneath the message ("ref: a1b2…"); not load-bearing.

Scopes requested: `read,activity:read_all,profile:read_all` —
chosen up-front to avoid re-consenting users when the
activity-reading and profile-reading slices ship. ADR 006/007
asked for narrower scopes; this is a deliberate divergence.

**Error contract.** All client-visible failures are 302
redirects to `/connect-failed?reason=<slug>` (with optional
`&id=<correlation_id>`). Slug set:
`user_denied | state_invalid | missing_code |
strava_exchange_failed | scope_insufficient | db_failure |
unknown`. The frontend renders a known message for each known
slug and a generic "Something went wrong" fallback for any
unrecognised value, so adding a new slug on the Lambda before
the frontend update doesn't crash.

**Response headers** on every Lambda response (added by
`headers::wrap` around the response builder):
`Strict-Transport-Security: max-age=63072000; includeSubDomains;
preload`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: strict-origin-when-cross-origin`. The same
three headers are configured for the Amplify app via the
CFN `AWS::Amplify::App.CustomHeaders` field so the SPA gets
the same baseline. CORS is *not* set — the OAuth flow is
top-level navigation. Slice 2 endpoints will add CORS scoped
to `https://lepre.run`.

### 3. Stack contents (`customers/lepre/lepre-web.yaml`)

CFN parameters at the top of the template (no magic numbers
in the body): `LambdaMemoryMb` (default 256),
`LambdaTimeoutSeconds` (default 10), `LogRetentionDays`
(default 7), `FunctionName` (default `lepre-api`),
`ApiDomain` (default `api.lepre.run`), `AppDomain`
(default `lepre.run`), `BootstrapS3Key` (default
`lepre/bootstrap.zip`).

Resources:

- `AWS::Amplify::App` for `lepre-web`, with GitHub source
  integration (repo `lepre-run/lepre-web`, access token
  resolved from SSM `/lepre/web/amplify_github_token` via CFN
  `{{resolve:ssm-secure:/lepre/web/amplify_github_token:1}}`).
  `CustomHeaders` populated with the three security headers
  above for `pattern: '**'`. Build env vars: none for slice 1
  (all OAuth wiring is on `api.lepre.run`, not the SPA).
- `AWS::Amplify::Branch` for `main`,
  `EnableAutoBuild: true`. `AWS::Amplify::Domain` for
  `!Ref AppDomain` (apex; Cloudflare's CNAME flattening lets
  the apex point at the Amplify-issued CNAME target).
- `AWS::IAM::Role` `lepre-api-role` with: AWS-managed
  `service-role/AWSLambdaBasicExecutionRole`,
  `ssm:GetParameter`/`GetParameters` scoped to
  `arn:aws:ssm:eu-west-1:018532615177:parameter/lepre/api/*`
  *only* (not the broader `/lepre/*` — keeps Lambda away from
  `/lepre/web/amplify_github_token`), `kms:Decrypt` on the
  AWS-managed `aws/ssm` key alias.
- `AWS::Lambda::Function` `!Ref FunctionName`,
  `Runtime: provided.al2023`, `Handler: bootstrap`,
  `Architectures: [arm64]`,
  `Code: { S3Bucket: francescobarbera-releases,
  S3Key: !Ref BootstrapS3Key }`. The S3 object is a small
  custom-runtime placeholder uploaded once during
  Implementation step 7 (a 20-line `bootstrap` shell script
  that returns 502 `stack_bootstrap_only` for every
  invocation). The first `lepre-api` CI run replaces the
  function code via `aws lambda update-function-code
  --zip-file fileb://…`. Inline `ZipFile:` is *not* used —
  CloudFormation's `ZipFile` only supports managed runtimes
  (Node, Python), not `provided.al2023`.
- `AWS::Logs::LogGroup` `!Sub /aws/lambda/${FunctionName}`,
  `RetentionInDays: !Ref LogRetentionDays`.
- `AWS::ApiGatewayV2::Api` (`ProtocolType: HTTP`).
- `AWS::ApiGatewayV2::Integration` (`AWS_PROXY` to the Lambda
  ARN, `PayloadFormatVersion: '2.0'`).
- `AWS::ApiGatewayV2::Route` `$default` → the integration.
- `AWS::ApiGatewayV2::Stage` `$default`, `AutoDeploy: true`.
- `AWS::Lambda::Permission` granting
  `apigateway.amazonaws.com` to `lambda:InvokeFunction` on the
  API ARN. Without this, every request 500s.
- `AWS::CertificateManager::Certificate` for `!Ref ApiDomain`,
  `ValidationMethod: DNS` — the validation CNAMEs are added
  manually at Cloudflare; the cert resource sits in
  `CREATE_IN_PROGRESS` until they're added. The stack creates
  with the cert pending; everything else completes around it.
- `AWS::ApiGatewayV2::DomainName` for `!Ref ApiDomain` with
  the cert ARN (`DependsOn` the cert).
- `AWS::ApiGatewayV2::ApiMapping` joining the API to the
  domain name on `Stage: $default`.

Outputs: `FunctionName`, `ApiDomain`, `AppDomain`,
`LambdaArn`, `ApiGatewayDomainNameTarget` (the
`RegionalDomainName` from the `DomainName` resource — that's
the value the user copies into the Cloudflare `api` CNAME).

### 4. Mongo

Atlas free-tier M0, region `eu-west-1` if available at
provision time, else `eu-central-1`. Database `lepre`,
collection `connections`. Document shape:

```
{
  _id: ObjectId,
  strava_athlete_id: <i64>,
  connection_attempt_id: <UUIDv4 string>,   # for cleanup-on-failure
  access_token_ciphertext: <BinData>,       # AES-256-GCM, AAD-bound
  access_token_nonce: <BinData>,            # 12 bytes, random per write
  refresh_token_ciphertext: <BinData>,
  refresh_token_nonce: <BinData>,
  key_version: <i32>,                       # 1 in slice 1
  expires_at: <ISODate>,                    # token expiry, BSON datetime from epoch seconds
  connected_at: <ISODate>,
  updated_at: <ISODate>
}
```

Index: `{ strava_athlete_id: 1 }` unique. (One provider in
slice 1; a `provider` discriminator + compound index land
when a second provider arrives, with backfill.) Connect with
`maxPoolSize=5`, client cached per Lambda container via
`tokio::sync::OnceCell<Client>`. The `tracing`
`EnvFilter` excludes the `mongodb`, `reqwest`, and
`hyper` crates from `debug` and below in the Lambda so
SRV URIs and HTTP response bodies don't leak via driver-level
logs.

**Token encryption.** AES-256-GCM via the `aes-gcm` crate.
Each token is encrypted with a fresh 12-byte random nonce.
**AAD binds the ciphertext to its row and field**: AAD =
`format!("strava|athlete={athlete_id}|kind={access|refresh}|key={key_version}")`
encoded as bytes. Decryption verifies the same AAD; an
attacker with DB write access who copies a ciphertext to
another row, another token field, or another athlete record
gets a decryption failure rather than a valid token swap.
`key_version` defaults to 1; rotation procedure is left to a
future ADR but the field is in slice 1 to avoid a schema
migration later. Encryption key is a 32-byte value stored
base64-encoded in SSM at `/lepre/api/token_encryption_key`;
Lambda reads it once on cold start (cached in `Config`).
Loss of the key loses every connection — accepted for slice
1; key backup is a follow-up.

### 5. Secrets, OIDC, deploy roles

SSM SecureString prefixes (split so Lambda's IAM scope can stay
narrow):

- `/lepre/api/strava_client_id`
- `/lepre/api/strava_client_secret`
- `/lepre/api/mongodb_uri`
- `/lepre/api/token_encryption_key`
- `/lepre/web/amplify_github_token` (read by CloudFormation,
  not by Lambda — Lambda's role doesn't grant on
  `/lepre/web/*`)

**Lambda config plumbing.** Lambda reads the four
`/lepre/api/*` parameters via a single
`ssm:GetParameters` batch call into a `Config` struct on
cold start, cached in `tokio::sync::OnceCell<Config>`.
Handlers receive `&Config`. One injection seam for tests.

**`lepre-deployer` (existing role, expanded):**
- OIDC trust replaced: the legacy
  `repo:francescobarbera/lepre:…` subject is dropped (the new
  app code lives under the `lepre-run` GitHub org, the legacy
  repo will be archived); the role now trusts only
  `repo:francescobarbera/aws-infrastructure:ref:refs/heads/main`,
  which is the repo that deploys the `lepre-web` stack.
- Amplify domain-association actions added to the existing
  `amplify-manage-app` policy:
  `amplify:CreateDomainAssociation`,
  `amplify:UpdateDomainAssociation`,
  `amplify:DeleteDomainAssociation`,
  `amplify:GetDomainAssociation`. Without these, the
  `AWS::Amplify::Domain` resource fails at deploy with
  `AccessDenied`.
- `ssm:PutParameter`/`GetParameter` on
  `arn:aws:ssm:eu-west-1:018532615177:parameter/lepre/*` +
  `kms:Decrypt` on the AWS-managed `aws/ssm` key alias.
  `ssm:DeleteParameter` is **not** granted — deletion is a
  break-glass operation; granting it on the deployer role
  means a compromised `aws-infrastructure` `main` branch
  could destroy `/lepre/api/token_encryption_key` and
  permanently brick every stored connection.
- ACM scoped: `acm:RequestCertificate` on `*` (request needs
  it because the ARN is server-generated), but
  `acm:DescribeCertificate`/`acm:DeleteCertificate` only on
  `arn:aws:acm:eu-west-1:018532615177:certificate/*`.
- (No Route 53 — DNS lives at Cloudflare.)

**`lepre-api-deployer` (new, narrow role at
`customers/lepre/api-deployer-role.yml`):** trust scoped to
`repo:lepre-run/lepre-api:ref:refs/heads/main`;
permissions limited to `lambda:UpdateFunctionCode` on
`arn:aws:lambda:eu-west-1:018532615177:function:lepre-api`.
The function name is the literal `lepre-api` (matches the
CFN parameter default) — the v2 plan to read the name from
stack Outputs is dropped: it would require adding
`cloudformation:DescribeStacks` and a `describe-stacks`
shell call to CI for a name that never changes. Single source
of truth lives in the CFN parameter default; CI uses the same
literal; divergence is detected at deploy time by the role's
function-ARN scoping.

**`infra-deployer` (existing, expanded in
`ci-deployer-role.yml`):** the
`iam-manage-roles-and-oidc` policy currently lists
`geotech-s3-upload`, `kidora-deployer`, `nologo-deployer`,
`quotesnap-deployer`, `tidy-quote-deployer`, `infra-deployer`.
Add `lepre-deployer` and `lepre-api-deployer` ARNs so the
`aws-infrastructure` CI can create or update them. Without
this addition, the deploy steps for those roles will fail with
`iam:PutRolePolicy: AccessDenied`.

### 6. CI/CD

- `lepre-web`: Amplify's built-in GitHub integration triggers
  on push to `main`. Build: `npm ci && npm run lint &&
  npm test -- --run && npm run build`. Husky pre-commit runs
  Biome + Vitest locally.
- `lepre-api`: GitHub Actions on push to `main`. Steps: cache
  Cargo, `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test`, `cargo lambda build --release --arm64`,
  `aws lambda update-function-code --function-name lepre-api
  --zip-file fileb://target/lambda/lepre-api/bootstrap.zip`.
  Assumes `lepre-api-deployer` via OIDC.
- `aws-infrastructure`: existing `deploy.yml` gains:
  - `Deploy lepre-deployer` (extends existing role) — uses
    `infra-deployer`.
  - `Deploy lepre-api-deployer` (new role) — uses
    `infra-deployer`.
  - `Deploy lepre-web` stack — assumes `lepre-deployer` (the
    role with Amplify, Lambda, API GW, ACM, IAM, SSM, Logs
    permissions for this project). The pre-existing
    `Deploy infra deployer role` step also re-runs to pick up
    the `iam-manage-roles-and-oidc` expansion.

### 7. Tests

Slice 1 ships these (real coverage; not deferred). All test
names are "should"-free per `rules/testing.md`. Rust unit
tests live in their respective modules under `#[cfg(test)]`;
the integration test lives in `tests/callback.rs`.

**`lepre-api` unit tests:**

- `state_cookie_set_on_start_carries_authorize_params`:
  handler for `/v1/auth/strava/start` returns a `Set-Cookie`
  with `HttpOnly; Secure; SameSite=Lax; Path=/v1/auth/strava;
  Max-Age=600`, no `Domain=` attribute, and a 32-byte
  base64url value; the redirect `Location` parses as a Strava
  authorize URL containing `client_id`, `redirect_uri`,
  `response_type=code`, all three scope strings, and `state`
  matching the cookie value.
- `state_match_redirects_to_connected`: callback with
  matching state + a stubbed Strava + Mongo returns 302 to
  `/connected` and clears the state cookie with the matching
  `Path` attribute.
- `state_mismatch_redirects_to_connect_failed`: callback with
  mismatched state returns 302 to `…/connect-failed?reason=
  state_invalid` and clears the cookie.
- `strava_error_param_redirects_to_connect_failed`: callback
  with `?error=access_denied` returns 302 with
  `reason=user_denied` and clears the cookie.
- `missing_code_redirects_to_connect_failed`: callback with
  matching state, no `error`, no `code` → 302 with
  `reason=missing_code` and cookie cleared.
- `strava_exchange_failed_redirects_to_connect_failed`:
  wiremock'd Strava returns 400 → 302 with
  `reason=strava_exchange_failed&id=<uuid>` and cookie
  cleared.
- `partial_scope_redirects_to_connect_failed_scope_insufficient`:
  Strava returns success but callback `scope=read` (missing
  the others) → wiremock asserts deauthorize POST happened →
  302 with `reason=scope_insufficient` and cookie cleared.
- `state_cookie_cleared_on_every_callback_exit`: table-driven
  over (`error_param`, `state_invalid`, `missing_code`,
  `strava_exchange_failed`, `scope_insufficient`,
  `db_failure`, success) — each branch's response carries the
  expected `Set-Cookie: lepre_oauth_state=;
  Path=/v1/auth/strava; Max-Age=0` deletion.
- `token_exchange_request_body_shape`: serialized request
  contains exactly `client_id`, `client_secret`, `code`,
  `grant_type=authorization_code` (form-encoded).
- `token_exchange_times_out_at_5_seconds`: `wiremock` stalls
  for 6 s → assert the exchange returns a timeout error and
  the handler maps it to `strava_exchange_failed`.
- `token_encryption_roundtrip`: encrypt + decrypt with a
  fixed key + correct AAD produces ciphertext != plaintext
  and decrypts back exactly.
- `decrypt_fails_with_wrong_athlete_id`: same key, wrong AAD
  athlete component → decryption returns an error.
- `decrypt_fails_with_wrong_token_kind`: same key, wrong AAD
  kind component (e.g. encrypted as `access`, decrypted as
  `refresh`) → error.
- `decrypt_fails_with_wrong_key_version`: AAD key_version
  mismatch → error.
- `nonce_unique_per_encryption`: 1000 encryptions of the same
  plaintext yield 1000 distinct ciphertexts and nonces.
- `healthz_returns_ok`: 200, `Content-Type: application/json`,
  body `{"ok":true}`, all three security headers present.
- `unknown_route_returns_404`: any other path → 404 with
  `{"error":"not_found","code":404}` and security headers.
- `security_headers_present_table_driven`: every route
  (start, callback success, callback failure, healthz,
  unknown) carries HSTS + X-Content-Type-Options +
  Referrer-Policy.

**`lepre-api` integration test (`tests/callback.rs`):**
Uses `lambda_http::run`-equivalent so the test exercises the
real event-translation layer. `wiremock` serves Strava;
`testcontainers` runs MongoDB. Cases:

- `happy_path_writes_encrypted_doc_with_aad`: full callback
  → Mongo collection has exactly one doc with the expected
  `strava_athlete_id`, `connection_attempt_id`, encrypted
  tokens, `expires_at` parsed correctly from epoch seconds
  to BSON datetime, `key_version=1`, `connected_at` and
  `updated_at` present and frozen-clock-stable.
- `repeat_callback_upserts_single_doc`: two successful
  callbacks for the same athlete → one doc, with the second
  call's encrypted tokens (tokens differ between calls).
- `mongo_failure_redirects_and_deauthorizes`: Lambda Config
  injected with a deliberately broken Mongo URI (deterministic
  failure, no testcontainer kill) → wiremock records the
  Strava deauthorize POST → response is 302 to
  `/connect-failed?reason=db_failure&id=<uuid>` with cookie
  cleared.

**`lepre-web` Vitest tests** (using
`@testing-library/react`):

- `button_page_renders_strava_href`: home page renders an
  anchor with
  `href === "https://api.lepre.run/v1/auth/strava/start"`.
- `connected_page_renders_static_message`: `/connected`
  renders the success copy.
- `connect_failed_renders_known_reason_message`: page with
  `?reason=user_denied` renders the user-denied message.
- `connect_failed_renders_fallback_for_unknown_reason`: page
  with `?reason=cosmic_rays` renders the generic fallback.

Acceptance gate: all of the above green in CI. The end-to-end
manual click (Implementation step 11) is a smoke check, not
the gate.

## Implementation

- [ ] 1. Wipe `~/opt/adventures/lepre/` contents *except*
  `plans/008-strava-join.md`; commit as `chore: archive prior
  iteration`. (Decision history persists in git history of the
  archived `francescobarbera/lepre` GitHub repo.)
- [ ] 2. Create new GitHub repos `lepre-run/lepre-web`
  and `lepre-run/lepre-api`. Move
  `plans/008-strava-join.md` into the new `lepre-api` repo as
  `plans/001-strava-join.md` (renumbered now that it is the
  only ADR in its new home).
- [ ] 3. In `aws-infrastructure`, open one PR with: edits to
  `ci-deployer-role.yml` (add `lepre-deployer` +
  `lepre-api-deployer` ARNs), edits to
  `customers/lepre/deployer-role.yml` (Amplify domain perms,
  OIDC trust addition, SSM `/lepre/*`, ACM cert-scoped, drop
  `ssm:DeleteParameter`), new
  `customers/lepre/api-deployer-role.yml`, new
  `customers/lepre/lepre-web.yaml`, three new deploy steps in
  `.github/workflows/deploy.yml`. Merge.
- [ ] 4. Verify via `aws iam get-role` that both `lepre-deployer`
  (with the new policies) and `lepre-api-deployer` exist before
  the next steps run. The `infra-deployer` IAM expansion must
  land in this run, before any role deploy that depends on
  the new ARN list.
- [ ] 5. Buy `lepre.run` on Cloudflare. DNS stays at Cloudflare.
- [ ] 6. Provision Atlas M0; create DB user
  (`lepre_api`, SCRAM-SHA-256, strong password); allowlist
  `0.0.0.0/0`; record SRV URI.
- [ ] 7. Generate the placeholder `bootstrap` script
  (~20 lines of POSIX shell that, in a `while true` loop,
  pulls the next event from `${AWS_LAMBDA_RUNTIME_API}` and
  posts back `{"statusCode":502,"body":"stack_bootstrap_only"}`),
  zip as `bootstrap.zip`, upload to
  `s3://francescobarbera-releases/lepre/bootstrap.zip` from
  the local terminal. Done once; replaced on first
  `lepre-api` CI run.
- [ ] 8. Generate `token_encryption_key`:
  `openssl rand -base64 32`. Create the five SSM SecureString
  params (four under `/lepre/api/`, one under
  `/lepre/web/`) from the local terminal.
- [ ] 9. Deploy the `lepre-web` CFN stack from
  `aws-infrastructure` CI. The ACM cert sits
  `CREATE_IN_PROGRESS`; everything else proceeds. Stack
  reaches `CREATE_IN_PROGRESS` waiting on the cert.
- [ ] 10. Add the ACM validation CNAME at Cloudflare; wait
  for the cert to validate (~2–10 min). Stack reaches
  `CREATE_COMPLETE`. Read the
  `ApiGatewayDomainNameTarget` output; add `api.lepre.run`
  CNAME at Cloudflare pointing at it. Add the apex
  `lepre.run` record (CNAME-flattened to the Amplify-issued
  CNAME target visible in the Amplify console after stack
  completion).
- [ ] 11. Scaffold `lepre-web` (Vite + React + TS + Biome +
  Vitest + `@testing-library/react` + Husky); implement
  three pages; push; verify Amplify build + deploy succeeds
  and apex serves the page.
- [ ] 12. Implement `lepre-api`: Cargo crate with the module
  layout in §1, the OAuth flow in §2, the encryption + AAD
  in §4, and the full §7 test suite. Wire CI; push; verify
  the real binary replaces the placeholder.
- [ ] 13. End-to-end smoke (not the acceptance gate): click
  the button as a real user, approve all scopes on Strava,
  observe (a) encrypted row in Mongo `connections`, (b)
  browser lands on `/connected`. Then deny on Strava → land
  on `/connect-failed?reason=user_denied`. Then approve only
  one scope → `…?reason=scope_insufficient` and verify
  Strava settings shows the app deauthorized.
- [ ] 14. Flip status to `accepted` in
  `lepre-api/plans/001-strava-join.md` once §7 tests are
  green in CI on both repos and the smoke check passes.
- [x] 15. *(Done in this revision.)* The legacy
  `repo:francescobarbera/lepre:…` OIDC trust subject was
  dropped from `lepre-deployer` when the new app repos moved
  to the `lepre-run` GitHub org. The legacy repo can be
  archived at the user's leisure with no role coupling.

## Alternatives considered

- **Single repo (the prior shape).** Rejected per user
  direction; revisited under Codex's "disproportionate"
  critique and kept on purpose (rationale in Context).
- **CloudFormation template inside `lepre-api`.** Rejected per
  user direction. Trade-off: a `lepre-api` infra change is
  two PRs (code + infra).
- **Lambda Function URL** instead of API Gateway HTTP API.
  Rejected: Strava only redirects to URLs whose registrable
  domain matches the app's "Authorization Callback Domain"
  (`lepre.run`); a Function URL on
  `*.lambda-url.eu-west-1.on.aws` doesn't qualify, so a
  custom domain via ACM + API Gateway (or via CloudFront) is
  unavoidable.
- **DynamoDB instead of Atlas (Codex flag).** Rejected: with
  AAD-bound AES-256-GCM at-rest encryption + SCRAM auth +
  TLS, the Atlas-allowlist combined risk is reduced to an
  acceptable level for slice 1; the project's data shape is
  naturally relational and ADR 006 carry-over is to use
  Atlas.
- **Inline CFN `ZipFile` placeholder Lambda.** Rejected after
  Codex round 2: `ZipFile` only supports managed runtimes
  (Node, Python), not `provided.al2023`. Replaced by an
  S3-backed placeholder (Implementation step 7).
- **Function name read from CFN stack Outputs.** Rejected
  after Codex round 2: requires `cloudformation:DescribeStacks`
  on the deployer role plus a CI shell call for a literal
  that never changes. Hardcoded `lepre-api` in CI + CFN
  parameter default.
- **No CSRF in slice 1.** Rejected — the `/start` route is a
  one-screen handler.
- **Plaintext tokens with a hard "before-non-dev" gate.**
  Rejected — encryption lands in slice 1 to close the
  combined Atlas-allowlist + plaintext risk.
- **Storing `accepted_scope` and `provider` in slice 1.**
  Rejected per simplicity-reviewer: scope is validated at
  callback time and discarded (no consumer reads it);
  `provider` is a constant for one provider. Both fields
  return when a second provider arrives.
- **`axum::Router` for routing.** Rejected for slice 1 —
  three routes don't justify the framework; a `match` is 5
  lines.
- **Single deployer role.** Rejected — the api-code deploy
  path lives in a separate repo, so a separate role with
  `lambda:UpdateFunctionCode` only is the right scope.
- **Split `lepre-web` into two stacks.** Deferred — trigger
  is "API stack needs a cadence different from Amplify",
  not yet true.
- **Display athlete name on `/connected`.** Rejected per
  user direction.

## Consequences

**Positive**
- Smallest end-to-end slice that *also* exercises every
  infra primitive (Amplify, Lambda, API GW, ACM, SSM,
  Atlas, OIDC, Cloudflare DNS, AAD-AES-GCM, GitHub-triggered
  CI on three repos). Slice 2+ extends, never adds.
- Three repos with clear seams: web changes don't redeploy
  Lambda; infra changes don't pull frontend code into a
  deployer role's blast radius; Lambda's IAM cannot read
  the Amplify GitHub token.
- Tokens are encrypted at rest from day one with AAD bound
  to athlete + token kind + key version — no migration when
  the closed beta opens, and copy-paste attacks against the
  DB row are detected by AEAD failure.

**Negative / risks**
- **Atlas M0 IP allow-list `0.0.0.0/0`.** Plaintext-token
  combined risk is closed by AAD-AES-GCM; residual risks
  remain — metadata leak (athlete IDs, connection times),
  availability (DB-side delete or DDoS), and replay attacks
  against fresh ciphertexts are not addressed by encryption.
  Reduced to acceptable for slice 1; PrivateLink requires
  paid tier.
- **Cloudflare-managed DNS + manual cert validation.** Adds
  a manual paste-CNAME step on every new ACM cert.
  Acceptable at one cert.
- **`lepre-deployer` OIDC trust** is now scoped to a single
  subject (`francescobarbera/aws-infrastructure` on `main`).
  The legacy `francescobarbera/lepre` trust was dropped in
  Implementation step 15 when the new app repos moved to
  `lepre-run`.
- **Stack name `lepre-web` covers Lambda + API GW too.**
  Documented misnomer; renaming forces stack replacement.
- **`token_encryption_key` loss = total connection loss.**
  Slice 1 has no key backup. Mitigation: SSM keeps revision
  history; KMS-managed key + rotation ADR before beta opens.
- **`/connected` and `/connect-failed` are publicly
  accessible** and could be used as low-impact phishing
  pages. A signed `?ok=<hmac>` param would close it but
  costs more than the impact justifies for slice 1;
  deferred.
- **OAuth `code` retry hazard.** A network blip after Strava
  accepted the `code` is unrecoverable for that attempt;
  the user re-clicks Join with Strava and goes through
  `/start` again with a fresh CSRF state. Documented; no
  automatic retry inside the handler.
- **Mongo "ambiguous write" trap.** `replace_one` may have
  succeeded server-side when the client saw a network
  error; the cleanup path attempts `delete_one` against
  `connection_attempt_id` before deauthorizing. If the
  cleanup also fails, the user sees a failure page but a
  stored row may persist for an athlete whose Strava grant
  is now revoked — manual reconciliation. Slice 1 accepts
  the residual ambiguity; an idempotency-key-based cleanup
  job lands in slice 2 if it actually happens.
- **No alarms / metrics** in slice 1. Acceptable at zero
  traffic; an observability ADR before beta.

## Links

- `~/opt/aws-infrastructure/customers/lepre/deployer-role.yml`
  — existing role, edited per §5.
- `~/opt/aws-infrastructure/ci-deployer-role.yml` — existing
  bootstrap role, gains two ARNs in
  `iam-manage-roles-and-oidc`.
- `~/opt/aws-infrastructure/.github/workflows/deploy.yml` —
  gains three new deploy steps.
- ADR 006 (deleted by step 1) — region, account, SSM prefix
  discipline, Atlas, OIDC pattern carry forward.
- ADR 007 (deleted by step 1) — token encryption shape,
  scope rationale, error-contract shape carry forward.

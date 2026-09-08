# Shadow Agent Backend

FastAPI gateway for the Shadow Agent runtime security layer.

## Project Structure

```text
backend/
  main.py            # application wiring: middleware, routers, lifespan
  app/
    config.py        # environment-driven configuration helpers
    schemas.py       # Pydantic request/response models
    serializers.py   # ORM row -> response serialization
    auth_helpers.py  # console auth/session helpers
    audit.py         # intercept logging, approvals, alerts, admin audit
    upstream.py      # upstream LLM forwarding (shared connection pool)
    metrics.py       # Prometheus /metrics counters + latency histograms
    routers/         # HTTP routers per domain
      auth.py        #   /api/v1/auth/*
      api_keys.py    #   /api/v1/api-keys*
      monitoring.py  #   /api/v1/logs|approvals|alerts|semantic-status
      replays.py     #   /api/v1/replays*
      policies.py    #   /api/v1/policies*
      tool_policies.py # /api/v1/tool-policies*
      rules.py       #   /api/v1/rules* (custom rules + dlp-status)
      gateway.py     #   /api/v1/analyze, /api/v1/chat/completions
    semantic.py      # request-side ML injection classifier (runtime)
    semantic_corpus.py # labeled training corpus (645 samples)
    semantic_model.json # trained model artifact (loaded in-process)
    dlp.py           # response-side DLP engine + streaming scanner
  tools/             # train_semantic_model.py, bench_semantic.py
  alembic/           # migration environment + versions
  security_engine.py # policy/permission/risk engines
  security_controls.py # auth, rate limiting, redaction
  database.py / models.py
  tests/             # pytest suite (fast, isolated temp DB per session)
```

## Run

```powershell
cd D:\Github_projects\ShadowAgent\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item .env.example .env
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

`main.py` will automatically load `backend/.env`, `backend/.env.local`, or
the repository-root `.env` at startup. For local development, editing
`backend/.env` is the easiest way to avoid re-entering API keys every time.
Console login **requires** `SHADOW_AGENT_JWT_SECRET`: the JWT signing key is
no longer derived from the static API keys, so a leaked client key cannot be
used to forge admin tokens.

Example `backend/.env`:

```env
SHADOW_AGENT_ADMIN_API_KEY=test-admin-key
SHADOW_AGENT_CLIENT_API_KEY=test-client-key
SHADOW_AGENT_JWT_SECRET=replace-with-a-random-string-at-least-32-characters
SHADOW_AGENT_API_KEY_PEPPER=replace-with-a-separate-random-string-for-managed-api-keys
SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN=replace-with-a-long-random-bootstrap-token
SHADOW_AGENT_ALLOW_OPEN_CONSOLE_BOOTSTRAP=false
SHADOW_AGENT_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
SHADOW_AGENT_UPSTREAM_BASE_URL=https://api.openai.com
SHADOW_AGENT_UPSTREAM_API_KEY=replace-with-upstream-provider-key
SHADOW_AGENT_UPSTREAM_MODEL=replace-with-upstream-model-name
SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES=true
SHADOW_AGENT_DATABASE_PATH=shadow_agent.db
SHADOW_AGENT_SEMANTIC_MODE=enforce
SHADOW_AGENT_RESPONSE_DLP_MODE=redact
```

Protected endpoints accept either:

- `Authorization: Bearer <jwt>` issued by `/api/v1/auth/register` or `/api/v1/auth/login`
- `Authorization: Bearer <api-key>` — OpenAI SDK compatible: managed keys and
  shared env keys also work via the Bearer scheme
- `X-API-Key` for a managed API key created by the backend admin console
- `X-API-Key` for legacy shared env keys during local development or compatibility mode

JWTs must be HS256 signed with `SHADOW_AGENT_JWT_SECRET` and include `exp`
plus a `role` claim of `admin`, `security_admin`, `client`, or `gateway`.
Managed API keys are hashed with `SHADOW_AGENT_API_KEY_PEPPER`, so production
deployments should set that value separately from the JWT secret.
Set `SHADOW_AGENT_ALLOWED_ORIGINS` to the public dashboard origin when exposing
the service across networks.

## OpenAI SDK Compatibility

Point any OpenAI-compatible SDK at the gateway — change `base_url` and `api_key`,
nothing else:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/api/v1", api_key="sak_...")
print(client.models.list())          # GET /api/v1/models (upstream model + simulated)
print(client.chat.completions.create(model="...", messages=[...]))
```

`GET /api/v1/models` lists the configured `SHADOW_AGENT_UPSTREAM_MODEL` plus
`shadow-agent-simulated` when simulated responses are enabled. Blocked requests
return a standard 403 error envelope whose `detail` carries the full security
decision (`request_id`, `reason`, `risk_score`, `matched_rules`, …), so SDK
callers can distinguish intercepts from upstream failures.

## Semantic Injection Detection (request side)

Prompt-injection detection runs as a two-layer fusion inside
`security_engine.semantic_intent_check`:

1. **regex signatures** — deterministic `INJECTION_PATTERNS` (high precision)
2. **local ML classifier** — `app/semantic.py` scores the text with a shipped
   logistic-regression model over hashed word/char n-gram features
   (`app/semantic_model.json`). In-process, zero network access, zero
   dependencies beyond the stdlib; ~60µs per text at P95.

Runtime configuration (read lazily, same pattern as the DLP engine):

- `SHADOW_AGENT_SEMANTIC_MODE` — `off` | `monitor` | `enforce` (default `enforce`).
  `monitor` lets flagged traffic through but persists
  `semantic_injection_suspected` intercept records (action `Monitored`) for
  gray-launch evaluation; `enforce` blocks at/above the threshold (403).
- `SHADOW_AGENT_SEMANTIC_THRESHOLD` — optional 0.5–0.99 override; empty = the
  precision-first threshold baked into the artifact by the trainer.

Operational endpoints (admin credentials required):

- `GET /api/v1/semantic-status` — mode, threshold, `model_loaded`,
  `model_version`, `trained_at`, train metrics.
- `GET /api/v1/rules/dlp-status` — response-side DLP mode/pattern counts.

Known limitation: recall on paraphrased **Chinese** injections is low
(held-out ~5%); see the benchmark for mitigation and the upgrade roadmap.

### Retraining & benchmarking

```powershell
# 1. extend the labeled corpus (keep tags balanced across the stratified split)
#    backend/app/semantic_corpus.py
# 2. retrain — writes backend/app/semantic_model.json
python tools\train_semantic_model.py
# 3. regenerate the published benchmark (docs/benchmarks/injection-detection.md)
python tools\bench_semantic.py
```

The trainer and the runtime share the exact feature-extraction code
(`app.semantic.extract_features`), so a regenerated artifact is drop-in:
restart the backend (or the container) to load it. Feature extraction must
stay byte-identical between training and inference.

## Response-Side DLP

Model outputs are scanned for secrets (AWS/GitHub/OpenAI keys, JWT, private
keys, plus admin-managed custom rules) with
`SHADOW_AGENT_RESPONSE_DLP_MODE` = `off` | `monitor` | `redact` | `block`
(default `redact`). Streaming responses use a hold-back buffer so secrets
split across SSE chunks are still caught. Custom rules are managed via
`/api/v1/rules*` (admin-only CRUD with audit logging and validation).

## Multi-Tenancy (Organizations)

Console users belong to organizations; every admin surface (logs, policies,
custom rules, managed keys, SSE event stream) is scoped to the caller's active
organization, while platform principals (static env keys / platform admins)
keep seeing everything.

- A default organization is seeded lazily at startup; pre-existing users and
  rows are backfilled into it, so single-tenant deployments keep working
  unchanged.
- Creating organizations requires a platform admin or an org `owner`; the
  creator becomes the owner of the new org.
- The active organization is carried in the session JWT (`org_id` / `org_role`
  claims). `POST /api/v1/auth/switch-org` re-issues the token for another
  membership; `GET /api/v1/auth/me` lists all orgs the user belongs to.
- Cross-tenant access by id returns `404` (no existence leak). All org
  mutations are audit-logged (`organization_created`, `org_member_added`, …).

Org management API: `GET/POST /api/v1/orgs`, `GET/PATCH/DELETE /api/v1/orgs/{id}`
(delete requires `?force=true` once the org owns data — it purges org-scoped
rows), plus members (`GET/POST /api/v1/orgs/{id}/members`,
`PATCH/DELETE /api/v1/orgs/{id}/members/{user_id}`).

## OIDC Single Sign-On (SSO)

Per-organization OIDC connections (Authorization Code + PKCE) configured at
runtime — no static env config per IdP:

1. In the console "组织管理" view (or `PUT /api/v1/orgs/{org_id}/sso`) fill in
   `provider_name`, `issuer_url` (must expose `.well-known/openid-configuration`),
   `client_id` / `client_secret`, optional `scopes`, `default_role` (platform
   role for JIT-provisioned users) and `jit_enabled` / `enabled` toggles.
   An empty `client_secret` on update keeps the stored one; the secret never
   leaves the DB (responses return a masked hint only).
2. Register the redirect URI `{SHADOW_AGENT_PUBLIC_BASE_URL}/api/v1/auth/sso/callback`
   with the IdP and make sure the console base URL (`SHADOW_AGENT_CONSOLE_URL`)
   is reachable from the user's browser.
3. Members enter the org slug on the console login screen ("SSO 登录") —
   `GET /api/v1/auth/sso/providers/{slug}` checks availability and
   `GET /api/v1/auth/sso/{slug}/login` redirects to the IdP with PKCE.
4. The backend exchanges the code, validates the ID token (signature via
   JWKS, issuer, audience, expiry, nonce — replay rejected), matches the email
   to a console user or JIT-provisions one, then redirects the browser to
   `{CONSOLE_URL}/sso/callback#access_token=...&expires_at=...` (errors arrive
   as `#error=...&error_description=...`).

Login state is single-use with a TTL; disabled/deactivated accounts are
rejected at callback time.

## Intercept Alerting (Webhook)

Set `SHADOW_AGENT_ALERT_WEBHOOK_URL` to receive a signed JSON POST on every
blocked request (Slack / Feishu / DingTalk bots or your own receiver):
- Payload fields: `source`, `event`, `timestamp` (UTC ISO), `request_id`,
  `threat_type`, `category`, `risk_score`, `layer`, `reason`,
  `recommended_action`, `action_taken`.
- With `SHADOW_AGENT_ALERT_WEBHOOK_SECRET` set, each delivery carries
  `X-ShadowAgent-Signature: sha256=<hmac-sha256 of the raw body>` for receiver-side
  verification.
- Deliveries retry up to 3 attempts (1s / 4s backoff) in a background task;
  the database audit log remains the authoritative record.

Before the first console admin can register, the backend should either:

- set `SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN` and send it as `X-Shadow-Agent-Bootstrap-Token`
- or, for local demo-only setup, explicitly set `SHADOW_AGENT_ALLOW_OPEN_CONSOLE_BOOTSTRAP=true`

After the first admin exists, self-service registration is **closed by default**.
To let additional users register, choose one of:

- local/open demo: set `SHADOW_AGENT_ALLOW_OPEN_REGISTRATION=true`
- invite-only: set `SHADOW_AGENT_CONSOLE_INVITE_TOKEN` and share it out-of-band;
  new users must send it as `X-Shadow-Agent-Invite-Token` when calling
  `/api/v1/auth/register`

If neither is configured, subsequent registrations return `403 registration_disabled`.
The live registration policy is exposed by `GET /api/v1/auth/bootstrap-status` via
`open_registration_enabled` and `invite_token_configured`.

## Real Upstream Proxy

By default, the gateway can still run in local demo mode if
`SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES=true`.

To use Shadow Agent as a real production-style gateway, set:

- `SHADOW_AGENT_UPSTREAM_BASE_URL`
- `SHADOW_AGENT_UPSTREAM_API_KEY`
- `SHADOW_AGENT_UPSTREAM_MODEL`

Then `/api/v1/chat/completions` will:

1. Audit the request
2. Separate trusted user intent from untrusted external context
3. Forward the sanitized payload to the upstream LLM provider
4. Return the upstream response with Shadow Agent audit metadata attached

For production deployments, set `SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES=false`.

If you need a custom database target, you can also set:

- `SHADOW_AGENT_DATABASE_PATH`
- `SHADOW_AGENT_DATABASE_URL`

## Managed API Keys

For production-style usage, do not keep issuing one shared client/admin key to everyone.
Instead:

1. Set `SHADOW_AGENT_JWT_SECRET`
2. Set `SHADOW_AGENT_API_KEY_PEPPER`
3. Set `SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN`
4. Register the first console account with `X-Shadow-Agent-Bootstrap-Token` so it becomes `admin`
5. Log into the admin console
6. Create per-user or per-system managed keys through:
   - `GET /api/v1/api-keys`
   - `POST /api/v1/api-keys`
   - `POST /api/v1/api-keys/{id}/rotate`
   - `POST /api/v1/api-keys/{id}/revoke`
   - `DELETE /api/v1/api-keys/{id}`
   - `POST /api/v1/api-keys/{id}/activate`

Managed keys support:

- Independent roles: `admin`, `security_admin`, `client`, `gateway`
- Rotation without changing the whole deployment environment
- Revocation when a key leaks
- Expiration windows
- Last-used audit metadata

The raw key is returned only once during create/rotate. The list API only returns
the masked prefix.

## Console Role Policy

- The first registered console user becomes `admin` by default only after the bootstrap gate is satisfied
- Later registrations default to `client`
- You can override that behavior with:
  - `SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN`
  - `SHADOW_AGENT_ALLOW_OPEN_CONSOLE_BOOTSTRAP`
  - `SHADOW_AGENT_ALLOW_OPEN_REGISTRATION`
  - `SHADOW_AGENT_CONSOLE_INVITE_TOKEN`
  - `SHADOW_AGENT_FIRST_USER_ROLE`
  - `SHADOW_AGENT_CONSOLE_DEFAULT_ROLE`

## Share Across Devices

For local-only use, keep the backend on `127.0.0.1` and point the frontend to:

```text
http://localhost:8000
```

To let other people on the same network use it:

1. Start the backend on `0.0.0.0`
2. Start the frontend with `npm run dev:public`
3. Set `SHADOW_AGENT_ALLOWED_ORIGINS` to the frontend's real URL
4. Give them your machine's LAN URL, such as `http://192.168.1.10:8000`

For serious multi-user usage, do not distribute the shared env keys. Let users
sign in through the console, or issue each integration its own managed API key
so it can be rotated or revoked independently.

## Smoke Test

The fast pytest suite is the primary regression gate (uses an isolated temp
database, a mock upstream, and does not touch your real `.env` values):

```powershell
cd D:\Github_projects\ShadowAgent\backend
pip install -r requirements-dev.txt
python -m pytest tests
```

It covers auth flows, managed API keys, policy management, approvals,
replays, gateway decisions, streaming concurrency, metrics, and the security
hardening regressions (conversation-history injection blocking, instant JWT
revocation, login lockout, approval state machine, admin action audit trail).

The legacy scripts remain as ad-hoc probes against a running server:

```powershell
python test_gateway.py
python test_integration.py
```

## Database Migrations (Alembic)

Schema changes are versioned under `alembic/versions/`. The runtime still
self-initializes via `create_all`, but production deployments should drive
schema changes through migrations:

```powershell
python -m alembic upgrade head                        # apply pending migrations
python -m alembic revision --autogenerate -m "..."    # create a new migration
python -m alembic history                             # inspect revisions
```

Existing databases created before Alembic was introduced are already stamped
at the baseline revision. The container entrypoint runs `upgrade head` before
starting uvicorn, and the database URL is resolved from the same environment
variables as the app (`SHADOW_AGENT_DATABASE_URL` / `SHADOW_AGENT_DATABASE_PATH`).

## Metrics

`GET /metrics` exposes Prometheus text-format metrics (admin credentials
required — the same `Authorization: Bearer` or `X-API-Key` as other admin
endpoints):

- `shadow_agent_http_requests_total{method,status,route}` — request counter
- `shadow_agent_http_request_duration_seconds_bucket/sum/count{route}` —
  latency histogram (buckets 5ms…10s)

Routes are recorded as templates (`/api/v1/policies/{id}`) so label
cardinality stays bounded. Requests throttled by the rate limiter before
reaching the app are not counted. Rows purged by the retention job are
exported as `shadow_agent_retention_purged_rows_total{table}`.

## Real-Time Event Stream (SSE)

`GET /api/v1/events/stream` (admin credentials required) pushes intercept
events to connected clients as Server-Sent Events:

- Frames: `event: intercept` with a JSON payload (request_id, layer,
  threat_type, risk_score, reason, …); `: ping` comments every 15s as
  heartbeat.
- On connect the last 50 events are replayed so dashboards render instantly.
- Use `fetch()` with header auth (browser `EventSource` cannot send
  Authorization headers); reconnect with backoff.
- In-process fan-out, bounded queues, slow consumers drop the oldest event;
  the database audit log remains the authoritative record.

## Log Retention

Operational logs are purged automatically (data minimization, see
`docs/compliance/gdpr.md`). Defaults: intercept logs / alert events /
replay runs 180 days, audit logs 365 days. Override globally with
`SHADOW_AGENT_LOG_RETENTION_DAYS`, per table with
`SHADOW_AGENT_INTERCEPT_LOG_RETENTION_DAYS` /
`SHADOW_AGENT_AUDIT_LOG_RETENTION_DAYS` /
`SHADOW_AGENT_ALERT_RETENTION_DAYS` /
`SHADOW_AGENT_REPLAY_RETENTION_DAYS` (set to `0` to keep a table forever).
The job runs at startup and then every
`SHADOW_AGENT_RETENTION_CLEANUP_INTERVAL_SECONDS` (default 3600, min 60),
deleting in bounded batches so large first runs cannot lock the database.

## Performance Testing

`perf/load_test.py` is a dependency-free load generator with bounded
concurrency/duration (safe for developer laptops):

```powershell
# terminal 1: isolated server (raised rate limit, throwaway DB, simulated mode)
$env:SHADOW_AGENT_DATABASE_PATH="$env:TEMP\perf.db"
$env:SHADOW_AGENT_RATE_LIMIT_PER_MINUTE="1000000"
$env:SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES="true"
$env:SHADOW_AGENT_UPSTREAM_BASE_URL=" "   # space: keep .env from overriding
python -m uvicorn main:app --host 127.0.0.1 --port 8018

# terminal 2:
python perf/load_test.py --base-url http://127.0.0.1:8018 `
    --client-key <client key> --admin-key <admin key>
```

Scenarios: `health`, `chat` (clean request through the full engine),
`injection` (blocked request, exercises intercept logging), `analyze`,
`logs`, `mixed`. Output includes RPS, p50/p90/p95/p99, and status-code
distribution. See `docs/launch-checklist.md` for recorded baselines.

## High Availability / Multi-Instance

The rate limiter and login lockout are process-local by default. To run
multiple gateway replicas behind a load balancer, share that state in Redis:

1. `pip install -r requirements-redis.txt` (or build the image with
   `--build-arg INSTALL_REDIS=true` / compose `SHADOW_AGENT_ENABLE_REDIS=true`)
2. Set `SHADOW_AGENT_REDIS_URL=redis://host:6379/0`

`GET /health` reports the active backend as `"shared_state": "redis"|"memory"`
so misconfiguration is observable. Redis failures at runtime degrade fail-open
(availability over throttle precision) with error logs. Multi-instance
deployments must also move SQLite to a shared filesystem or switch
`SHADOW_AGENT_DATABASE_URL` to a client-server database.

## Docker

Build and run the full stack from the repository root:

```powershell
Copy-Item .env.example .env   # fill in real secrets first
docker compose up -d --build
```

The backend container applies Alembic migrations at startup, persists SQLite
in the `shadowagent-data` volume, runs as a non-root user, and exposes a
healthcheck. Required secrets (`SHADOW_AGENT_JWT_SECRET`, static API keys,
pepper) fail fast when missing. See the root `.env.example` for all variables.

## Security Hardening Notes

- Conversation history (all non-system messages) is audited for injected
  instructions, not just the latest user message.
- Disabling or deleting a console user revokes their JWT immediately.
- Repeated failed logins lock the account temporarily
  (`SHADOW_AGENT_LOGIN_MAX_FAILURES`, `SHADOW_AGENT_LOGIN_LOCKOUT_SECONDS`).
- Privileged management operations (API keys, policies, approvals) are
  recorded in the audit log.
- Approvals transition only once out of `pending`; re-review returns `409`.
- Custom policy regexes are validated on create/update (`400` on invalid
  patterns) and compiled patterns are cached.
- Intercept logs store `request_id` in an indexed column; replays use that
  index instead of scanning the whole table.

## Broken Access Control Probe

```powershell
python broken_access_control_probe.py --base-url http://127.0.0.1:8000
```

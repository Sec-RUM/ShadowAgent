# Shadow Agent Backend

FastAPI gateway for the Shadow Agent runtime security layer.

## Run

```powershell
cd D:\Github_projects\ShadowAgent\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

`main.py` will automatically load `backend/.env`, `backend/.env.local`, or
the repository-root `.env` at startup. For local development, editing
`backend/.env` is the easiest way to avoid re-entering API keys every time.
If you want the console login flow to issue bearer tokens, also set
`SHADOW_AGENT_JWT_SECRET`.

Example `backend/.env`:

```env
SHADOW_AGENT_ADMIN_API_KEY=test-admin-key
SHADOW_AGENT_CLIENT_API_KEY=test-client-key
SHADOW_AGENT_JWT_SECRET=replace-with-a-random-string-at-least-32-characters
SHADOW_AGENT_API_KEY_PEPPER=replace-with-a-separate-random-string-for-managed-api-keys
SHADOW_AGENT_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
SHADOW_AGENT_UPSTREAM_BASE_URL=https://api.openai.com
SHADOW_AGENT_UPSTREAM_API_KEY=replace-with-upstream-provider-key
SHADOW_AGENT_UPSTREAM_MODEL=replace-with-upstream-model-name
SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES=true
SHADOW_AGENT_DATABASE_PATH=shadow_agent.db
```

Protected endpoints accept either:

- `Authorization: Bearer <jwt>` issued by `/api/v1/auth/register` or `/api/v1/auth/login`
- `X-API-Key` for a managed API key created by the backend admin console
- `X-API-Key` for legacy shared env keys during local development or compatibility mode

JWTs must be HS256 signed with `SHADOW_AGENT_JWT_SECRET` and include `exp`
plus a `role` claim of `admin`, `security_admin`, `client`, or `gateway`.
Managed API keys are hashed with `SHADOW_AGENT_API_KEY_PEPPER`, so production
deployments should set that value separately from the JWT secret.
Set `SHADOW_AGENT_ALLOWED_ORIGINS` to the public dashboard origin when exposing
the service across networks.

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
3. Register the first console account so it becomes `admin`
4. Log into the admin console
5. Create per-user or per-system managed keys through:
   - `GET /api/v1/api-keys`
   - `POST /api/v1/api-keys`
   - `POST /api/v1/api-keys/{id}/rotate`
   - `POST /api/v1/api-keys/{id}/revoke`
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

- The first registered console user becomes `admin` by default
- Later registrations default to `client`
- You can override that behavior with:
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

```powershell
cd D:\Github_projects\ShadowAgent\backend
python test_gateway.py
```

## Broken Access Control Probe

```powershell
python broken_access_control_probe.py --base-url http://127.0.0.1:8000
```

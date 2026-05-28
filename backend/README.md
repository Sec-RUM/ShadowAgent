# Shadow Agent Backend

FastAPI prototype for the Shadow Agent gateway and purification engine.

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
SHADOW_AGENT_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

Protected endpoints accept either `X-API-Key` or `Authorization: Bearer <jwt>`.
JWTs must be HS256 signed with `SHADOW_AGENT_JWT_SECRET` and include `exp`
plus a `role` claim of `admin`, `security_admin`, `client`, or `gateway`.
Set `SHADOW_AGENT_ALLOWED_ORIGINS` to the public dashboard origin when exposing
the service across networks.

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

Anyone who knows the shared API key can use the corresponding role. The current
implementation uses shared admin/client keys, not per-user API keys.

## Smoke Test

```powershell
cd D:\Github_projects\ShadowAgent\backend
python test_gateway.py
```

## Broken Access Control Probe

```powershell
python broken_access_control_probe.py --base-url http://127.0.0.1:8000
```

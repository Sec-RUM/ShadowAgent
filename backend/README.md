# Shadow Agent Backend

FastAPI prototype for the Shadow Agent gateway and purification engine.

## Run

```powershell
cd E:\SecurityTools\AIsec_Sandbox\CodeX\ShadowAgent\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SHADOW_AGENT_ADMIN_API_KEY="replace-with-long-random-admin-key"
$env:SHADOW_AGENT_CLIENT_API_KEY="replace-with-long-random-client-key"
$env:SHADOW_AGENT_ALLOWED_ORIGINS="http://localhost:3000,http://127.0.0.1:3000"
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Protected endpoints accept either `X-API-Key` or `Authorization: Bearer <jwt>`.
JWTs must be HS256 signed with `SHADOW_AGENT_JWT_SECRET` and include `exp`
plus a `role` claim of `admin`, `security_admin`, `client`, or `gateway`.
Set `SHADOW_AGENT_ALLOWED_ORIGINS` to the public dashboard origin when exposing
the service across networks.

## Smoke Test

```powershell
cd E:\SecurityTools\AIsec_Sandbox\CodeX\ShadowAgent\backend
python test_gateway.py
```

## Broken Access Control Probe

```powershell
python broken_access_control_probe.py --base-url http://127.0.0.1:8000
```

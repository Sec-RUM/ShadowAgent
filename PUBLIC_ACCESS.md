# Public Access Setup

ShadowAgent is now configurable for access from another network. Keep the API
keys private before exposing any port.

## 1. Choose a Public URL

Use one of these:

- A cloud server with a public IP/domain.
- Router port forwarding to this machine.
- A tunnel such as Cloudflare Tunnel, ngrok, or frp.

You need two public URLs if frontend and backend are both exposed:

- Frontend: `https://shadow.example.com`
- Backend: `https://shadow-api.example.com`

## 2. Start the Backend

```powershell
cd D:\Github_projects\ShadowAgent\backend
$env:SHADOW_AGENT_ADMIN_API_KEY="replace-with-long-random-admin-key"
$env:SHADOW_AGENT_CLIENT_API_KEY="replace-with-long-random-client-key"
$env:SHADOW_AGENT_ALLOWED_ORIGINS="https://shadow.example.com"
.\start_public.ps1 -HostAddress 0.0.0.0 -Port 8000
```

For local network testing, use:

```powershell
$env:SHADOW_AGENT_ALLOWED_ORIGINS="http://YOUR-LAN-IP:3000"
.\start_public.ps1 -HostAddress 0.0.0.0 -Port 8000
```

## 3. Start the Frontend

```powershell
cd D:\Github_projects\ShadowAgent\frontend
$env:SHADOW_AGENT_API_BASE="https://shadow-api.example.com"
$env:SHADOW_AGENT_ADMIN_API_KEY="same-admin-key-used-by-backend"
.\start_public.ps1 -HostAddress 0.0.0.0 -Port 3000
```

For local network testing:

```powershell
$env:SHADOW_AGENT_API_BASE="http://YOUR-LAN-IP:8000"
.\start_public.ps1 -HostAddress 0.0.0.0 -Port 3000
```

## 4. Firewall / Router

Open only the ports you actually need:

- `3000/tcp` for the dashboard.
- `8000/tcp` for the API, only if it is not hidden behind a reverse proxy.

For production, put HTTPS in front of both services with Nginx, Caddy,
Cloudflare, or another reverse proxy. Do not expose the API without TLS.

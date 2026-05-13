param(
    [string]$HostAddress = "0.0.0.0",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"

if (-not $env:SHADOW_AGENT_ADMIN_API_KEY) {
    throw "Set SHADOW_AGENT_ADMIN_API_KEY before exposing the backend."
}

if (-not $env:SHADOW_AGENT_CLIENT_API_KEY -and -not $env:SHADOW_AGENT_JWT_SECRET) {
    throw "Set SHADOW_AGENT_CLIENT_API_KEY or SHADOW_AGENT_JWT_SECRET before exposing the backend."
}

python -m uvicorn main:app --host $HostAddress --port $Port

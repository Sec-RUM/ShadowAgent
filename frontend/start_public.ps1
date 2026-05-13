param(
    [string]$HostAddress = "0.0.0.0",
    [int]$Port = 3000
)

$ErrorActionPreference = "Stop"

if (-not $env:SHADOW_AGENT_API_BASE) {
    throw "Set SHADOW_AGENT_API_BASE to the backend URL before starting the frontend."
}

if (-not $env:SHADOW_AGENT_ADMIN_API_KEY -and -not $env:SHADOW_AGENT_JWT_TOKEN) {
    throw "Set SHADOW_AGENT_ADMIN_API_KEY or SHADOW_AGENT_JWT_TOKEN so the dashboard can read protected logs."
}

$npm = Get-Command npm -ErrorAction SilentlyContinue
if ($npm) {
    npm run build
    npm run start -- --hostname $HostAddress --port $Port
    exit $LASTEXITCODE
}

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    throw "Neither npm nor node is available on PATH. Install Node.js or add it to PATH."
}

node .\node_modules\next\dist\bin\next build
node .\node_modules\next\dist\bin\next start --hostname $HostAddress --port $Port

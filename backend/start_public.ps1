param(
    [string]$HostAddress = "0.0.0.0",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"

$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) {
            return
        }

        if ($line.StartsWith("export ")) {
            $line = $line.Substring(7).Trim()
        }

        $parts = $line.Split("=", 2)
        $name = $parts[0].Trim()
        $value = $parts[1].Trim().Trim('"').Trim("'")
        if ($name -and -not (Test-Path "Env:$name")) {
            Set-Item -Path "Env:$name" -Value $value
        }
    }
}

if (-not $env:SHADOW_AGENT_ADMIN_API_KEY) {
    throw "Set SHADOW_AGENT_ADMIN_API_KEY or add it to backend/.env before exposing the backend."
}

if (-not $env:SHADOW_AGENT_CLIENT_API_KEY -and -not $env:SHADOW_AGENT_JWT_SECRET) {
    throw "Set SHADOW_AGENT_CLIENT_API_KEY or SHADOW_AGENT_JWT_SECRET, or add one of them to backend/.env before exposing the backend."
}

python -m uvicorn main:app --host $HostAddress --port $Port

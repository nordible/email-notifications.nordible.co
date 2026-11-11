# Load environment variables from .env if present
if (Test-Path ".env") {
    Get-Content ".env" | Where-Object { $_ -match '=' -and -not $_.StartsWith('#') } | ForEach-Object {
        $parts = $_.Split('=', 2)
        $key = $parts[0].Trim()
        $val = $parts[1].Trim()
        Set-Variable -Name $key -Value $val -Scope Script -ErrorAction SilentlyContinue
    }
}

# Parameters (fallback to defaults if not defined in .env)
$SshUser = if ($SSH_USER) { $SSH_USER } else { "root" }
$SshHost = if ($SSH_HOST) { $SSH_HOST } else { "95.217.5.54" }
$SshPort = if ($SSH_PORT) { $SSH_PORT } else { "22" }
$RemoteDir = if ($REMOTE_APP_DIR) { $REMOTE_APP_DIR } else { "/opt/bulwark-relay" }

Write-Host "⏳ Step 1: Syncing repository and restarting container on $SshHost..." -ForegroundColor Cyan

$remoteScript = @"
set -e
cd $RemoteDir
git fetch origin
git checkout main
git pull origin main
docker compose up -d --build --force-recreate
sleep 3
docker ps --filter name=bulwark-relay
"@

ssh -p $SshPort "${SshUser}@${SshHost}" $remoteScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ Remote deployment failed."
    exit $LASTEXITCODE
}

Write-Host "✅ Bulwark Push Relay deployment to $SshHost completed successfully!" -ForegroundColor Green

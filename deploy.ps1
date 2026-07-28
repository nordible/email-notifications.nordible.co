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
$ContainerName = if ($CONTAINER_NAME) { $CONTAINER_NAME } else { "nordible-mail-server" }
$NetworkName = if ($CADDY_NETWORK) { $CADDY_NETWORK } else { "nordible-net" }

$LocalTar = "nordiblemail.tar"
$RemoteTar = "/tmp/nordiblemail.tar"

Write-Host "⏳ Step 1: Building Docker image locally..." -ForegroundColor Cyan
docker build -t nordiblemail:latest .
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ Docker build failed."
    exit $LASTEXITCODE
}

Write-Host "⏳ Step 2: Saving Docker image to tar archive..." -ForegroundColor Cyan
if (Test-Path $LocalTar) { Remove-Item $LocalTar }
docker save -o $LocalTar nordiblemail:latest
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ Docker save failed."
    exit $LASTEXITCODE
}

Write-Host "⏳ Step 3: Transferring image and .env to $SshHost via SCP..." -ForegroundColor Cyan
scp -P $SshPort $LocalTar "${SshUser}@${SshHost}:${RemoteTar}"
if (Test-Path ".env") {
    ssh -p $SshPort "${SshUser}@${SshHost}" "mkdir -p /opt/${ContainerName}"
    scp -P $SshPort ".env" "${SshUser}@${SshHost}:/opt/${ContainerName}/.env"
}
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ SCP transfer failed."
    exit $LASTEXITCODE
}

Write-Host "⏳ Step 4: Loading image and running $ContainerName on $SshHost..." -ForegroundColor Cyan
$remoteScript = "docker load -i $RemoteTar && rm -f $RemoteTar && docker tag nordiblemail:latest ${ContainerName}:latest && docker network create ${NetworkName} || true && docker rm -f ${ContainerName} || true && docker run -d --name ${ContainerName} --restart unless-stopped --network ${NetworkName} --env-file /opt/${ContainerName}/.env -p 25:25 -p 465:465 -p 587:587 -p 993:993 -p 8080:8080 -v /opt/${ContainerName}/data:/var/lib/stalwart -v /opt/${ContainerName}/etc:/etc/stalwart ${ContainerName}:latest"

ssh -p $SshPort "${SshUser}@${SshHost}" $remoteScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "❌ Remote SSH deployment failed."
    exit $LASTEXITCODE
}

Write-Host "✅ Deployment of $ContainerName to $SshHost completed successfully!" -ForegroundColor Green

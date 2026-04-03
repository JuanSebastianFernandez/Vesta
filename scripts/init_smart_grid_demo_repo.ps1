param(
    [string]$RepoPath = "C:\Users\kidsh\Documents\Projects\Vesta\vesta_backend\demo\smart-grid-repo"
)

$ErrorActionPreference = "Stop"

function Copy-Variant([string]$Source, [string]$Destination) {
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

Set-Location $RepoPath

if (-not (Test-Path ".git")) {
    git init
    git config user.name "VESTA Demo"
    git config user.email "demo@vesta.local"
}

git checkout --detach | Out-Null

$variants = Join-Path $RepoPath "variants"

Copy-Variant (Join-Path $variants "server.baseline.py") (Join-Path $RepoPath "app\server.py")
Copy-Variant (Join-Path $variants "device_controller.baseline.py") (Join-Path $RepoPath "app\device_controller.py")
Copy-Variant (Join-Path $variants "grid_telemetry.baseline.js") (Join-Path $RepoPath "web\grid_telemetry.js")
Copy-Variant (Join-Path $variants "maintenance_agent.baseline.c") (Join-Path $RepoPath "native\maintenance_agent.c")
Copy-Variant (Join-Path $variants "safety_controller.baseline.cpp") (Join-Path $RepoPath "native\safety_controller.cpp")
if (Test-Path (Join-Path $RepoPath "app\credential_harvester.py")) {
    Remove-Item -LiteralPath (Join-Path $RepoPath "app\credential_harvester.py") -Force
}
git add .
git commit -m "baseline-clean" --allow-empty
$baselineCommit = (git rev-parse HEAD).Trim()
git update-ref refs/heads/baseline-clean $baselineCommit

Copy-Variant (Join-Path $variants "device_controller.suspicious.py") (Join-Path $RepoPath "app\device_controller.py")
Copy-Variant (Join-Path $variants "grid_telemetry.suspicious.js") (Join-Path $RepoPath "web\grid_telemetry.js")
Copy-Variant (Join-Path $variants "maintenance_agent.suspicious.c") (Join-Path $RepoPath "native\maintenance_agent.c")
Copy-Variant (Join-Path $variants "safety_controller.suspicious.cpp") (Join-Path $RepoPath "native\safety_controller.cpp")
Copy-Variant (Join-Path $variants "credential_harvester.suspicious.py") (Join-Path $RepoPath "app\credential_harvester.py")
git add .
git commit -m "suspicious-commit" --allow-empty
$suspiciousCommit = (git rev-parse HEAD).Trim()
git update-ref refs/heads/suspicious-commit $suspiciousCommit

Copy-Variant (Join-Path $variants "server.runtime_attackable.py") (Join-Path $RepoPath "app\server.py")
git add .
git commit -m "runtime-attackable" --allow-empty
$runtimeCommit = (git rev-parse HEAD).Trim()
git update-ref refs/heads/runtime-attackable $runtimeCommit

git checkout runtime-attackable
Write-Host "Smart-grid demo repo initialized with branches: baseline-clean, suspicious-commit, runtime-attackable"

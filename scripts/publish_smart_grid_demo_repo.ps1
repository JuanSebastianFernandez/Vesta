param(
    [string]$RepoPath = "C:\Users\kidsh\Documents\Projects\Vesta\vesta_backend\demo\smart-grid-repo",
    [string]$RemoteName = "origin",
    [switch]$ForceRuntimeAttackable
)

$ErrorActionPreference = "Stop"

Set-Location $RepoPath

if (-not (Test-Path ".git")) {
    throw "The path '$RepoPath' is not a Git repository."
}

$branches = @("main", "baseline-clean", "suspicious-commit")
foreach ($branch in $branches) {
    git rev-parse --verify $branch | Out-Null
    git push --set-upstream $RemoteName $branch
}

git rev-parse --verify "runtime-attackable" | Out-Null
if ($ForceRuntimeAttackable) {
    git push --force-with-lease $RemoteName runtime-attackable
}
else {
    git push --set-upstream $RemoteName runtime-attackable
}

Write-Host ""
Write-Host "Remote heads after publish:"
git ls-remote --heads $RemoteName

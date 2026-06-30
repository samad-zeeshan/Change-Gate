# Offline README demo
# Runs the agent in-process (in-memory backend) — no Docker, no network.
# Designed to be screen-recorded as a GIF.

$ErrorActionPreference = "Stop"


[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONUTF8 = "1"
$env:PYTHONWARNINGS = "ignore"  
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }  
$env:PYTHONPATH = Join-Path $root "src"

function Invoke-Case {
    param([string]$ReqId, [string]$Caption)
    Write-Host ""
    Write-Host "  $Caption" -ForegroundColor Cyan
    Write-Host "  > python -m change_gate.agent.main $ReqId" -ForegroundColor DarkGray
    Write-Host ""
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $py -m change_gate.agent.main $ReqId 2>$null
    $ErrorActionPreference = $prev
    Start-Sleep -Seconds 2
}

Invoke-Case -ReqId "cr-001" -Caption "1) Low-risk flag flip in dev -> auto-approved"
Invoke-Case -ReqId "cr-003" -Caption "2) Prod change during a freeze window -> denied outright"

Write-Host ""
Write-Host "  Same engine, opposite outcomes - both decided deterministically and audited." -ForegroundColor Green
Write-Host ""

<#
.SYNOPSIS
    Wake a sleeping Render free-tier instance and block until it actually serves.

.DESCRIPTION
    The free plan sleeps after ~15 min idle. A scan issues hundreds of sequential
    requests; if the first one lands on a cold instance it times out, and red-prompt
    scores that as the target having RESISTED the attack. The scan then completes
    looking clean while being full of false negatives. Run this immediately before
    every scan and every demo.

    PowerShell twin of scripts/warm.sh. Exits 0 only once /health has answered 200
    twice in a row.

.EXAMPLE
    .\scripts\warm.ps1 https://redprompt-target.onrender.com

.EXAMPLE
    $env:RP_TARGET_URL = "https://redprompt-target.onrender.com"; .\scripts\warm.ps1
#>
param(
    [string]$BaseUrl = $env:RP_TARGET_URL
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    Write-Error "usage: .\scripts\warm.ps1 <base-url>   (or set `$env:RP_TARGET_URL)"
    exit 2
}
$BaseUrl = $BaseUrl.TrimEnd('/')

$deadline = (Get-Date).AddSeconds(180)
$streak = 0
$lastStatus = "no response"

Write-Host "warming $BaseUrl " -NoNewline
while ((Get-Date) -lt $deadline) {
    $code = 0
    try {
        # 30s, not the default: a cold Render container legitimately takes 30-60s
        # to answer its first request. Anything shorter reports a false failure.
        $resp = Invoke-WebRequest -Uri "$BaseUrl/health" -TimeoutSec 30 -UseBasicParsing
        $code = [int]$resp.StatusCode
    } catch {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        $lastStatus = $_.Exception.Message
    }

    if ($code -eq 200) {
        $streak++
        # Two in a row: one 200 can come from the proxy before the app is really ready.
        if ($streak -ge 2) {
            Write-Host " awake"
            (Invoke-WebRequest -Uri "$BaseUrl/health" -TimeoutSec 30 -UseBasicParsing).Content
            exit 0
        }
    } else {
        $streak = 0
        if ($code -ne 0) { $lastStatus = "HTTP $code" }
    }

    Write-Host "." -NoNewline
    Start-Sleep -Seconds 3
}

Write-Host ""
Write-Error "FAILED: $BaseUrl/health did not return 200 within 180s (last: $lastStatus)."
Write-Host "Do not start a scan - a cold target produces false negatives, not errors." -ForegroundColor Yellow
exit 1

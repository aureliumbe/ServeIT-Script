[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\ServeIT.json'),
    [string]$JsonPath = (Join-Path $PSScriptRoot (Join-Path 'reports' ("ServeIT-report_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))),
    [string]$HtmlPath,
    [switch]$GroupByServer,
    [string]$ImportJsonResult,
    [string[]]$ComputerName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'src\ServeIT.Core.psm1') -Force

if ([string]::IsNullOrWhiteSpace($HtmlPath)) {
    $HtmlPath = [System.IO.Path]::ChangeExtension($JsonPath, '.html')
}

if ($GroupByServer -and [string]::IsNullOrWhiteSpace($HtmlPath)) {
    throw '-GroupByServer can only be used when -HtmlPath is set.'
}

if ($ImportJsonResult) {
    if ([string]::IsNullOrWhiteSpace($HtmlPath)) {
        throw '-ImportJsonResult requires -HtmlPath.'
    }
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $report = Get-Content -LiteralPath $ImportJsonResult -Raw | ConvertFrom-Json
} else {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $checks = @(Get-SVChecks -RootPath (Join-Path $PSScriptRoot 'checks') -Configuration $config)
    $context = New-SVContext -Configuration $config -ComputerName $ComputerName -ShowProgress:($VerbosePreference -eq 'Continue')
    $results = @(Invoke-SVChecks -Checks $checks -Context $context)
    $report = New-SVReport -Context $context -Results $results

    $parent = Split-Path -Parent $JsonPath
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
}

if ($HtmlPath) {
    $htmlParent = Split-Path -Parent $HtmlPath
    if (-not (Test-Path -LiteralPath $htmlParent)) { New-Item -ItemType Directory -Path $htmlParent -Force | Out-Null }
    ConvertTo-SVHtml -Report $report -Configuration $config -GroupByServer:$GroupByServer | Set-Content -LiteralPath $HtmlPath -Encoding UTF8
}

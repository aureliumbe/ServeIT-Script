Set-StrictMode -Version Latest

function New-SVResult {
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][bool]$Passed,
        [string]$Message = '',
        [bool]$Warning = $false
    )
    [pscustomobject]@{
        Item = $Item
        Value = $Value
        Passed = $Passed
        Message = $Message
        Warning = $Warning
    }
}

function Write-SVResult {
    param([Parameter(Mandatory)]$Result, [string]$ComputerName = '-')
    $server = $ComputerName
    $part = [string]$Result.Item
    if ($ComputerName -ne '-' -and $part.StartsWith("${ComputerName}:")) {
        $part = $part.Substring($ComputerName.Length + 1)
    } elseif ($ComputerName -ne '-' -and $part -eq $ComputerName) {
        $part = 'Result'
    } elseif ($part.Contains(':')) {
        $parts = $part.Split(':', 2)
        $server = $parts[0]
        $part = $parts[1]
    }
    $status = if ($Result.Warning) { 'WARNING' } elseif ($Result.Passed) { 'PASS' } else { 'FAIL' }
    $value = if ($Result.Value -is [string] -or $Result.Value -is [ValueType]) {
        [string]$Result.Value
    } else {
        $Result.Value | ConvertTo-Json -Compress -Depth 10
    }
    $color = if ($Result.Warning) { 'Yellow' } elseif ($Result.Passed) { 'Green' } else { 'Red' }
    Write-Host ('{0,-24} {1,-42} {2,-50} {3}' -f $server, $part, $value, $status) -ForegroundColor $color
}

function Write-SVCheckHeading {
    param([Parameter(Mandatory)][string]$Check, $Configuration)
    $displayName = $Check
    if ($null -ne $Configuration) {
        $configuredCheck = @($Configuration.checks | Where-Object id -eq $Check | Select-Object -First 1)
        if ($configuredCheck -and $configuredCheck.name) { $displayName = [string]$configuredCheck.name }
    }
    Write-Host ''
    Write-Host "=== $displayName ===" -ForegroundColor Cyan
    Write-Host ('{0,-24} {1,-42} {2,-50} {3}' -f 'Server', 'Onderdeel', 'Waarde', 'Resultaat') -ForegroundColor DarkCyan
}

function Test-SVRpcConnection {
    param([Parameter(Mandatory)][string]$ComputerName)
    try {
        Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop | Select-Object -First 1 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Test-SVPSRemoting {
    param([Parameter(Mandatory)][string]$ComputerName)
    try {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock { $true } -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Get-SVExchangeServerNames {
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry "LDAP://CN=Microsoft Exchange,CN=Services,CN=Configuration,$global:LdapDomain"
        if (-not $root.distinguishedName) { return @() }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher $root
        $searcher.Filter = 'objectClass=msExchExchangeServer'
        $servers = @($searcher.FindAll() | ForEach-Object {
            $classes = $_.Properties.objectclass
            if ("$classes" -eq 'top server msExchExchangeServer') { [string]$_.Properties.cn }
        })
        $servers
    } catch {
        @()
    }
}

function New-SVContext {
    param([Parameter(Mandatory)]$Configuration, [string[]]$ComputerName, [switch]$ShowProgress)
    if ($ShowProgress) { $VerbosePreference = 'Continue' }
    $discovered = $false
    if ($ComputerName) {
        $names = @($ComputerName)
    } elseif ($Configuration.serverDiscovery.enabled) {
        try {
            $adParameters = @{ Filter = { (OperatingSystem -like '*server*') -and (Enabled -eq $true) }; ErrorAction = 'Stop' }
            if ($Configuration.serverDiscovery.searchBase) { $adParameters.SearchBase = $Configuration.serverDiscovery.searchBase }
            $names = @(Get-ADComputer @adParameters | Select-Object -ExpandProperty Name)
            $discovered = $true
        } catch {
            $names = @($Configuration.computers)
        }
    } else {
        $names = @($Configuration.computers)
    }
    $reachable = @()
    $unreachable = @()
    $rpcUnreachable = @()
    $psRemotingStatus = @()
    $serverTotal = [math]::Max($names.Count, 1)
    $serverIndex = 0
    Write-Progress -Id 1 -Activity 'ServeIT connectivity checks' -Status 'Preparing server connectivity checks' -PercentComplete 0
    foreach ($name in $names) {
        $serverIndex++
        $percent = [math]::Floor(($serverIndex / $serverTotal) * 100)
        Write-Progress -Id 1 -Activity 'ServeIT connectivity checks' -Status "[$name] Checking ICMP reachability" -PercentComplete $percent
        if (Test-Connection -ComputerName $name -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            Write-Progress -Id 1 -Activity 'ServeIT connectivity checks' -Status "[$name] Checking WMI/RPC connectivity" -PercentComplete $percent
            if (Test-SVRpcConnection -ComputerName $name) {
                $reachable += $name
                Write-Progress -Id 1 -Activity 'ServeIT connectivity checks' -Status "[$name] Checking PowerShell remoting" -PercentComplete $percent
                $remotingAvailable = Test-SVPSRemoting -ComputerName $name
                $psRemotingStatus += [pscustomobject]@{
                    ComputerName = $name
                    Available = $remotingAvailable
                    Reason = if ($remotingAvailable) { '' } else { 'PowerShell remoting unavailable' }
                }
            } else {
                $rpcUnreachable += [pscustomobject]@{ ComputerName = $name; Reason = 'RPC server unavailable' }
                Write-Warning "Excluding $name from server checks: RPC server is unavailable."
            }
        } else {
            $unreachable += [pscustomobject]@{ ComputerName = $name; Reason = 'Unreachable' }
        }
    }
    $global:hklm = 2147483650
    $global:Verbose = $false
    $global:WINS_Servers = @()
    $global:Servers = @($reachable | ForEach-Object {
        $remoting = $psRemotingStatus | Where-Object ComputerName -eq $_ | Select-Object -First 1
        [pscustomobject]@{ ServerName = $_; PSRemoting = [bool]$remoting.Available; Tests = @() }
    })
    try {
        $global:domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $global:LdapDomain = ([adsisearcher]'').SearchRoot.Path.Split('/')[2]
    } catch {
        $global:domain = $null
        $global:LdapDomain = $null
    }
    Write-Progress -Id 1 -Activity 'ServeIT connectivity checks' -Status 'Checking Active Directory for Exchange servers' -PercentComplete 100
    $exchangeCandidates = @(Get-SVExchangeServerNames)
    $exchangeServers = @($exchangeCandidates | ForEach-Object {
        $candidate = $_
        $reachable | Where-Object { $_ -eq $candidate -or $_ -like "${candidate}.*" } | Select-Object -First 1
    } | Where-Object { $_ })
    Write-Progress -Id 1 -Activity 'ServeIT connectivity checks' -Status 'Connectivity checks complete' -Completed
    [pscustomobject]@{
        RunId = [guid]::NewGuid().ToString()
        StartedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        ComputerName = @($reachable)
        DiscoveredComputerName = @($names)
        UnreachableServers = @($unreachable)
        RpcUnreachableServers = @($rpcUnreachable)
        PSRemotingStatus = @($psRemotingStatus)
        ExchangeServers = @($exchangeServers)
        DiscoveryMode = if ($discovered) { 'ActiveDirectory' } elseif ($ComputerName) { 'Explicit' } else { 'ConfiguredFallback' }
        Warnings = @([pscustomobject]@{
            Code = 'DefragCheck'
            Message = if ($Configuration.defragCheckEnabled) { 'Defrag analysis will be executed; this can take some time.' } else { 'Defrag analysis will not be executed.' }
            Enabled = [bool]$Configuration.defragCheckEnabled
        }) + @($psRemotingStatus | Where-Object { -not $_.Available } | ForEach-Object {
            [pscustomobject]@{
                Code = 'PSRemotingUnavailable'
                ComputerName = $_.ComputerName
                Message = 'PowerShell remoting is unavailable; remoting-dependent checks will report Not Available.'
                Enabled = $false
            }
        })
        Configuration = $Configuration
    }
}

function Get-SVChecks {
    param([Parameter(Mandatory)][string]$RootPath, [Parameter(Mandatory)]$Configuration)
    $enabled = @($Configuration.checks | Where-Object { $_.enabled -and ($Configuration.defragCheckEnabled -or $_.id -ne 'Get-SVDefragAnalysis') })
    $enabledIds = @($enabled | ForEach-Object { $_.id })
    $allFiles = @(Get-ChildItem -LiteralPath $RootPath -Filter '*.ps1')
    $files = @($allFiles | Where-Object { $enabledIds -contains $_.BaseName })
    $configured = @($Configuration.checks)
    $configuredIds = @($configured | ForEach-Object { $_.id })
    $helperIds = @($Configuration.helperFunctions)
    foreach ($file in @($allFiles | Where-Object { $_.BaseName -notin $configuredIds -and $_.BaseName -notin $helperIds })) {
        Write-Warning "Check script '$($file.Name)' is not registered in the configuration and will be skipped."
    }
    foreach ($entry in @($configured | Where-Object { -not $_.enabled -and $_.id -in $allFiles.BaseName })) {
        Write-Warning "Check '$($entry.name)' ($($entry.id)) is disabled in the configuration and will be skipped."
    }
    $allFileNames = @($allFiles | ForEach-Object { $_.BaseName })
    foreach ($entry in @($enabled | Where-Object { $_.id -notin $allFileNames })) {
        Write-Warning "Configured check '$($entry.name)' ($($entry.id)) has no matching script and will be skipped."
    }
    $priorityIds = @($Configuration.priorityChecks)
    $remaining = @($enabled | Where-Object { $_.id -notin $priorityIds })
    $ordered = foreach ($id in $priorityIds) {
        $entry = $enabled | Where-Object id -eq $id | Select-Object -First 1
        if (-not $entry) { continue }
        $file = $files | Where-Object BaseName -eq $entry.id | Select-Object -First 1
        if ($file) {
            [pscustomobject]@{ Id = $entry.id; Name = $entry.name; Path = $file.FullName }
        }
    }
    $ordered
    foreach ($entry in $remaining) {
        $file = $files | Where-Object BaseName -eq $entry.id | Select-Object -First 1
        if ($file) {
            [pscustomobject]@{ Id = $entry.id; Name = $entry.name; Path = $file.FullName }
        }
    }
}

function Invoke-SVChecks {
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Checks, [Parameter(Mandatory)]$Context)
    $compatibilityPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\ServeIT.LegacyCompat.ps1'
    if (Test-Path -LiteralPath $compatibilityPath) { . $compatibilityPath }
    Get-ChildItem -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'checks') -Filter '*.ps1' |
        ForEach-Object { . $_.FullName }
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($check in $Checks) {
        Write-SVCheckHeading $check.Id $Context.Configuration
        $invoke = Get-Command -Name $check.Id -ErrorAction SilentlyContinue
        if (-not $invoke) {
            $item = New-SVResult $check.Id 'Registration' 'Function not found' $false 'Check function could not be loaded'
            $all.Add($item)
            continue
        }
        $isDomainCheck = @($Context.Configuration.domainChecks) -contains $check.Id
        $isExchangeCheck = @($Context.Configuration.exchangeChecks) -contains $check.Id
        $targets = if ($isDomainCheck) { @($null) } elseif ($isExchangeCheck) { @($Context.ExchangeServers) } else { @($Context.ComputerName) }
        foreach ($computer in $targets) {
            try {
                $usesContext = $invoke.Parameters.ContainsKey('Context')
            if ($isDomainCheck) { $items = & $invoke 6>$null }
            elseif ($usesContext) { $items = & $invoke -Context $Context -ComputerName $computer 6>$null }
            else { $items = & $invoke $computer 6>$null }
            $items = ConvertTo-SVResults -Check $check.Id -ComputerName $(if ($computer) { $computer } else { 'Domain' }) -Items $items
            }
            catch { $items = New-SVResult $check.Id 'Execution' $_.Exception.Message $false 'Check execution failed' }
            foreach ($item in @($items)) {
                $all.Add($item)
                Write-SVResult $item -ComputerName $computer
            }
        }
    }
    @($all)
}

function ConvertTo-SVResults {
    param([Parameter(Mandatory)][string]$Check, [Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)]$Items)
    $legacy = @(@($Items) | Where-Object { $_.PSObject.Properties.Name -contains 'testResult' })
    if ($legacy.Count -gt 0) {
        foreach ($test in $legacy) {
            foreach ($item in @($test.testResult)) {
                New-SVResult $Check "${ComputerName}:$($item.testItem)" $item.testValue ([bool]$item.testResultaat)
            }
        }
        return
    }
    foreach ($item in @($Items)) {
        $isResult = $item.PSObject.Properties.Name -contains 'Check' -and
            $item.PSObject.Properties.Name -contains 'Item' -and
            $item.PSObject.Properties.Name -contains 'Passed'
        if ($isResult) {
            $item
        } elseif ($item -is [string] -or $item -is [ValueType]) {
            New-SVResult $Check $ComputerName $item $true
        } elseif ($null -ne $item) {
            New-SVResult $Check $ComputerName $item $true
        }
    }
}

function New-SVReport {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][AllowEmptyCollection()][array]$Results)
    $checkNames = [ordered]@{}
    foreach ($check in @($Context.Configuration.checks)) {
        if ($check.id -and $check.name) { $checkNames[$check.id] = $check.name }
    }
    [pscustomobject]@{
        SchemaVersion = 1
        RunId = $Context.RunId
        StartedAtUtc = $Context.StartedAtUtc
        FinishedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        ComputerName = $Context.ComputerName
        DiscoveredComputerName = $Context.DiscoveredComputerName
        UnreachableServers = $Context.UnreachableServers
        RpcUnreachableServers = $Context.RpcUnreachableServers
        PSRemotingStatus = $Context.PSRemotingStatus
        ExchangeServers = $Context.ExchangeServers
        DiscoveryMode = $Context.DiscoveryMode
        Warnings = @($Context.Warnings)
        CheckNames = [pscustomobject]$checkNames
        Summary = [pscustomobject]@{
            Total = @($Results).Count
            Passed = @($Results | Where-Object Passed).Count
            Failed = @($Results | Where-Object { -not $_.Passed }).Count
        }
        Results = @($Results)
    }
}

function ConvertTo-SVHtml {
    param([Parameter(Mandatory)]$Report, $Configuration, [switch]$GroupByServer)
    $rows = [System.Text.StringBuilder]::new()
    $escape = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }
    $results = @($Report.Results)
    $rpcUnreachable = @(if ($Report.PSObject.Properties.Name -contains 'RpcUnreachableServers') { @($Report.RpcUnreachableServers) })
    $script:SVHtmlServers = @()
    if ($Report.PSObject.Properties.Name -contains 'ComputerName') {
        $script:SVHtmlServers = @($Report.ComputerName)
    }
    $script:SVHtmlCheckNames = @{}
    if ($Report.PSObject.Properties.Name -contains 'CheckNames' -and $null -ne $Report.CheckNames) {
        foreach ($property in @($Report.CheckNames.PSObject.Properties)) {
            if ($null -ne $property.Name) { $script:SVHtmlCheckNames[$property.Name] = [string]$property.Value }
        }
    }
    if ($null -ne $Configuration) {
        foreach ($check in @($Configuration.checks)) {
            if ($check.id -and $check.name) { $script:SVHtmlCheckNames[$check.id] = [string]$check.name }
        }
    }
    $groups = if ($GroupByServer) {
        $results | Group-Object { Get-SVResultServer $_ }
    } else {
        $results | Group-Object Check
    }
    foreach ($group in $groups) {
        $objectValues = @($group.Group | Where-Object { $null -ne $_.Value -and ($_.Value -is [pscustomobject] -or $_.Value -is [hashtable]) })
        $allValuesAreObjects = $objectValues.Count -eq @($group.Group).Count -and $objectValues.Count -gt 0
        $valueProperties = @($objectValues | ForEach-Object { $_.Value.PSObject.Properties.Name } | Sort-Object -Unique)
        $groupCheck = if ($group.Group.Count -gt 0) { [string]$group.Group[0].Check } else { [string]$group.Name }
        $heading = if ($GroupByServer) { $group.Name } else { Get-SVCheckName $groupCheck }
        $columns = if ($allValuesAreObjects -and $valueProperties.Count -gt 0) {
            @('Server', 'Item') + $valueProperties + @('Status')
        } else {
            @('Server', 'Item', 'Value', 'Status')
        }
        $headerHtml = ($columns | ForEach-Object { "<th>$(& $escape $_)</th>" }) -join ''
        $escapedHeading = & $escape $heading
        [void]$rows.AppendLine("<section class='group' data-check='$(& $escape $groupCheck)'><h2 class='check-title'>$escapedHeading</h2><table><caption>$escapedHeading</caption><thead><tr>$headerHtml</tr></thead><tbody>")
        foreach ($result in @($group.Group)) {
            $status = if ($result.Warning) { 'warning' } elseif ($result.Passed) { 'pass' } else { 'fail' }
            $statusText = if ($result.Warning) { 'WARNING' } elseif ($result.Passed) { 'PASS' } else { 'FAIL' }
            $value = if ($result.Value -is [string] -or $result.Value -is [ValueType]) { [string]$result.Value } else { $result.Value | ConvertTo-Json -Compress -Depth 10 }
            $server = Get-SVResultServer $result
            $item = Get-SVResultItem $result
            if ($allValuesAreObjects -and $valueProperties.Count -gt 0) {
                $dataCells = @($server, $item) + @($valueProperties | ForEach-Object { $result.Value.$_ })
            } else {
                $dataCells = @($server, $item, $value)
            }
            $cellHtml = ($dataCells | ForEach-Object { "<td>$(& $escape $_)</td>" }) -join ''
            $cellHtml += "<td><span class='status $status'>$statusText</span></td>"
            [void]$rows.AppendLine("<tr>$cellHtml</tr>")
        }
        [void]$rows.AppendLine('</tbody></table></section>')
    }
    $failed = [int]$Report.Summary.Failed
    $total = [int]$Report.Summary.Total
    $warningItems = @()
    if ($Report.PSObject.Properties.Name -contains 'Warnings') { $warningItems += @($Report.Warnings) }
    $warningItems += @($rpcUnreachable | ForEach-Object {
        $entry = $_
        $computerName = if ($entry -and $entry.PSObject.Properties.Name -contains 'ComputerName') { $entry.ComputerName } else { $null }
        [pscustomobject]@{
            Code = 'RPCUnavailable'
            ComputerName = $computerName
            Message = 'Server was excluded because RPC was unavailable.'
        }
    })
    $warningNotice = if ($warningItems.Count -gt 0) {
        $warningHtml = foreach ($warning in $warningItems) {
            $hasCode = $warning -and $warning.PSObject.Properties.Name -contains 'Code' -and $warning.Code
            $hasMessage = $warning -and $warning.PSObject.Properties.Name -contains 'Message' -and $warning.Message
            $hasComputerName = $warning -and $warning.PSObject.Properties.Name -contains 'ComputerName' -and $warning.ComputerName
            $label = if ($hasCode) { "[$($warning.Code)] " } else { '' }
            $message = if ($hasMessage) { [string]$warning.Message } else { 'Unknown warning' }
            $server = if ($hasComputerName) { " ($([string]$warning.ComputerName))" } else { '' }
            "<li>$(& $escape ($label + $message + $server))</li>"
        }
        "<div class='notice'><strong>Warnings</strong><ul>$($warningHtml -join '')</ul></div>"
    } else { '' }
    $rpcNotice = $warningNotice
    $logoPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\ServeIT.Logo.svg'
    $logo = if (Test-Path -LiteralPath $logoPath) {
        (Get-Content -LiteralPath $logoPath -Raw) -replace '<svg ', '<svg width="240.4" height="60.8" style="max-width:100%;height:auto" '
    } else {
        ''
    }
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ServeIT report</title>
<style>
:root{color-scheme:dark;--bg:#071521;--panel:#102637;--line:#29465b;--text:#edf6fb;--muted:#a7bdc9;--blue:#0089cb;--pale:#a0c1dc;--red:#ff7b72;--green:#6ee7b7;--warning:#ffd166}*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#071521,#0b2535);color:var(--text);font:14px Segoe UI,Arial,sans-serif}.top{padding:28px max(24px,calc((100% - 1400px)/2));border-bottom:1px solid var(--line);background:#071521}.brand{display:flex;align-items:center;gap:18px}.mark{width:64px;height:64px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#95bbe4,#0089cb 45%,#00558a);border:2px solid var(--pale)}h1{margin:0;font-size:28px;letter-spacing:.04em}.meta{color:var(--muted);margin-top:6px}.summary{display:flex;gap:12px;flex-wrap:wrap;margin-top:24px}.metric{background:var(--panel);border:1px solid var(--line);padding:12px 16px;min-width:120px}.metric strong{display:block;font-size:22px}.notice{margin-top:18px;padding:12px 14px;border:1px solid var(--warning);color:var(--warning);background:rgba(255,209,102,.08)}.content{max-width:1400px;margin:28px auto;padding:0 24px}.group{margin-bottom:28px}.group h2{font-size:18px;border-left:4px solid var(--blue);padding-left:10px}table{width:100%;border-collapse:collapse;background:rgba(16,38,55,.85);border:1px solid var(--line)}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--pale);font-weight:600}td:nth-child(3){word-break:break-word}.status{font-weight:700}.pass{color:var(--green)}.fail{color:var(--red)}@media(max-width:720px){th:nth-child(1),td:nth-child(1){display:none}th,td{padding:9px 7px;font-size:12px}.content{padding:0 12px}}
</style></head><body><header class="top"><div class="brand"><div class="mark" aria-label="ServeIT logo"></div><div><h1>ServeIT</h1><div class="meta">Infrastructure health report</div></div></div><div class="summary"><div class="metric"><strong>$total</strong>Total tests</div><div class="metric"><strong>$([int]$Report.Summary.Passed)</strong>Passed</div><div class="metric"><strong>$failed</strong>Failed</div><div class="metric"><strong>$(& $escape $Report.FinishedAtUtc)</strong>Completed UTC</div></div></header><main class="content">$rows</main></body></html>
 </style></head><body><header class="top"><div class="brand"><div class="mark" aria-label="ServeIT logo"></div><div><h1>ServeIT</h1><div class="meta">Infrastructure health report</div></div></div><div class="summary"><div class="metric"><strong>$total</strong>Total tests</div><div class="metric"><strong>$([int]$Report.Summary.Passed)</strong>Passed</div><div class="metric"><strong>$failed</strong>Failed</div><div class="metric"><strong>$(& $escape $Report.FinishedAtUtc)</strong>Completed UTC</div></div>$rpcNotice</header><main class="content">$rows</main></body></html>
"@
    $html.Replace('<div class="mark" aria-label="ServeIT logo"></div>', $logo)
}

function Get-SVResultServer {
    param([Parameter(Mandatory)]$Result)
    $item = [string]$Result.Item
    $knownServers = @($script:SVHtmlServers)
    $match = $knownServers | Where-Object { $item -eq $_ -or $item.StartsWith("${_}:") } | Select-Object -First 1
    if ($match) { return $match }
    if ($item.Contains(':')) { return $item.Split(':', 2)[0] }
    return $item
}

function Get-SVResultItem {
    param([Parameter(Mandatory)]$Result)
    $item = [string]$Result.Item
    $server = Get-SVResultServer $Result
    if ($item -eq $server) { return 'Result' }
    if ($item.StartsWith("${server}:")) { return $item.Substring($server.Length + 1) }
    return $item
}

function Get-SVCheckName {
    param([AllowEmptyString()][AllowNull()][string]$Check)
    if ([string]::IsNullOrWhiteSpace($Check)) { return 'Unnamed check' }
    if ($script:SVHtmlCheckNames.ContainsKey($Check)) { return $script:SVHtmlCheckNames[$Check] }
    return [string]$Check
}

Export-ModuleMember -Function New-SVResult, New-SVContext, Get-SVChecks, Invoke-SVChecks, New-SVReport, ConvertTo-SVHtml

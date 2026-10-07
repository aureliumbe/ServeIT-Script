function Get-SVCheckWindowsDnsSettingsPerNic($server, $WINS_Servers) {

    $server = $server.ToLower()
    $returnValue = @()
    $dnsServerIPs = @()
    $noReverseDnsIPs = @()
    $expectedWinsServers = @($WINS_Servers | Where-Object { $_ })

    $ns = nslookup $domain
    $nsText = [string]($ns -join ' ')
    while ($nsText.Contains(':')) {
        $nsText = $nsText.Substring($nsText.IndexOf(':') + 1)
    }
    $dnsServerIPs = @($nsText.Trim().Split(' ') | Where-Object { $_ })

    foreach ($ip in $dnsServerIPs) {
        try {
            [System.Net.Dns]::GetHostByAddress($ip) | Out-Null
        }
        catch {
            $noReverseDnsIPs += $ip
        }
    }

    $networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $server -ErrorAction Stop
    $serverShortName = $server.Split('.')[0]
    $serverFqdn = if ($server.Contains('.')) { $server } else { "$server.$($domain.name)" }
    $serverIsDomainController = @($domain.DomainControllers.name | Where-Object {
        $domainControllerName = ([string]$_).TrimEnd('.')
        $domainControllerName -ieq $serverFqdn -or $domainControllerName.Split('.')[0] -ieq $serverShortName
    }).Count -gt 0

    foreach ($network in $networks) {
        $networkName = [string]$network.Description
        if ([string]::IsNullOrWhiteSpace($networkName)) {
            $networkName = "Network adapter $($network.Index)"
        }

        $dnsServers = @($network.DNSServerSearchOrder | Where-Object { $_ })
        $invalidDnsServers = @()
        for ($index = 0; $index -lt $dnsServers.Count; $index++) {
            $dnsServer = [string]$dnsServers[$index]
            $isLastDnsServer = $index -eq ($dnsServers.Count - 1)

            if ($dnsServer -eq '127.0.0.1' -and $serverIsDomainController -and $isLastDnsServer) {
                if ($dnsServers.Count -eq 1) {
                    $invalidDnsServers += $dnsServer
                }
            }
            elseif ($dnsServer -eq '127.0.0.1' -and -not $isLastDnsServer) {
                $invalidDnsServers += $dnsServer
            }
            elseif ($dnsServerIPs -notcontains $dnsServer) {
                $invalidDnsServers += $dnsServer
            }
        }

        $dnsValue = if ($dnsServers.Count -gt 0) { $dnsServers -join ', ' } else { 'Notset' }
        if ($invalidDnsServers.Count -gt 0) {
            $dnsValue += "; invalid DNS server(s): $($invalidDnsServers -join ', ')"
        }
        $dnsPassed = $invalidDnsServers.Count -eq 0
        $returnValue += New-SVTestResult $networkName "DNS servers: $dnsValue" $dnsPassed

        $winsPrimaryServer = [string]$network.WINSPrimaryServer
        $winsSecondaryServer = [string]$network.WINSSecondaryServer
        $configuredWinsServers = @($winsPrimaryServer, $winsSecondaryServer | Where-Object { $_ })
        $winsPassed = $true
        $winsMessage = "Primary: $(if ($winsPrimaryServer) { $winsPrimaryServer } else { 'Notset' }); Secondary: $(if ($winsSecondaryServer) { $winsSecondaryServer } else { 'Notset' })"

        if ($expectedWinsServers.Count -gt 0) {
            if ($configuredWinsServers.Count -eq 0) {
                $winsPassed = $false
                $winsMessage += '; expected WINS server(s) are not configured'
            }
            else {
                $invalidWinsServers = @($configuredWinsServers | Where-Object { $expectedWinsServers -notcontains $_ })
                if ($invalidWinsServers.Count -gt 0) {
                    $winsPassed = $false
                    $winsMessage += "; unexpected WINS server(s): $($invalidWinsServers -join ', ')"
                }
            }
        }
        elseif ($configuredWinsServers.Count -gt 0) {
            $winsPassed = $false
            $winsMessage += '; no WINS servers are expected'
        }

        if ($expectedWinsServers.Count -gt 0 -or $configuredWinsServers.Count -gt 0) {
            $returnValue += New-SVTestResult $networkName "WINS servers: $winsMessage" $winsPassed
        }
    }

    $serverIP = Resolve-SVDnsName $server
    if ($serverIP -and $noReverseDnsIPs -contains $serverIP) {
        $returnValue += New-SVTestResult 'Reverse DNS' "No PTR record for IP $serverIP" $false
    }

    return New-SVTest "$server network adapters" $returnValue
}

function Get-SVIPv6Settings($comp,$DNS_Servers_IPv6_Address) {
#
# Get IPv6 NIC DNS settings
#
    $ReturnValue = @()
    $DNS_Servers = @()
    $DNS_Server_Name = ""
    $DNS_Server_Names = @()

    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0 
    $ips = @()
    $nstemp = $ns
    
    do  {        
        $pos = $nstemp.IndexOf(":")
        if ($pos -gt -1) {
            $nstemp = $nstemp.Substring($pos+1)
            }
        } while ($pos -gt -1)
    $nstemp = $nstemp.Trim()

    do  {
       if ($nstemp.split(" ")[$i].trim() -ne "") {
            $ips += $nstemp.split(" ")[$i].trim()
            }
       $i = $i +1
        } while ($i -ne ($nstemp.split(" ").count))

    foreach ($ip in $ipaddr) { 
        if ($ip.InterfaceAlias -notlike "Loopbac*") {
            $ip.ipaddress
            }
        }

    $DC_names = ($domain.DomainControllers.name).toupper() | sort
    if ($DC_Names -Contains ($comp).toupper()+"."+($domain.name).toupper() ) {
        $Continue_DNS = $false
        $Continue_LLIPv6 = $false
        $Continue_IPv4 = $false
        $NIC_DNS_Servers = @()
        $NIC_IPv4_Address = @()
        $NIC_Link_local_IPv6_Address = @()
        $DNS_IPv6 = @()

        #$ipv6_DNS = Invoke-Command -Computer $comp -ScriptBlock { netsh int ipv6 show dnsservers }
        $ipconfigall = Invoke-Command -Computer $comp -ScriptBlock {ipconfig /all}
       
        #Link-local IPv6 Address . . . . . : fe80::5c99:e044:e7c9:9242%12(Preferred)
        #IPv4 Address. . . . . . . . . . . : 192.168.254.27(Preferred)
        #DNS Servers . . . . . . . . . . . : fe80::7cb1:8180:bce2:fbda%8
       
        foreach ($line in $ipconfigall) {
            if ($line.Trim() -like 'Connection-specific DNS Suffix*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Description*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Physical Address*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'DHCP Enabled*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Autoconfiguration Enabled*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Link-local IPv6 Address*') {
                $Continue_DNS = $false ; $Continue_IPv4 = $false
                If ($line.Trim() -like 'Link-local IPv6 Address*' -OR $Continue_LLIPv6) { $NIC_Link_local_IPv6_Address += (($line.substring(39)).Trim()).split("(")[0] }
                ELSE { $NIC_Link_local_IPv6_Address += ($line.Trim()).split("(")[0] }
                $Continue_LLIPv6 = $true                
                }
            if ($line.Trim() -like 'IPv4 Address*') {
                $Continue_DNS = $false ; $Continue_LLIPv6 = $false
                If ($line.Trim() -like 'IPv4 Address*' -OR $Continue_IPv4) { $NIC_IPv4_Address += (($line.substring(39)).Trim()).split("(")[0] }
                ELSE { $NIC_IPv4_Address += ($line.Trim()).split("(")[0] }
                $Continue_IPv4 = $true                
                }
            if ($line.Trim() -like 'Subnet Mask*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Default Gateway*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'DHCPv6 IAID*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'DHCPv6 Client DUID*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'NetBIOS over Tcpip*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ( ($line.Trim() -like 'DNS Servers*') -OR $Continue_DNS) {
                $Continue_LLIPv6 = $false ; $Continue_IPv4 = $false
                If ($line.Trim() -like 'DNS Servers*') { $NIC_DNS_Servers += ($line.substring(39)).Trim() }
                ELSE { $NIC_DNS_Servers += $line.Trim() }
                $Continue_DNS = $true                
                }
            }
        
        foreach ($item in $NIC_DNS_Servers) {
                IF ( ($item -ne "127.0.0.1") -AND ($item -ne "::1") -AND ($IPS -NotContains $item) ) { $DNS_IPv6 += $item }
                }

        if ( ($NIC_Link_local_IPv6_Address.length -gt 0) -AND ($DNS_IPv6.length -gt 0) ) {
            foreach ($item in $NIC_Link_local_IPv6_Address) {
                if ($DNS_IPv6 -Contains $item) {
                    $ReturnMsg = "Link-local IPv6 Address '" + $item+ "' is in the IPv6 NIC DNS Settings: '"+$DNS_IPv6+"'"
                    $ReturnValue += New-SVTestResult "IPv6 NIC DNS Settings" $ReturnMsg $true
                    }
                else {
                    $ReturnMsg = "Link-local IPv6 Address '" + $item+ "' is NOT in the IPv6 NIC DNS Settings: '"+$DNS_IPv6+"'"
                    $ReturnValue += New-SVTestResult "IPv6 NIC DNS Settings" $ReturnMsg $false
                    }
                }
            }
        elseif ($NIC_Link_local_IPv6_Address.length -eq 0) {
            $ReturnMsg = "IPv6 disabled"
            $ReturnValue += New-SVTestResult "IPv6 NIC DNS Settings" $ReturnMsg $true
            }
        else {
            $ReturnMsg = "No IPv6 address set on NIC"
            $ReturnValue += New-SVTestResult "IPv6 NIC DNS Settings" $ReturnMsg $false
            }

        }
return New-SVTest "IPv6 NIC DNS Settings on DC's" $ReturnValue
}

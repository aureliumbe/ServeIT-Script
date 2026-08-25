function Get-SVAllServersIPv6Address {
#
# Get Configured IPv6 DNS servers
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
    foreach ($DNS_Server in $IPS) {
        $DNS_Server_Name = nslookup $DNS_Server
        foreach ($line in $DNS_Server_Name) {
            if ($Line -like "Name:*") {
                $DNS_Server_Names += (($Line.split(":")[1].trim()).split(".")[0]).toupper()
                }
            }
        }

            $NIC_DNS_Servers = @()
            $NIC_IPv4_Address = @()
            $NIC_Link_local_IPv6_Address = @()
            $DNS_IPv6 = @()
                    
        foreach ($DNS_Server_Name in $DNS_Server_Names ) {
            $Continue_DNS = $false
            $Continue_LLIPv6 = $false
            $Continue_IPv4 = $false

            #$ipv6_DNS = Invoke-Command -Computer $comp -ScriptBlock { netsh int ipv6 show dnsservers }
            $ipconfigall = Invoke-Command -Computer $DNS_Server_Name -ScriptBlock {ipconfig /all}
       
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
                    If ($line.Trim() -like 'Link-local IPv6 Address*' -OR $Continue_LLIPv6) {
                        $NIC_Link_local_IPv6_Address += (($line.substring(39)).Trim()).split("(")[0]
                        }
                    ELSE {
                        $NIC_Link_local_IPv6_Address += ($line.Trim()).split("(")[0]
                        }
                    $Continue_LLIPv6 = $true                
                    }
                if ($line.Trim() -like 'IPv4 Address*') {
                    $Continue_DNS = $false ; $Continue_LLIPv6 = $false
                    If ($line.Trim() -like 'IPv4 Address*' -OR $Continue_IPv4) {
                        $NIC_IPv4_Address += (($line.substring(39)).Trim()).split("(")[0]
                        }
                    ELSE {
                        $NIC_IPv4_Address += ($line.Trim()).split("(")[0]
                        }
                    $Continue_IPv4 = $true                
                    }
                if ($line.Trim() -like 'Subnet Mask*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'Default Gateway*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'DHCPv6 IAID*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'DHCPv6 Client DUID*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'NetBIOS over Tcpip*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ( ($line.Trim() -like 'DNS Servers*') -OR $Continue_DNS) {
                    $Continue_LLIPv6 = $false ; $Continue_IPv4 = $false
                    If ($line.Trim() -like 'DNS Servers*') {
                        $NIC_DNS_Servers += ($line.substring(39)).Trim()
                        }
                    ELSE {
                        $NIC_DNS_Servers += $line.Trim()
                        }
                    $Continue_DNS = $true                
                    }
                }        
        }
    
return $NIC_Link_local_IPv6_Address
}

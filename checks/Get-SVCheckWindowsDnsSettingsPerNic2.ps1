function Get-SVCheckWindowsDNSSettingsPerNIC2($server) {
    $server=$server.ToLower()
    $ReturnValue = @()
    $ReturnMsg = ""

    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0
    $ips = @()
    $dcs = @()
    $nstemp = $ns    
    $No_Reverse_DNS_Zone = ""
    $No_Reverse_DNS_IP = ""
    $ServerIPs = ""

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

    foreach ($item in $ips) {
        try {
            $temp_dc = [System.Net.Dns]::GetHostbyAddress($item)
            #write-host $temp_dc.HostName+"  <-> "$item
            $dcs += $temp_dc.HostName
            }
        catch {
            #echo "No reverse IP Zone for ip $item"
            $No_Reverse_DNS_Zone = "No Reverse IP Zone/PTR Record for ip $item"
            $No_Reverse_DNS_IP = $item
            }
        }
    
    $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $server -ErrorAction Stop

    foreach($Network in $Networks) {
        $pos=1
        $DNS_Servers_Ok=$true
        $DNSServers = $Network.DNSServerSearchOrder

        foreach ($DNSServer in $DNSServers) {
            if ( ( ($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -eq $pos) ) -and ($domain.DomainControllers.name.Contains($server) ) ) {                 
                    #echo "127.0.0.1 is the last DNS server in the list on a DC = OK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $true)
                    }
            elseif (($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -ne $pos)) {
                    #echo "127.0.0.1 is not the last DNS server in the list = NOK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }
            elseif ($ips.Contains($DNSServer)) {
                    #echo $DNSServer" is a known AD DNS server = OK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $true)
                    }
            elseif (-not($ips.Contains($DNSServer))) {
                    #echo $DNSServer" is not a known AD DNS server = NOK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }

            if ($IPs.Contains($No_Reverse_DNS_IP)) {
                if ( ( ([System.Net.Dns]::GetHostAddresses($server)).ipaddresstostring -eq $No_Reverse_DNS_IP) -and ( ([System.Net.Dns]::GetHostAddresses($server)).addressfamily -eq "InterNetwork") ) {
                    #echo $No_Reverse_DNS_Zone + " = NOK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }
                }

            $pos=$pos+1
            }

        if ( ($No_Reverse_DNS_Zone.length -eq 0) ) {
            $ReturnMsg = $DNSServers
            }
        elseif ( ($No_Reverse_DNS_Zone.length -ne 0) -and ( ($domain.DomainControllers.ipaddress).Contains( ([System.Net.Dns]::GetHostAddresses($server)).ipaddresstostring ) -and ( ([System.Net.Dns]::GetHostAddresses($server)).addressfamily -eq "InterNetwork") ) ) {
            $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
            $ReturnMsg = $DNSServers + $No_Reverse_DNS_Zone
            }

        $NetworkName = $Network.Description
        $WINSPrimaryserver = $Network.WINSPrimaryServer 
        $WINSSecondaryserver = $Network.WINSSecondaryserver 
        If(!$DNSServers) {
            $PrimaryDNSServer = "Notset"
            $SecondaryDNSServer = "Notset"
            }
        elseif($DNSServers.count -eq 1) {
            $PrimaryDNSServer = $DNSServers[0]
            $SecondaryDNSServer = "Notset"
            }
            else
                {
                $PrimaryDNSServer = $DNSServers[0]
                $SecondaryDNSServer = $DNSServers[1]
                }        
        }

    if ($DNS_Servers_Ok) {
        write-host "DNS Config Ok"        
        $ReturnValue += New-SVTestResult "Server DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        }
    else {
        write-host "DNS Config Not Ok"
        $ReturnValue += New-SVTestResult "Server DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        }

return New-SVTest "Server DNS Settings per NIC" $ReturnValue
}

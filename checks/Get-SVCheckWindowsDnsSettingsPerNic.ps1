function Get-SVCheckWindowsDnsSettingsPerNic($server, $WINS_Servers) {

    $server=$server.ToLower()
    $ReturnValue = @()
    $ReturnMsg = ""
    $ReturnMsg1 = @()    

    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0
    $ips = @()
    $dcs = @()
    $No_Reverse_DNS_IP = @()

    $nstemp = $ns    
    $No_Reverse_DNS_Zone = ""
    #$No_Reverse_DNS_IP = ""
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

    foreach ($item in $domain.DomainControllers.name) {
        #echo $item.toupper()
        $dcs += $item.toupper()
        }

    foreach ($item in $ips) {
        try {
            $temp_dc = [System.Net.Dns]::GetHostbyAddress($item)
            #write-host $temp_dc.HostName+"  <-> "$item
            #$dcs += $temp_dc.HostName
            }
        catch {
            #echo "No reverse IP Zone for ip $item"
            #$No_Reverse_DNS_Zone = "No Reverse IP Zone/PTR Record for ip "
            $No_Reverse_DNS_IP += $item
            }
        }

    $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $server -ErrorAction Stop

    $DNS_Servers_Ok=$true
    $WINS_Servers_Ok=$true
    $DNS_Server=""
    $ReturnMsg2 = @()
    $ReturnMsg3 =""

    foreach($Network in $Networks) {
        $pos=1
        if ($Network.DNSServerSearchOrder.length -gt 0) {
            $DNSServers = $DNSServers + $Network.DNSServerSearchOrder
            }

        foreach ($DNSServer in $DNSServers) {
            $ServerIsDC = $False
            foreach ($item in $domain.DomainControllers.name.toupper()) {
                if ( ($domain.DomainControllers.name.toupper()).Contains($server.ToUpper()+"."+$domain.name.toupper()) ) {
                    $ServerIsDC = $True
                    }
                }

            if ( ( ($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -eq $pos) -and ($pos -ne 1) ) -and ($ServerIsDC) ) {
                    #echo "127.0.0.1 is the last DNS server in the list on a DC = OK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $true)
                    }
            elseif ( ( ($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -eq $pos) -and ($pos -eq 1) ) -and ($ServerIsDC) ) {
                    #echo "127.0.0.1 is the first and only DNS server in the list on a DC = NOK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }
            elseif (($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -ne $pos)) {
                    #echo "127.0.0.1 is not the last DNS server in the list = NOK"
                    $ReturnMsg2 += $DNSServer
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }
            elseif ($ips.Contains($DNSServer)) {
                    #echo $DNSServer" is a known AD DNS server = OK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $true)
                    }
            elseif (-not($ips.Contains($DNSServer))) {
                    #echo $DNSServer" is not a known AD DNS server = NOK"
                    $ReturnMsg2 += $DNSServer
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }

            #foreach ($DNSServer in $DNSServers) 
            $pos=$pos+1
            }

        $NetworkName = $Network.Description
        if ($NetworkName -contains "iDRAC Virtual NIC*") {
            echo "iDRAC NIC"
            }
        $WINSPrimaryserver = $Network.WINSPrimaryServer 
        $WINSSecondaryserver = $Network.WINSSecondaryserver 

        if ($WINS_Servers.Count -gt 0 -and $WINSPrimaryserver.length -eq 0 -and $WINSSecondaryserver.length -eq 0) {
            #echo "Wrong Config, WINS Servers exist but no WINS configured on NIC Settings"
            $WINS_Servers_Ok=($WINS_Servers_Ok -band $false)
            }
        elseif ($WINS_Servers.Count -gt 0 -and ($WINSPrimaryserver.length -ne 0 -or $WINSSecondaryserver.length -ne 0) ) {
                #echo "2 WINS Servers configured on NIC Settings"
                $WINS_Servers_Ok=($WINS_Servers_Ok -band $true)    
                #}
                if ($WINSPrimaryserver.length -ne 0) {
                    if ($WINS_Servers.Contains($WINSPrimaryserver)) {
                        #echo "NIC Primary WINS Server setting is a valid WINS Server"
                        $WINS_Servers_Ok=($WINS_Servers_Ok -band $true)
                        }
                    else {
                        #echo "NIC Primary WINS Server setting is not a valid WINS Server"
                        $WINS_Servers_Ok=($WINS_Servers_Ok -band $false)
                        }
                    }

                if ($WINSSecondaryserver.length -ne 0) {
                    if ($WINS_Servers.Contains($WINSSecondaryserver)) {
                        #echo "NIC Secondary WINS Server setting is a valid WINS Server"
                        $WINS_Servers_Ok=($WINS_Servers_Ok -band $true)
                        }
                    else {
                        #echo "NIC Secondary WINS Server setting is not a valid WINS Server"
                        $WINS_Servers_Ok=($WINS_Servers_Ok -band $false)
                        }
                    }
                }
        elseif ($WINS_Servers.Count -eq 0 -and ($WINSPrimaryserver.length -ne 0 -or $WINSSecondaryserver.length -ne 0) ) {
                #echo "No WINS Servers, but NIC has at least one WINS Server configured"
                $WINS_Servers_Ok=($WINS_Servers_Ok -band $false)
                }

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
        # ENd of the foreach($Network in $Networks)
        }

    $ReturnMsg = $DNSServers
    $ReturnMsg1 += $WINSPrimaryserver
    $ReturnMsg1 += $WINSSecondaryserver

    if ($DNS_Servers_Ok) {
        #write-host "DNS and WINS Config Ok"
        #echo $DNSServers + $WINSPrimaryserver + $WINSSecondaryserver
        $ReturnValue += New-SVTestResult "DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        }
    else {
        #write-host "DNS Or WINS Config Not Ok"
        #echo $DNSServers + $WINSPrimaryserver + $WINSSecondaryserver
        $ReturnMsg3 = " -> Invalid DNS Server(s): " + $ReturnMsg2
        $ReturnValue += New-SVTestResult "DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        $ReturnValue += New-SVTestResult "DNS Settings per NIC" $ReturnMsg3 $DNS_Servers_Ok
        }    

    if ($WINS_Servers.Count -gt 0) {
        if ( ($WINSPrimaryserver -eq $null) -and ($WINSSecondaryserver -eq $null) ) {
            #write-host "No Primary or Secondary WINS Configured"
            $ReturnValue += New-SVTestResult "WINS Settings per NIC" "No Primary or Secondary WINS Configured" $false
            }
        elseif( ($WINSPrimaryserver -ne $null) -or ($WINSSecondaryserver -ne $null) ) {
            #write-host "Primary or Secondary WINS Configured"
            $ReturnValue += New-SVTestResult "WINS Settings per NIC" $ReturnMsg1 $true
            }
        }
    else {
        #write-host "There are NO WINS Servers"
        if ( ($WINSPrimaryserver.length -ne 0) -or ($WINSSecondaryserver.length -ne 0) ) {
            #write-host "No WINS Servers, but NIC has at least one WINS Server configured"
            $ReturnMsg3 = " -> No WINS Servers, but NIC has a WINS Server(s): " + $ReturnMsg1
            $ReturnValue += New-SVTestResult "WINS Settings per NIC" $ReturnMsg3 $false
            }

        }

    #}

    #$ServerIP = (Resolve-DnsName $server).ipaddress
    $ServerIP = Resolve-SVDnsName $server
    #if ($No_Reverse_DNS_IP -eq $ServerIP) {
    if ( $No_Reverse_DNS_IP.Contains($ServerIP) ) {
        $No_Reverse_DNS_Zone = "No PTR Record for ip "
        #$No_Reverse_DNS_IP = $ServerIP
        $DNS_Servers_Ok=$false
        $ReturnMsg = $No_Reverse_DNS_Zone+$No_Reverse_DNS_IP
        $ReturnValue += New-SVTestResult "DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        }

return New-SVTest "DNS and WINS Settings per NIC" $ReturnValue
}

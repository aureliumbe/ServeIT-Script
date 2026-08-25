function Get-SVServersConfig(){
    $ReturnValue = @()
    $ReturnMsg = ""
    $SearchBase="CN=CONFIGURATION,"+$LdapDomain
    
    try {
        $Auth_DHCP_Servers = Get-ADObject -SearchBase $SearchBase -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" | sort
        }
    catch {echo "No Permission to Read DHCP AD_Object"}

    foreach ($DHCP_Server in $Auth_DHCP_Servers) {
        $DHCP_Scopes = ""
        $DHCP_Servername = ((($DHCP_Server.DistinguishedName).split(","))[0]).Split("=")[1]
        if ($DHCP_Servername -notlike "*DhcpRoot*") {
            if((Test-Connection -ComputerName $DHCP_Servername -Count 1 -Quiet) -eq $false) {
                }
            else{
                $DHCP_Server_Dump = Invoke-Command -ComputerName $DHCP_Servername -ScriptBlock {netsh dhcp server dump all}
                foreach ($item in $DHCP_Server_Dump) {
                    if ($item -match ("Dhcp Server \\\\$DHCP_Servername add scope") -gt 0) {
                        $pos = $item.indexof("add scope ")
                        if ($pos -gt 0) {
                            #echo $item.substring($pos+10)
                            $Server_Scope_Subnet = ($item.substring($pos+10)).split(" """)[0]
                            $Server_Scope_SubnetMask = ($item.substring($pos+10)).split(" """)[1]
                            #$temp_item = $item.substring($pos+10+$scope_subnet.length+1+$Scope_SubnetMask.length+1)
                            $Server_Scope_Name = ($item.substring($pos+10)).split("""")[1]
                            $Server_Scope_Description = ($item.substring($pos+10)).split("""")[3]
                            }

                        $ReturnMsg = "$DHCP_Servername.ToUpper() DHCP Scope: $Server_Scope_Subnet $Server_Scope_SubnetMask $Server_Scope_Name $Server_Scope_Description"
                        $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                        #
                        # End of if ($item -match ("Dhcp Server \\\\$DHCP_Servername add scope") -gt 0)
                        #
                        }

                    if ($item -match ("Dhcp Server \\\\$DHCP_Servername set optionvalue") -gt 0) {
                        # 3 "Router" IPADDRESS 1 comment="Array of router addresses ordered by preference" 0.0.0.0
                        # 4 "Time Server" IPADDRESS 1 comment="Array of time server addresses, by preference" 0.0.0.0
                        # 5 "Name Servers" IPADDRESS 1 comment="Array of name servers [IEN 116], by preference" 0.0.0.0
                        # 6 "DNS Servers" IPADDRESS 1 comment="Array of DNS servers, by preference" 0.0.0.0
                        #15 "DNS Domain Name" STRING 0 comment="DNS Domain name for client resolutions" ""
                        #44 "WINS/NBNS Servers" IPADDRESS 1 comment="NBNS Address(es) in priority order" 0.0.0.0
                        #46 "WINS/NBT Node Type" BYTE 0 comment="0x1 = B-node, 0x2 = P-node, 0x4 = M-node, 0x8 = H-node" 0
                        #51 "Lease" DWORD 0 comment="Client IP address lease time in seconds" 0
                        $pos = $item.indexof("set optionvalue 3 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_Router = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option:  3 Router: $DhcpServerOption_Router"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 4 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_TimeServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option:  4 Timeservers: $DhcpServerOption_TimeServers"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 5 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_NameServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option:  5 Nameservers: $DhcpServerOption_NameServers"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 6 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_DNSServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option:  6 DNS Servers: $DhcpServerOption_DNSServers"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 15 STRING")
                        if ($pos -gt 0) {
                            $DhcpServerOption_DomainName = ($item.substring($pos+26))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option: 15 DomainName: $DhcpServerOption_DomainName"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 44 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_WINSServers = ($item.substring($pos+29))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option: 44 WINS Servers: $DhcpServerOption_WINSServers"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 46 BYTE")
                        if ($pos -gt 0) {
                            $DhcpServerOption_WINSNodeType = ($item.substring($pos+24))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option: 46 WINS Node Type: $DhcpServerOption_WINSNodeType"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 51 DWORD")
                        if ($pos -gt 0) {
                            $DhcpServerOption_DHCPLease = ($item.substring($pos+25))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option: 51 DHCP Lease(s): $DhcpServerOption_DHCPLease"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        #
                        # End of if ($item -match ("Dhcp Server \\\\$DHCP_Servername set optionvalue") -gt 0)
                        #
                        }


                    if ($item -match ("Dhcp Server \\\\$DHCP_Servername scope $Server_Scope_Subnet set optionvalue") -gt 0) {
                        # 3 "Router" IPADDRESS 1 comment="Array of router addresses ordered by preference" 0.0.0.0
                        # 4 "Time Server" IPADDRESS 1 comment="Array of time server addresses, by preference" 0.0.0.0
                        # 5 "Name Servers" IPADDRESS 1 comment="Array of name servers [IEN 116], by preference" 0.0.0.0
                        # 6 "DNS Servers" IPADDRESS 1 comment="Array of DNS servers, by preference" 0.0.0.0
                        #15 "DNS Domain Name" STRING 0 comment="DNS Domain name for client resolutions" ""
                        #44 "WINS/NBNS Servers" IPADDRESS 1 comment="NBNS Address(es) in priority order" 0.0.0.0
                        #46 "WINS/NBT Node Type" BYTE 0 comment="0x1 = B-node, 0x2 = P-node, 0x4 = M-node, 0x8 = H-node" 0
                        #51 "Lease" DWORD 0 comment="Client IP address lease time in seconds" 0                        
                        $pos = $item.indexof("set optionvalue 3 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_Router = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  3 Router: $DhcpScopeOption_Router"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 4 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_TimeServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  4 Timeservers: $DhcpScopeOption_TimeServers"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 5 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_NameServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  5 Nameservers: $DhcpScopeOption_NameServers"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 6 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_DNSServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  6 DNS Servers: $DhcpScopeOption_DNSServers"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 15 STRING")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_DomainName = ($item.substring($pos+26))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  7 DomainName: $DhcpScopeOption_DomainName"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 44 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_WINSServers = ($item.substring($pos+29))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option: 44 WINS Servers: $DhcpScopeOption_WINSServers"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 46 BYTE")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_WINSNodeType = ($item.substring($pos+24))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option: 46 WINS Node Type: $DhcpScopeOption_WINSNodeType"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 51 DWORD")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_DHCPLease = ($item.substring($pos+25))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option: 51 DHCP Lease(s): $DhcpScopeOption_DHCPLease"
                            $ReturnValue += New-SVTestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        #
                        # End of if ($item -match ("Dhcp Server \\\\$DHCP_Servername scope $Server_Scope_Subnet set optionvalue") -gt 0)
                        #
                        }
                    }

                #
                # End of if((Test-Connection -ComputerName $DHCP_Servername -Count 1 -Quiet) -eq $true)
                #
                }

            #
            # End of if ($DHCP_Servername -notlike "*DhcpRoot*")
            #
            }

        #
        # foreach ($DHCP_Server in $Auth_DHCP_Servers)
        #
        }
        
return New-SVTest "DHCP Server Config" $ReturnValue
}

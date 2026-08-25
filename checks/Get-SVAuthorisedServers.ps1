function Get-SVAuthorisedServers(){
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
            $FoundDhcp = $False
            try {
                $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $DHCP_Servername -ErrorAction SilentlyContinue
                foreach ($proc in $processes) {
                    if ($proc.name -eq "svchost.exe" ) {
                        $ProcCMD = $proc.CommandLine
                        if ($ProcCMD -ne $null) {
                            If ($ProcCMD.ToUpper().contains('DHCP') ) {
                                $FoundDhcp = $True
                                }
                            }
                        }
                    }
                }
            catch{}

          If ($FoundDhcp) {
                $ReturnValue += New-SVTestResult $DHCP_Servername.ToUpper() "DHCP Server Responding" $true
                }
            else{
                $ReturnValue += New-SVTestResult $DHCP_Servername.ToUpper() "DHCP Server Not Responding" $false
                }
            }
        }
             
               
return New-SVTest "DHCP Authorized Servers" $ReturnValue
}

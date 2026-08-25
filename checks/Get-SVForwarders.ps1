function Get-SVForwarders(){
$ReturnValue = @()
#   DNS server settings
#   DGO: Only test on Accessable DC's
#
    #$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    foreach ($dc in ($domain.DomainControllers.name | sort) ) {
        $dnsconfig = Invoke-Command -ComputerName $dc -ScriptBlock {dnscmd /exportsettings ; type "C:\Windows\System32\dns\DnsSettings.txt"}
        #$dnsforwarders.IPAddress
        foreach ($line in $dnsconfig) {
            if ($line -like "*Forwarders=ADDRLISt:*") {
                #echo $line
                $DNSfwdrs = $line.split(":")[1]
                }
            }
        $DNSfwdrs = $DNSfwdrs.replace(",",", ")
        $ReturnMsg = $dc.ToUpper() + " -> " + $DNSfwdrs
        #echo $ReturnMsg
        $ReturnValue += New-SVTestResult "DNS Forwarders" $ReturnMsg $true
        }

return New-SVTest "DNS Forwarders" $ReturnValue
}

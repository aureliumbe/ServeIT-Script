function Get-SVFirewallProfile($server) {
    $OS_Major_Version = (Get-WmiObject win32_operatingsystem -Computer $server).version.split(".")[0]
    $OS_Minor_Version = (Get-WmiObject win32_operatingsystem -Computer $server).version.split(".")[1]
    $OS_Version = $OS_Major_Version+$OS_Minor_Version

    if ( [int]$OS_Version -gt 52 ) {

        $ReturnMsg = ""
        $ReturnValue = @()
        $FW_Profiles_Status = @()

        $ScriptBlock = { (Get-NetFirewallProfile -PolicyStore ActiveStore | select name,enabled) }
        $ScriptBlock = { (Get-NetFirewallProfile | select name,enabled) }
        $FW_Profiles_Status = Invoke-Command -ComputerName $server -ScriptBlock $ScriptBlock -ErrorAction Ignore
        $FW_All_Profiles_Status = ($FW_Profiles_Status | where { $_.Enabled -eq $True } | measure ).Count -eq 3

        if ($FW_All_Profiles_Status) {
            #Write-Host "Windows Firewall is Compliant"
            #write-host $Profile.name"Profile is Enabled"
            $ReturnMsg = "Domain, Private & Public Profiles are enabled"
            $ReturnValue += New-SVTestResult "Windows Adv. Firewall" $ReturnMsg $true
            }
        else {
            foreach ($Profile in $FW_Profiles_Status) {
                IF (-NOT $Profile.Enabled) {
                    #write-host $Profile.name"Profile is Disabled"
                    $ReturnMsg = $Profile.name+" Profile is Disabled"
                    $ReturnValue += New-SVTestResult "Windows Adv. Firewall" $ReturnMsg $false
                    }
                ELSE {
                    #write-host $Profile.name"Profile is Enabled"
                    $ReturnMsg = $Profile.name+" Profile is Enabled"
                    $ReturnValue += New-SVTestResult "Windows Adv. Firewall" $ReturnMsg $true                    
                    }
                }
            }
        }
     else {
            $ReturnMsg = "not available in this OS"
            $ReturnValue += New-SVTestResult "Windows Adv. Firewall" $ReturnMsg $true
            }       
            
 return New-SVTest "Windows Adv. Firewall" $ReturnValue
}

function Get-SVNla($comp) {

    $ReturnValue = @()
    
    $RDP_NLA = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $comp -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
    
    if ($RDP_NLA) {
        $ReturnMsg = "Enabled"
        $ReturnValue += New-SVTestResult "RDP NLA" $ReturnMsg $true
        }
    else {
        $ReturnMsg = "Disabled"
        $ReturnValue += New-SVTestResult "RDP NLA" $ReturnMsg $false
        }
    
    Return New-SVTest "RDP Network Level Authentication" $ReturnValue
}

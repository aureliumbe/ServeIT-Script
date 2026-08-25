function Get-SVCheckSetting($comp){
#
# Enable-NetAdapterRss –Name *
#
# This setting is found on the Advanced tab of the device’s Device Manager property sheet or in the Adapter Settings panel in Intel PROSet ACU.
# To change this setting in Windows PowerShell, use the Set-IntelNetAdapterSetting cmdlet.
# Set-IntelNetAdapterSetting -Name "<adapter_name>" -DisplayName "Receive Side Scaling" -DisplayValue "Enabled"
# 
$ReturnValue = @()
$RSS_ENABLED = $false

$RSS_STATE = Invoke-Command -ComputerName $comp -ScriptBlock {netsh interface tcp show global}

foreach ($item in $RSS_STATE) {
    if ($item -match 'Receive-Side Scaling.*') {
       #echo $item.Contains(": enabled")
       $RSS_ENABLED = $true
       }
    }

if ($RSS_ENABLED) {
    $ReturnValue += New-SVTestResult "Receive-Side Scaling" "Enabled" $true
        }
else {
    $ReturnValue += New-SVTestResult "Receive-Side Scaling" "Disabled" $false
    }

return New-SVTest "Receive-Side Scaling" $ReturnValue
}

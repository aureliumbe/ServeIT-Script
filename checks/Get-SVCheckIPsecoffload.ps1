function Get-SVCheckIPsecoffload($comp){
#
# Enable IPsec TOv2 with PowerShell cmdlet: Enable-NetAdapterIPsecOffload, or in the network adapter Advanced Properties.
#
$ReturnValue = @()
$IPsecoffload = ""

$IPsecoffload = Invoke-Command -ComputerName $comp -ScriptBlock {(Get-NetAdapterIPsecOffload).Enabled}

if ($IPsecoffload) {
    $ReturnValue += New-SVTestResult "IPsecoffload (if supported)" "Enabled" $true
        }
else {
    $ReturnValue += New-SVTestResult "IPsecoffload (if supported)" "Disabled" $false
    }

return New-SVTest "IPsecoffload" $ReturnValue
}

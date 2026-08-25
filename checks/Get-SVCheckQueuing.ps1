function Get-SVCheckQueuing($comp){
$ReturnValue = @()

$VMQueuing = Invoke-Command -ComputerName $comp -ScriptBlock {Get-NetAdapterVmq -Name "*" | Where-Object -FilterScript { $_.Enabled }}

if ($VMQueuing) {
    $ReturnValue += New-SVTestResult "VM Queuing (1gb NIC?)" "Enabled" $false  
    }
else {
    $ReturnValue += New-SVTestResult "VM Queuing (1gb NIC?)" "Disabled" $true
    }

return New-SVTest "VM Queuing" $ReturnValue
}

function Get-SVCheckPowerPlan($comp){
#
# COntrol Panel -> Power Options -> High Performance
#
$ReturnValue = @()
$High_Perf_Plan_Active=$false

$Power_Plans = get-wmiobject -class "win32_PowerPlan" -namespace "root\cimv2\power" -computername $comp -ErrorAction Continue

foreach ($Power_Plan in $Power_Plans) {
    if ($Power_Plan.IsActive) {
        #Write-host $comp" Power Plan:"($Power_Plan.ElementName)
        if ($Power_Plan.ElementName -eq "High Performance") {
            $High_Perf_Plan_Active = $true
            }
        }
    }

    if ($High_Perf_Plan_Active) {
        $ReturnValue += New-SVTestResult "High Performance Power Plan" "Enabled" $High_Perf_Plan_Active
        }
    else {
        $ReturnValue += New-SVTestResult "High Performance Power Plan" "Disabled" $High_Perf_Plan_Active
        }


return New-SVTest "High Performance Power Plan" $ReturnValue
}

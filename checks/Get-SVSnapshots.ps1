Function Get-SVSnapshots($server){
    $ReturnValue = @()

<# On Error "Hyper-V encountered an error trying to access an object on computer 'xxx-xxx-xx' because the object was not found...."
   Run the following command to rebuild the WMI components for virtualization
   MOFCOMP %SYSTEMROOT%\System32\WindowsVirtualization.V2.mof
#>

    # Get the Hyper-V feature and store it in $hyperv
    $hyperv = Invoke-Command -ComputerName $server -ScriptBlock {Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online} -ErrorAction Continue

    # Check if Hyper-V is already enabled.
    if($hyperv.State -eq "Enabled") {

        $vmsnapshots = Invoke-Command -ComputerName $server -ScriptBlock {
            $vms = Get-VM | select vmName
            foreach ($vm in $vms) {
                Get-Vmsnapshot -VMname $vm.VMName
                }
            }

        if ($vmsnapshots -eq $null) {
            $ReturnMsg = "None "
            $ReturnValue += New-SVTestResult "Hyper-V Snapshots" $ReturnMsg $true
            }
        else {
            foreach ($vmsnapshot in $vmsnapshots) {
                if ($vmsnapshot.ParentSnapshotName -eq $null) {
                    $ReturnMsg = "Snapshot " + $vmsnapshot.name + " - Type: " + $vmsnapshot.SnapshotType
                    }
                else {
                    $ReturnMsg = "Snapshot " + $vmsnapshot.name + " - Type: " + $vmsnapshot.SnapshotType + " - Parent: " + $vmsnapshot.ParentSnapshotName
                    }
                    $year = $vmsnapshot.CreationTime.Year
                    $month = $vmsnapshot.CreationTime.Month
                    $day = $vmsnapshot.CreationTime.Day
                    $year1 = "{0:D4}" -f $year
                    $month1 = "{0:D2}" -f $month
                    $day1 = "{0:D2}" -f $day
                    $LastModDay=$year1+$month1+$day1
                    $Diff1="{0:D8}" -f (Get-Date -UFormat "%Y%m%d")
                    $Diff2="{0:D8}" -f $LastModDay
                    $Diff0=$Diff1-$Diff2
                    if ($Diff0 -gt 7) {
                        $ReturnValue += New-SVTestResult "Hyper-V Snapshots" $ReturnMsg $false
                        }
                    else {
                        $ReturnValue += New-SVTestResult "Hyper-V Snapshots" $ReturnMsg $true
                        }
                }            
            }
        } 
    else {
        $ReturnValue += New-SVTestResult "Hyper-V Snapshots" "Not Installed" $true
        }    
  
return New-SVTest "Hyper-V Lingering Snapshots" $ReturnValue
}

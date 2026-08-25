function Get-SVVeeamEndpointBackup($comp) {
$file = ""
$filename = ""
$filepath = ""
$ReturnValue = @()
  
$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%Veeam.Endpoint.Service%'" -ErrorAction Continue
if ($processes -eq $null) {
    $ReturnValue += New-SVTestResult "Veeam Endpoint Backup" "Not Installed" $true
    return New-SVTest "Veeam Endpoint Backup" $ReturnValue
    }
else {
    $Filename = $Processes.ExecutablePath    
    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename

    $ReturnValue += New-SVTestResult "Veeam Endpoint Backup" "Version: $FileVersion Installed" $true
    return New-SVTest "Veeam Endpoint Backup" $ReturnValue
    }

}

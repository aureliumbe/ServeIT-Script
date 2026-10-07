function Get-SVCheckCacheDb($comp){
$ReturnValue = @()

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'cservice.exe'" -ErrorAction Continue
if ($null -eq $processes) 
    {
    #echo "Caché Database Not Installed"
    $ReturnValue += New-SVTestResult "Cache Database" "Not Detected" $true
    return New-SVTest "Cache Database" $ReturnValue
    }
else {
    $Filename = $Processes.ExecutablePath
    #$FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Filename).FileVersion
    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename
    
    $ReturnValue += New-SVTestResult "Caché Database" "Version: $FileVersion Installed" $true    
    }
return New-SVTest "Cache Database" $ReturnValue
}

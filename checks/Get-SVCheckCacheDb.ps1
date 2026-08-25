function Get-SVCheckCacheDb($comp){
$ReturnValue = @()

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'cservice.exe'" -ErrorAction Continue
if ($processes -eq $null) 
    {
    #echo "Caché Database Not Installed"
    $ReturnValue += New-SVTestResult "Caché Database" "Not Installed" $true
    return New-SVTest "Caché Database" $ReturnValue
    }
else {
    $Filename = $Processes.ExecutablePath
    #$FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Filename).FileVersion
    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename
    
    $ReturnValue += New-SVTestResult "Caché Database" "Version: $FileVersion Installed" $true    
    }
return New-SVTest "Caché Database" $ReturnValue
}

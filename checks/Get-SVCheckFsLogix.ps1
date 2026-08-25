function Get-SVCheckFsLogix($comp){
#
# Check FSlogix version
# https://learn.microsoft.com/en-us/fslogix/how-to-install-fslogix#download-fslogix
#
$ReturnValue = @()
$hklm = 2147483650

$FSLogixAppsVersion_key = "SOFTWARE\FSLogix\Apps\"
$FSLogixAppsEnabled_key = "SOFTWARE\FSLogix\Profiles\"
$FSLogixAppsVersion_item = "InstallVersion"
$FSLogixAppsEnabled_item = "Enabled"
$FSLogixAppsVersion_Value = ""
$FSLogixAppsEnabled_Value = ""


$process = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'frxsvc.exe'" -ErrorAction Continue
if ($process -ne $null) {
    Try {
        $FSLogix_Apps_Latest_Version = ( (Invoke-WebRequest "https://community.chocolatey.org/packages/fslogix").content )
        $VersionIndex = $FSLogix_Apps_Latest_Version.indexof("FSLogix Apps Agent ")
        #$FSLogixLatestVersion = $FSLogix_Apps_Latest_Version.substring($VersionIndex,100)
        $FSLogix_Apps_Latest_Version = ($FSLogix_Apps_Latest_Version.substring($VersionIndex,100)).split(" ")[3].split("<")[0]
        }
    Catch {
        $FSLogix_Apps_Latest_Version = ""
        Write-Host "Invoke-Webrequest is not available in this OS/Powershell Version - Module 'Check_FSLogix'." -ForegroundColor Red | Out-Default
        }

    $Filename = $process.ExecutablePath
    $FSLogixAppsVersion_Value = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename

    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp

    $FSLogixAppsEnabled_Value = $wmi.GetDWORDValue($hklm, $FSLogixAppsEnabled_key, $FSLogixAppsEnabled_item)
    $FSLogixAppsEnabled_Value = $FSLogixAppsEnabled_Value.uValue

    IF ($FSLogix_Apps_Latest_Version.trim() -gt $FSLogixAppsVersion_Value.trim()) {
        IF ($FSLogixAppsEnabled_Value -eq "1") {
            $FSLogix_Result = "Enabled, version: $FSLogixAppsVersion_Value installed, $FSLogix_Apps_Latest_Version available"
            $ReturnValue += New-SVTestResult "FSLogix Apps" $FSLogix_Result $false
            }
        ELSE {
            $FSLogix_Result = "Disabled, version: $FSLogixAppsVersion_Value installed, $FSLogix_Apps_Latest_Version available"
            $ReturnValue += New-SVTestResult "FSLogix Apps" $FSLogix_Result $false
            }
        }
    ELSE {
       IF ($FSLogixAppsEnabled_Value -eq "1") {
            $FSLogix_Result = "Enabled, version: $FSLogixAppsVersion_Value installed"
            $ReturnValue += New-SVTestResult "FSLogix Apps" $FSLogix_Result $true
            }
        ELSE {
            $FSLogix_Result = "Disabled, version: $FSLogixAppsVersion_Value installed"
            $ReturnValue += New-SVTestResult "FSLogix Apps" $FSLogix_Result $false
            }
         }

    }
else {
    $ReturnValue += New-SVTestResult "FSLogix Apps" "Not Installed" $true    
    }
    
return New-SVTest "FSLogix Apps" $ReturnValue
}

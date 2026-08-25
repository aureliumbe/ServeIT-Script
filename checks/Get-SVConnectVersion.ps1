function Get-SVConnectVersion($comp) {
# "C:\Program Files\Microsoft Azure Active Directory Connect\AzureADConnect.exe"
# "C:\Program Files\Microsoft Azure AD Sync\UIShell\miisclient.exe"
# "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync\Microsoft.Azure.ActiveDirectory.Synchronization.Framework.dll"
# "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe"  SYNCHRONISATION PROCESS

$filename = ""
$ReturnValue = @()
$ReturnMessage = ""

# https://www.microsoft.com/en-us/download/details.aspx?id=47594

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'miiserver.exe'" -ErrorAction Continue
if ($processes -eq $null) 
    {
    #echo "Microsoft Azure AD Sync Not Installed"
    $ReturnValue += New-SVTestResult "Microsoft Azure AD Sync/Connect" "Not Installed" $true
    return New-SVTest "Microsoft Azure AD Sync/Connect" $ReturnValue
    }
else {
    $Filename = $Processes.ExecutablePath
    #$FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Filename).FileVersion
    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename
    #echo "Microsoft Azure AD Sync/Connect Installed Version: $FileVersion Installed"

    $LatestVersion = $null
    $VersionCheckPassed = $false
    try {
        $url = "https://learn.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-version-history"
        $pageContent = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
        $versionPattern = "\d+\.\d+\.\d+\.\d+"
        $versions = [regex]::Matches($pageContent.Content, "<h2[^>]*>(.*?)</h2>") | ForEach-Object {
            $match = [regex]::Match($_.Groups[1].Value, $versionPattern)
            if ($match.Success) { [version]::Parse($match.Value) }
        }
        $LatestVersion = $versions | Sort-Object -Descending | Select-Object -First 1
        if ($null -eq $LatestVersion) { throw "No current Entra Connect version was found." }
        $VersionCheckPassed = ([version]$FileVersion -eq $LatestVersion)
    }
    catch {
        $LatestVersion = "Unavailable"
    }
    
    $AAD_Sync = Invoke-Command -ComputerName $comp -ScriptBlock {Get-ADSyncScheduler}
    $AAD_NextSyncCycle = $AAD_Sync.NextSyncCycleSTartTimeInUTC
    $AAD_SyncCycleEnabled =  $AAD_Sync.SyncCycleEnabled
    $AAD_StagingModeEnabled = $AAD_Sync.StagingModeEnabled
    $AAD_SchedulerSuspended = $AAD_Sync.SchedulerSuspended
    $AAD_NextSyncCyclePolicyType = $AAD_Sync.NextSyncCyclePolicyType

    $NextSyncCycleUTCTime = Get-Date $AAD_NextSyncCycle
    $strCurrentTimeZone = (Get-WmiObject win32_timezone -computername $comp).StandardName
    $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
    $NextSyncCycleLocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($NextSyncCycleUTCTime, $TZ)

    $ReturnMessage = " + SyncEnabled:"+$AAD_SyncCycleEnabled+" - StagingEnabled:"+$AAD_StagingModeEnabled+" - SchedulerSuspended:"+$AAD_SchedulerSuspended+" - PolicyType:"+$AAD_NextSyncCyclePolicyType+" - NextSync:"+$NextSyncCycleLocalTime
    
    $ReturnValue += New-SVTestResult "Microsoft Azure AD Sync/Connect" "Installed: $FileVersion - Latest: $LatestVersion" $VersionCheckPassed
    
    if ($AAD_SyncCycleEnabled -AND (-NOT($AAD_SchedulerSuspended)) -AND (-NOT($AAD_StagingModeEnabled)) ) {
        $ReturnValue += New-SVTestResult "Microsoft Azure AD Sync/Connect" $ReturnMessage $true    
        }
    Else {
        $ReturnValue += New-SVTestResult "Microsoft Azure AD Sync/Connect" $ReturnMessage $false
        }
    
    return New-SVTest "Microsoft Azure AD Sync/Connect" $ReturnValue
    }
}

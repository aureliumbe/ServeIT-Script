function Get-SVCheckSettings($comp){
#
# get-smbserverconfiguration & set-smbserverconfiguration
#
$ReturnValue = @()
$SMB_SETTINGS = ""
$SMB_SETTINGS2 = ""
$Status = $true
$Status2 = $true

$OS_Version = Get-SVOsVersion $comp

if ( [int]$OS_Version -gt 63 -AND [INT](Get-WmiObject win32_operatingsystem -computername $comp).version.split(".")[2] -gt 17762) {
    # Windows 2019 or greater
    Echo Windows 2019/2022
    $AsynchronousCredits = 512
    $AutoDisconnectTimeout = 15
    $CachedOpenLimit = 10
    $DurableHandleV2TimeoutInSeconds = 180
    $MaxThreadsPerQueue = 20
    $Smb2CreditsMax = 8192
    $Smb2CreditsMin = 512
    }
else {
    # Windows 2003/2003R2/2008/2008R2/2016
    Echo Windows 7/8/2008/2008R2/2012/2012R2/2016
    $AsynchronousCredits = 64
    $AutoDisconnectTimeout = 0
    $CachedOpenLimit = 5
    $DurableHandleV2TimeoutInSeconds = 30
    $MaxThreadsPerQueue = 20
    $Smb2CreditsMax = 2048
    $Smb2CreditsMin = 128
    }

$SMB_FILESERVER = Invoke-Command -ComputerName $comp -ScriptBlock {get-smbserverconfiguration}

if ($SMB_FILESERVER) {
    if ($SMB_FILESERVER.AsynchronousCredits -eq $AsynchronousCredits)  {
        $SMB_SETTINGS = "AsynchronousCredits: "+$SMB_FILESERVER.AsynchronousCredits+"(ok), "
        }
    else {
        $SMB_SETTINGS = "AsynchronousCredits: "+$SMB_FILESERVER.AsynchronousCredits+"("+$AsynchronousCredits+"), "
        $Status = $false
        }
    if ($SMB_FILESERVER.MaxThreadsPerQueue -eq $MaxThreadsPerQueue)  {
        $SMB_SETTINGS = $SMB_SETTINGS + "MaxThreadsPerQueue: "+$SMB_FILESERVER.MaxThreadsPerQueue+"(ok), "
        }
    else {
        $SMB_SETTINGS = $SMB_SETTINGS + "MaxThreadsPerQueue: "+$SMB_FILESERVER.MaxThreadsPerQueue+"("+$MaxThreadsPerQueue+"), "
        $Status = $false
        }
    if ($SMB_FILESERVER.Smb2CreditsMax -eq $Smb2CreditsMax)  {
        $SMB_SETTINGS = $SMB_SETTINGS + "Smb2CreditsMax: "+$SMB_FILESERVER.Smb2CreditsMax+"(ok), "
        }
    else {
        $SMB_SETTINGS = $SMB_SETTINGS + "Smb2CreditsMax: "+$SMB_FILESERVER.Smb2CreditsMax+"("+$Smb2CreditsMax+"), "
        $Status = $false
        }
    if ($SMB_FILESERVER.Smb2CreditsMin -eq $Smb2CreditsMin)  {
        $SMB_SETTINGS = $SMB_SETTINGS + "Smb2CreditsMin: "+$SMB_FILESERVER.Smb2CreditsMin+"(ok), "
        }
    else {
        $SMB_SETTINGS = $SMB_SETTINGS + "Smb2CreditsMin: "+$SMB_FILESERVER.Smb2CreditsMin+"("+$Smb2CreditsMin+"), "
        $Status = $false
        }
    if ($SMB_FILESERVER.DurableHandleV2TimeoutInSeconds -eq $DurableHandleV2TimeoutInSeconds)  {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + " -> DurableHandleV2TimeoutInSeconds: "+$SMB_FILESERVER.DurableHandleV2TimeoutInSeconds+"(ok), "
        }
    else {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + " -> DurableHandleV2TimeoutInSeconds: "+$SMB_FILESERVER.DurableHandleV2TimeoutInSeconds+"("+$DurableHandleV2TimeoutInSeconds+"), "
        $Status2 = $false
        }
    if ($SMB_FILESERVER.AutoDisconnectTimeout -eq $AutoDisconnectTimeout)  {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + "AutoDisconnectTimeout: "+$SMB_FILESERVER.AutoDisconnectTimeout+"(ok), "
        }
    else {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + "AutoDisconnectTimeout: "+$SMB_FILESERVER.AutoDisconnectTimeout+"("+$AutoDisconnectTimeout+"), "
        $Status2 = $false
        }    
    if ($SMB_FILESERVER.CachedOpenLimit -eq $CachedOpenLimit)  {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + "CachedOpenLimit: "+$SMB_FILESERVER.CachedOpenLimit+"(ok)"
        }
    else {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + "CachedOpenLimit: "+$SMB_FILESERVER.CachedOpenLimit+"("+$CachedOpenLimit+")"
        $Status2 = $false
        }

    if ($Status) {
        $ReturnValue += New-SVTestResult "SMB Fileserver Settings" $SMB_SETTINGS $true
        }
    else {
        $ReturnValue += New-SVTestResult "SMB Fileserver Settings" $SMB_SETTINGS $false
        }
    if ($Status2) {
        $ReturnValue += New-SVTestResult "SMB Fileserver Settings" $SMB_SETTINGS2 $true
        }
    else {
        $ReturnValue += New-SVTestResult "SMB Fileserver Settings" $SMB_SETTINGS2 $false
        }
    }
else {
    $ReturnValue += New-SVTestResult "SMB Fileserver Settings" "No SMB Fileserver" $false
    }

return New-SVTest "SMB Fileserver Settings" $ReturnValue
}

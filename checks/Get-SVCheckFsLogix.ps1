function Get-SVCheckFsLogix($comp){
#
# Check FSlogix version
# https://learn.microsoft.com/en-us/fslogix/how-to-install-fslogix#download-fslogix
#
$ReturnValue = @()

$FSLogixAppsEnabled_key = "SOFTWARE\FSLogix\Profiles\"
$FSLogixAppsEnabled_item = "Enabled"
$FSLogixAppsVersion_Value = ""
$FSLogixAppsEnabled_Value = ""


$process = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'frxsvc.exe'" -ErrorAction Continue
if ($null -ne $process) {
    $PackageUri = 'https://community.chocolatey.org/api/v2/Packages?$filter=tolower(Id)%20eq%20''fslogix'''
    $PackageResponse = Invoke-RestMethod -Uri $PackageUri -Method Get -UseBasicParsing -ErrorAction Stop
    $PackageVersions = $PackageResponse.id -replace '.*Version=''(.*)''\)','$1' | ForEach-Object {[version] $_}
    $FSLogix_Apps_Latest_Version = ($PackageVersions | Sort-Object -Descending)[0]

    if ([string]::IsNullOrWhiteSpace([string]$FSLogix_Apps_Latest_Version)) {
        $FSLogix_Apps_Latest_Version = ""
    Write-Host "Unable to determine the latest FSLogix version - Module 'Check_FSLogix'." -ForegroundColor Red | Out-Default
    }

    $Filename = $process.ExecutablePath
    $FSLogixAppsVersion_Value = Invoke-Command -ComputerName $comp -scriptblock {
        param($Param1)
        try {
            $file = Get-Item -LiteralPath $Param1 -ErrorAction Stop
            $file.VersionInfo.FileVersion
        }
        catch {
            $null
        }
    } -ArgumentList $Filename

    $FSLogixAppsEnabled_Value = Invoke-Command -ComputerName $comp -scriptblock {
        param($Key, $Name)
        $path = "HKLM:\$Key"
        try {
            $value = Get-ItemProperty -Path $path -Name $Name -ErrorAction Stop
            if ($null -ne $value) {
                $value.$Name
            }
            else {
                0
            }
        }
        catch {
            0
        }
    } -ArgumentList $FSLogixAppsEnabled_key, $FSLogixAppsEnabled_item

    if ($null -eq $FSLogixAppsEnabled_Value) { $FSLogixAppsEnabled_Value = 0 }
    $FSLogixAppsEnabled_Value = [int]$FSLogixAppsEnabled_Value

    $InstalledVersion = $null
    $LatestVersion = $null
    $InstalledVersionParsed = [version]::TryParse([string]$FSLogixAppsVersion_Value, [ref]$InstalledVersion)
    $LatestVersionParsed = [version]::TryParse([string]$FSLogix_Apps_Latest_Version, [ref]$LatestVersion)

    IF ($LatestVersionParsed -and $InstalledVersionParsed -and $LatestVersion -gt $InstalledVersion) {
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

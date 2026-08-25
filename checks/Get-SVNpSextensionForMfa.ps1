function Get-SVNpSextensionForMfa($comp){
#
#$comp="hci-fs-01"
#
$NPSextensionPresent = $false
 
$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'svchost.exe'" -ErrorAction Continue
foreach ($process in $processes) {
    if ( $process.commandline -like "*C:\WINDOWS\System32\svchost.exe -k netsvcs -p -s IAS" ) {        

        # Get MFA NPSextension installed version
        $NPSextensionInstalledVersion = Invoke-command -ComputerName $comp {Get-WmiObject Win32_Product -Filter "Name like 'NPS Extension For Azure MFA'" | Select-Object -ExpandProperty Version}

        if ($NPSextensionInstalledVersion) {
            $NPSextensionPresent = $true

            # Get the latest version of MFA NPS Extension

            $web = New-Object Net.WebClient
            $NPSextensionLatestVersionRawText = (Invoke-WebRequest "https://www.microsoft.com/en-us/download/details.aspx?id=54688").content

            # Compare if the current version match the latest version

            $VersionIndex = $NPSextensionLatestVersionRawText.indexof("NpsExtnForAzureMfaInstaller.exe")
            $NPSextensionLatestVersion = $NPSextensionLatestVersionRawText.substring($VersionIndex,500)
            $VersionIndex = $NPSextensionLatestVersion.indexof("version")
            $NPSextensionLatestVersion = [regex]::Match( ($NPSextensionLatestVersion.Substring($VersionIndex,100)).split(":")[1].split(",")[0] , '[^"]+(?=")').Value
            $NPSextensionLatestVer = $NPSextensionLatestVersion.Replace(".","")
            $NPSextensionInstalledVer = $NPSextensionInstalledVersion.replace(".","")
 
            if ( $NPSextensionLatestVer -gt $NPSextensionInstalledVer ) {
                #echo "NPSextension for Azure MFA version $NPSextensionInstalledVersion is installed, nieuwe versie $NPSextensionLatestVersion beschikbaar"
                $ReturnMsg = "version: $NPSextensionInstalledVersion installed version: $NPSextensionLatestVersion available"
                $ReturnValue += New-SVTestResult "NPSextension for Azure MFA" $ReturnMsg $false
                }
            else {
                $ReturnMsg = "version: $NPSextensionInstalledVersion installed"
                $ReturnValue += New-SVTestResult "NPSextension for Azure MFA" $ReturnMsg $true
                }
            }            
        }
    }
    if ( -NOT $NPSextensionPresent ) {
        $ReturnValue += New-SVTestResult "NPSextension for Azure MFA" "Not Installed" $true
        }

return New-SVTest "NPSextension for Azure MFA" $ReturnValue
}

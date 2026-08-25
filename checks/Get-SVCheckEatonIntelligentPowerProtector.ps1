function Get-SVCheckEatonIntelligentPowerProtector($comp){
$ReturnValue = @()

# RegKey: HKLM\SOFTWARE\Wow6432Node\Eaton\IntelligentPowerProtector\InstallPath:REG_SZ:C:\Program Files (x86)\Eaton\IntelligentPowerProtector
# Process mc2.exe
# File: C:\Program Files (x86)\Eaton\IntelligentPowerProtector\mc2.exe
# DBfile: C:\Program Files (x86)\Eaton\IntelligentPowerProtector\db\mc2.db

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'mc2.exe'" -ErrorAction Continue

if ($processes -ne $null) {
    if ($processes.ExecutablePath -eq "C:\Program Files (x86)\HPE\PowerProtector\mc2.exe") {
       $Installed_SW = Invoke-Command -ComputerName $comp -ScriptBlock { (get-itemproperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') } -ErrorAction SilentlyContinue

        foreach ($item in $Installed_SW) {
            if ($item.DisplayName -ilike "*HPE Power Protector*") {
                $Eaton_Version = ($item.DisplayVersion).split(" ")[0]
                }
            }

        $Eaton_Version = $Eaton_Version -replace '(?ms).(\d.\d+.\d+).*','$1'
        $FileVer= "Version: "+$Eaton_Version+" installed"
        $ReturnValue += New-SVTestResult "Eaton IPP" $FileVer $true
        }
    else {
        $Installed_SW = Invoke-Command -ComputerName $comp -ScriptBlock { (get-itemproperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') } -ErrorAction SilentlyContinue

        foreach ($item in $Installed_SW) {
            if ($item.DisplayName -ilike "*Eaton*") {
                $Eaton_Version = ($item.DisplayVersion).split(" ")[0]
                }
            }
        $Eaton_Version = $Eaton_Version -replace '(?ms).(\d.\d+.\d+).*','$1'
        $FileVer= "Version: "+$Eaton_Version+" installed"
        $ReturnValue += New-SVTestResult "Eaton IPP" $FileVer $true
        }
    }
else {
    $ReturnValue += New-SVTestResult "Eaton IPP" "Not Installed" $true    
    }
    
return New-SVTest "Eaton Intelligent PowerProtector" $ReturnValue
}

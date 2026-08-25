function Get-SVCheckRemoteDesktopConnectionManager($comp){
$ReturnValue = @()
$Latest_Version = ""

# Info van MVK
# (Get-Process rdcman).productversion[0] -replace '^(\d+\.\d+).*','$1'
# [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try {
    $Latest_Version = (Invoke-WebRequest https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman).content -replace '(?ms).*Remote Desktop Connection Manager v(\d+\.\d+).*','$1'
    }
Catch
    {
    $Latest_Version = ""
    Write-Host "Invoke-Webrequest is not available in this OS/Powershell Version - Module 'Check_Remote_Desktop_Connection_Manager'." -ForegroundColor Red | Out-Default
    }

#$Latest_Version = (Invoke-WebRequest https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman).content -replace '(?ms).*Remote Desktop Connection Manager v(\d+\.\d+).*','$1'

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'rdcman.exe'" -ErrorAction Continue
if ($processes -eq $null) 
    {
    $Filename = "\Program Files (x86)\Microsoft\Remote Desktop Connection Manager\RDCMan.exe"    
    if ( Test-Path \\$comp\c$\$Filename ) {
        #echo "Is Installed C:\Program Files\Microsoft"        
        $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) (Get-Item $Param1).VersionInfo} -ArgumentList $Filename -ErrorAction SilentlyContinue
        if (($FileVersion.ProductVersion.Split(".")[0]+"."+$FileVersion.ProductVersion.Split(".")[1]) -lt $Latest_Version) {
            $FileVer= "Version: "+($FileVersion.ProductVersion.Split(".")[0]+"."+$FileVersion.ProductVersion.Split(".")[1])+" installed, "+$Latest_Version+" available"
            $ReturnValue += New-SVTestResult "RD Connection Manager" $FileVer $false
            }
        else {
            $FileVer= "Version: "+$FileVersion.ProductVersion+" installed"
            $ReturnValue += New-SVTestResult "RD Connection Manager" $FileVer $true
            }
        }
    else {
        $Filename = "\Program Files\Microsoft\Remote Desktop Connection Manager\RDCMan.exe"
        if ( Test-Path \\$comp\c$\$Filename ) {
            #echo "Is Installed in C:\Program Files (x86)\Microsoft"
            $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) (Get-Item $Param1).VersionInfo} -ArgumentList $Filename -ErrorAction SilentlyContinue
            if (($FileVersion.ProductVersion.Split(".")[0]+"."+$FileVersion.ProductVersion.Split(".")[1]) -lt $Latest_Version) {
                $FileVer= "Version: "+($FileVersion.ProductVersion.Split(".")[0]+"."+$FileVersion.ProductVersion.Split(".")[1])+" installed, "+$Latest_Version+" available"
                $ReturnValue += New-SVTestResult "RD Connection Manager" $FileVer $false
                }
            else {
                $FileVer= "Version: "+$FileVersion.ProductVersion+" installed"
                $ReturnValue += New-SVTestResult "RD Connection Manager" $FileVer $true
                }
            }
        else {
            $ReturnValue += New-SVTestResult "RD Connection Manager" "Not Installed" $true
            }
        }
        
    return New-SVTest "Remote Desktop Connection Manager" $ReturnValue
    }
   else {
        $Filename = $Processes.ExecutablePath
        $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename
        if (($FileVersion.Split(".")[0]+"."+$FileVersion.Split(".")[1]) -lt $Latest_Version) {
            $FileVer= "Version: "+($FileVersion.Split(".")[0]+"."+$FileVersion.Split(".")[1])+" installed, "+$Latest_Version+" available"
            $ReturnValue += New-SVTestResult "RD Connection Manager" $FileVer $false
            }
        else {
            $FileVer= "Version: "+($FileVersion.Split(".")[0]+"."+$FileVersion.Split(".")[1])+" installed"
            $ReturnValue += New-SVTestResult "RD Connection Manager" $FileVer $true
            }

    }        

return New-SVTest "Remote Desktop Connection Manager" $ReturnValue
}

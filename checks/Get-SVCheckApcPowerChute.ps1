function Get-SVCheckApcPowerChute($comp){

<#
# https://www.apc.com/shop/be/en/categories/power/uninterruptible-power-supply-ups-/ups-management/powerchute-network-shutdown/N-auzzn7
Try {
    $Latest_Version = ( (Invoke-WebRequest "https://www.apc.com/shop/be/en/categories/power/uninterruptible-power-supply-ups-/ups-management/powerchute-network-shutdown/N-auzzn7").content -replace '(?ms).*v(/d./d./d)*Windows, Linux, Windows Virtualization Installer for Nutanix/Hyper-V/SCVMM.*','$1')
    }
Catch {
       Write-Host "Invoke-Webrequest is not available in this OS/Powershell Version - Module 'Check_Eaton_IntelligentPowerProtector'." -ForegroundColor Red | Out-Default
    }
#>

$ReturnValue = @()
$hklm = 2147483650

$APC_PC_key1 = "SOFTWARE\APC\PowerChuteNetworkShutdown\"
$APC_PC_PATH_Key = "Version"
$APC_PC_PATH = ""

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'PCNS.exe'" -ErrorAction Continue
if ($processes -ne $null) {
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
    $APC_PC_PATH_Key = $wmi.GetStringValue($hklm, $APC_PC_key1, $APC_PC_PATH_Key)
    $APC_PC_PATH_Key = $APC_PC_PATH_Key.sValue
    $ReturnValue += New-SVTestResult "APC PCNS" "Version: $APC_PC_PATH_Key Installed" $true
    }
else {
    $ReturnValue += New-SVTestResult "APC PCNS" "Not Installed" $true    
    }
    
return New-SVTest "APC PowerChute Network Shutdown" $ReturnValue
}

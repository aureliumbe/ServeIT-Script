function Get-SVCheckUefiSecureboot($comp){
$ReturnValue = @()
$hklm = 2147483650

$SecureBootRegKey = "SYSTEM\CurrentControlSet\Control\SecureBoot\State\"
$SecureBootKey = "UEFISecureBootEnabled"
$SecureBootValue = ""

$wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp

$SecureBootValue = ($wmi.GetDWORDValue($hklm, $SecureBootRegKey, $SecureBootKey)).uvalue
#$SecureBootValue = Invoke-command -ComputerName $comp -ScriptBlock {Confirm-SecureBootUEFI}

if ($SecureBootValue) {
    $ReturnValue += New-SVTestResult "UEFI Secureboot" "Enabled" $true
    }
else {
    $ReturnValue += New-SVTestResult "UEFI Secureboot" "Disabled" $false
    }

return New-SVTest "UEFI Secureboot" $ReturnValue
}

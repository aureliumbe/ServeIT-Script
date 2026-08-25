function Get-SVCheck12Protocol($comp){
# https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client
# https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-tls-enforcement#powershell-script-to-check-tls-12
# TLS 1.2 was first introduced into .Net Framework 4.5.1 and 4.5.2 with the following hotfix rollups:


$ReturnValue = @()
$hklm = 2147483650

$WinHttp_RegKey64 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\"
$WinHttp_RegKey32 = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\"
$DefaultSecureProtocols_Key = "DefaultSecureProtocols"

#$TLS_1_0_Client_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\"
#$TLS_1_1_Client_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\"
$TLS_1_2_Client_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\"
#$TLS_1_2_Client_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client\"
#$TLS_1_0_Server_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\"
#$TLS_1_1_Server_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\"
$TLS_1_2_Server_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\"
#$TLS_1_2_Server_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server\"

$dotNetv4_32bit_Framework_Key = "SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
$dotNetv4_64bit_Framework_Key = "SOFTWARE\Microsoft\.NETFramework\v4.0.30319"

$SystemDefaultTlsVersions_Key = "SystemDefaultTlsVersions"
$SchUseStrongCrypto_Key = "SchUseStrongCrypto"

$TLS_DisabledByDefault_Key = "DisabledByDefault"
$TLS_Enabled_Key = "Enabled"

$WinHttp_TLS_Value64 = ""
$WinHttp_TLS_Value32 = ""
$TLS_1_0_DisabledByDefault_Value = ""
$TLS_1_0_Enabled_Value = ""
$TLS_1_1_DisabledByDefault_Value = ""
$TLS_1_1_Enabled_Value = ""
$TLS_1_2_DisabledByDefault_Value = ""
$TLS_1_2_Enabled_Value = ""

$wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp

$WinHttp_TLS_Value64 = ($wmi.GetDWORDValue($hklm, $WinHttp_RegKey64, $DefaultSecureProtocols_Key)).uvalue
$WinHttp_TLS_Value32 = ($wmi.GetDWORDValue($hklm, $WinHttp_RegKey32, $DefaultSecureProtocols_Key)).uvalue

$dNETv4_32bit_Default_TLS_Version = ($wmi.GetDWORDValue($hklm, $dotNetv4_32bit_Framework_Key, $SystemDefaultTlsVersions_Key)).uvalue
$dNETv4_32bit_StrongCrypto = ($wmi.GetDWORDValue($hklm, $dotNetv4_32bit_Framework_Key, $SchUseStrongCrypto_Key)).uvalue

$dNETv4_64bit_Default_TLS_Version = ($wmi.GetDWORDValue($hklm, $dotNetv4_64bit_Framework_Key, $SystemDefaultTlsVersions_Key)).uvalue
$dNETv4_64bit_StrongCrypto = ($wmi.GetDWORDValue($hklm, $dotNetv4_64bit_Framework_Key, $SchUseStrongCrypto_Key)).uvalue

$TLS_1_2_Client_Enabled_Value = ($wmi.GetDWORDValue($hklm, $TLS_1_2_Client_RegKey, $TLS_Enabled_Key)).uvalue
$TLS_1_2_Client_DisabledByDefault_Value = ($wmi.GetDWORDValue($hklm, $TLS_1_2_Client_RegKey, $TLS_DisabledByDefault_Key)).uvalue

$TLS_1_2_Server_Enabled_Value = ($wmi.GetDWORDValue($hklm, $TLS_1_2_Server_RegKey, $TLS_Enabled_Key)).uvalue
$TLS_1_2_Server_DisabledByDefault_Value = ($wmi.GetDWORDValue($hklm, $TLS_1_2_Server_RegKey, $TLS_DisabledByDefault_Key)).uvalue

<#
$dNETv4_32bit_Default_TLS_Version
$dNETv4_32bit_StrongCrypto
$dNETv4_64bit_Default_TLS_Version
$dNETv4_64bit_StrongCrypto
$TLS_1_2_Server_Enabled_Value
$TLS_1_2_Server_DisabledByDefault_Value
$TLS_1_2_Client_Enabled_Value
$TLS_1_2_Client_DisabledByDefault_Value
#>

if ( ($dNETv4_32bit_Default_TLS_Version -eq 1) -AND ($dNETv4_32bit_StrongCrypto -eq 1) -AND ($dNETv4_64bit_Default_TLS_Version -eq 1) -AND ($dNETv4_64bit_StrongCrypto -eq 1) -AND ($TLS_1_2_Server_Enabled_Value -eq 1) -AND ($TLS_1_2_Server_DisabledByDefault_Value -eq 0) -AND ($TLS_1_2_Client_Enabled_Value -eq 1) -AND ($TLS_1_2_Client_DisabledByDefault_Value -eq 0) ) {
    $TLS_Value = "$dNETv4_32bit_Default_TLS_Version "+"$dNETv4_32bit_StrongCrypto "+"$dNETv4_64bit_Default_TLS_Version "+"$dNETv4_64bit_StrongCrypto "+"$TLS_1_2_Server_Enabled_Value "+"$TLS_1_2_Server_DisabledByDefault_Value "+"$TLS_1_2_Client_Enabled_Value "+"$TLS_1_2_Client_DisabledByDefault_Value"
    $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
    }
else {

    if ( $dNETv4_32bit_Default_TLS_Version -ne $null ) {
        $TLS_Value = "32bit SystemDefaultTlsVersions = "+$dNETv4_32bit_Default_TLS_Version
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "32bit SystemDefaultTlsVersions"+" not found"
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $Value $false
        }


    if ( $dNETv4_32bit_StrongCrypto -ne $null ) {
        $TLS_Value = "32bit SchUseStrongCrypto = "+$dNETv4_32bit_StrongCrypto
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "32bit SchUseStrongCrypto"+" not found"
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $Value $false
        }


    if ( $dNETv4_64bit_Default_TLS_Version -ne $null ) {
        $TLS_Value = "64bit SystemDefaultTlsVersions = "+$dNETv4_64bit_Default_TLS_Version
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "64bit SystemDefaultTlsVersions"+" not found"
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $Value $false
        }

    if ( $dNETv4_64bit_StrongCrypto -ne $null ) {
        $TLS_Value = "64bit SchUseStrongCrypto = "+$dNETv4_64bit_StrongCrypto
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "64bit SchUseStrongCrypto"+" not found"
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $Value $false
        }



    if ( $TLS_1_2_Server_Enabled_Value -ne $null ) {
        $TLS_Value = "TLS 1.2 Server Enabled = "+$TLS_1_2_Server_Enabled_Value
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "TLS 1.2 Server Enabled"+" not found"
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $Value $false
        }

    if ( $TLS_1_2_Server_DisabledByDefault_Value -ne $null ) {
        $TLS_Value = "TLS 1.2 Server DisabledByDefault = "+$TLS_1_2_Server_DisabledByDefault_Value
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "TLS 1.2 Server DisabledByDefault"+" not found"
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $Value $false
        }

    if ( $TLS_1_2_Client_Enabled_Value -ne $null ) {
        $TLS_Value = "TLS 1.2 Client Enabled = "+$TLS_1_2_Client_Enabled_Value
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "TLS 1.2 Client Enabled"+" not found"
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $Value $false
        }

    if ( $TLS_1_2_Client_DisabledByDefault_Value -ne $null ) {
        $TLS_Value = "TLS 1.2 Client DisabledByDefault = "+$TLS_1_2_Client_DisabledByDefault_Value
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "TLS 1.2 Client DisabledByDefault"+" not found"
        $ReturnValue += New-SVTestResult "WinHTTP and TLS 1.2 support" $Value $false
        }
    }
return New-SVTest "WinHTTP and TLS 1.2 support" $ReturnValue
}

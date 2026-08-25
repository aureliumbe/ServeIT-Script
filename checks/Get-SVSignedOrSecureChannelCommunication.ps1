function Get-SVSignedOrSecureChannelCommunication($comp){

    #Domain member: Digitally encrypt or sign secure channel data (always)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal:REG_DWORD:0x00000001

    #Domain member: Digitally encrypt secure channel data (when possible)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel:REG_DWORD:0x00000001

    #Domain member: Digitally sign secure channel data (when possible)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel:REG_DWORD:0x00000001

    #Microsoft network client: Digitally sign communications (always)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature:REG_DWORD:0x00000001

    #Microsoft network client: Digitally sign communications (if server agrees)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature:REG_DWORD:0x00000001

    #Microsoft network server: Digitally sign communications (always)"
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature:REG_DWORD:0x00000001

    #Microsoft network server: Digitally sign communications (if client agrees)"
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature:REG_DWORD:0x00000001

    $hklm = 2147483650
    $key1 = "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    $key2 = "SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
    $item_RequireSignOrSeal = "RequireSignOrSeal"
    $item_SealSecureChannel = "SealSecureChannel"
    $item_SignSecureChannel = "SignSecureChannel"

    $item_RequireSecuritySignature = "RequireSecuritySignature"
    $item_EnableSecuritySignature = "EnableSecuritySignature"

    $ReturnValue = @()
    $ReturnMsg = ""
  
    $DCs = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().DomainControllers.Name
    $Comp_FQDN = $comp + "." +$domain.name

    # Check Windows Update Configuration
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
    #if ($DCs -contains $Comp_FQDN) {
    #    echo "Deze computer is een DC"
        $RequireSignOrSeal = $wmi.GetDWORDValue($hklm, $Key1, $item_RequireSignOrSeal)
        $RequireSignOrSeal = $RequireSignOrSeal.UValue
        $ReturnMsg = "Domain member: Digitally encrypt or sign secure channel data (always)"
        if ($RequireSignOrSeal) {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        $SealSecureChannel = $wmi.GetDWORDValue($hklm, $Key1, $item_SealSecureChannel)
        $SealSecureChannel = $SealSecureChannel.UValue
        $ReturnMsg = "Domain member: Digitally encrypt secure channel data (when possible)"
        if ($SealSecureChannel) {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        $SignSecureChannel = $wmi.GetDWORDValue($hklm, $Key1, $item_SignSecureChannel)
        $SignSecureChannel = $SignSecureChannel.UValue
        $ReturnMsg = "Domain member: Digitally sign secure channel data (when possible)"
        if ($SignSecureChannel) {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        #}
    #else {
        echo "Deze Computer is ne member server"
        $RequireSecuritySignature = $wmi.GetDWORDValue($hklm, $Key2, $item_RequireSecuritySignature)
        $RequireSecuritySignature = $RequireSecuritySignature.UValue
        $ReturnMsg = "Microsoft network server: Digitally sign communications (always)"
        if ($RequireSecuritySignature) {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        $EnableSecuritySignature = $wmi.GetDWORDValue($hklm, $Key2, $item_EnableSecuritySignature)
        $EnableSecuritySignature = $EnableSecuritySignature.UValue
        $ReturnMsg = "Microsoft network server: Digitally sign communications (if client agrees)"
            if ($EnableSecuritySignature) {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += New-SVTestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        #}
   
return New-SVTest "Encrypt or Sign AD Communication" $ReturnValue
}

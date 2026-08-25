function Get-SVCheckSmBv1($comp){

# 2008R2  Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}
#   FIX:  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 –Force
# 2012    Get-SmbServerConfiguration | Select EnableSMB1Protocol
#   Fix:  Set-SmbServerConfiguration -EnableSMB1Protocol $false -force
# 2012R2  (Get-WindowsFeature FS-SMB1).Installed
#         Get-SmbServerConfiguration | Select EnableSMB1Protocol
#   FIX:  Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
#         Set-SmbServerConfiguration -EnableSMB1Protocol $false
#
# Windows 7/2008/2008R2 via registry key 
# Windows 8/8.1/10/2012/206/2019 via powershell Get-SmbServerConfiguration | Select EnableSMB1Protocol

$OS_Version = Get-SVOsVersion $comp

    $hklm = 2147483650
    $key1 = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
    $item_Name = "SMB1"

    $ReturnValue = @()
    $ReturnMsg = ""

if ( [int]$OS_Version -gt 61 ) {
    # WIndows 2012 or greater
    $SMB_Configuration = Invoke-Command -ComputerName $comp -scriptblock {Get-SmbServerConfiguration} -ErrorAction SilentlyContinue
    $SMBv1 = $SMB_Configuration.EnableSMB1Protocol
    if ($SMBv1) {
        $ReturnValue += New-SVTestResult "SMBv1 Protocol" "Enabled" $false
        }
    elseif (-Not $SMBv1) {
        $ReturnValue += New-SVTestResult "SMBv1 Protocol" "Disabled" $true
        }
    }
Else {
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
    $SMB = $wmi.GetDWORDValue($hklm, $Key1, $item_Name)
        $SMBv1 = $SMB.UValue
        $ReturnMsg = "Disabled"
        if ($SMBv1 -eq $null -OR $SMBv1 -eq 1) {
            $ReturnValue += New-SVTestResult "SMBv1 Protocol" "Enabled" $false
            }
        elseif ($SMBv1 -eq 0) {
            $ReturnValue += New-SVTestResult "SMBv1 Protocol" "Disabled" $true
            }
        }
   
return New-SVTest "SMBv1 Protocol" $ReturnValue
}

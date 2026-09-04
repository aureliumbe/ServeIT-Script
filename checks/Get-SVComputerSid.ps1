function Get-SVComputerSid($comp) {
#
# Get SID of a Dmain Joined Computer
#
    $ReturnValue = @()

    $ReturnSID = get-adcomputer $comp -Properties sid
    $ReturnMsg = $ReturnSID.SID.ToString()

    $SidCount = Get-ADComputer -Filter * -Properties SID | ? -Property SID -eq $ReturnMsg | ? -Property DistinguishedName -notlike "*OU=Domain Controllers*" | Measure-Object | Select-Object -ExpandProperty Count
    if ($SidCount -gt 1) {
        $ReturnMsg = $ReturnMsg + " (SID is not unique, found on $SidCount computers)"
        $testvalue = $false
    } else {
        $testvalue = $true
    }

    $ReturnValue += New-SVTestResult "Computer SID" $ReturnMsg $testvalue

return New-SVTest "Computer Unique SID" $ReturnValue
}

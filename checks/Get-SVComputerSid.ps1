function Get-SVComputerSid($comp) {
#
# Get SID of a DOmain Joined Computer
#
    $ReturnValue = @()

    $ReturnSID = get-adcomputer $comp -prop sid
    $ReturnMsg = $ReturnSID.SID

    #if ($vergelijker -contains $newsid) {Out-Default "gevonden"} else {$vergelijker += $newsid}

    $ReturnValue += New-SVTestResult "Computer SID" $ReturnMsg $true

return New-SVTest "Computer Unique SID" $ReturnValue
}

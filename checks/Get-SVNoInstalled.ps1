function Get-SVNoInstalled($comp) {
    $ReturnValue = @()

    $ReturnValue += New-SVTestResult "Antivirus Installed" "No known Anti-Virus software" $false
    Return New-SVTest "Antivirus" $ReturnValue
}

function Get-SVADRecycleBin(){

$ReturnValue = @()
$Result = ""

    $enabledScopes = (Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes
    if ($enabledScopes)
        {
        foreach ($line in $enabledScopes){
            if ($Result.Length -eq 0) {
                $Result = $line.split(",")[1]
                }
            else {
                $Result = $Result + " | " + $line.split(",")[1]
                }
            }
        $ReturnValue += New-SVTestResult "AD Recycle Bin Enabled" $Result $true
        }
    else
        {
        $ReturnMsg = "Disabled"
        $ReturnValue += New-SVTestResult "AD Recycle Bin Enabled" $Result $false
        }
return New-SVTest "AD Recycle Bin" $ReturnValue
}

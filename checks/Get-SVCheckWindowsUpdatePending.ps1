function Get-SVCheckWindowsUpdatePending($server) {
    $ReturnValue = @()
    $ReturnMsg = ""

    try {
        $WUstatus = Invoke-Command -ComputerName $server -ScriptBlock {
            (New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | Select-Object Title
            } -ErrorAction Stop
        foreach ($item in $WUstatus) {
            $ReturnMsg = $item.title
            $ReturnValue += New-SVTestResult "Windows Updates" $ReturnMsg $false
            }
    }
    catch {
        $ReturnMsg = "Exception: " + $_.Exception.Message
        $ReturnValue += New-SVTestResult "Windows Updates" $ReturnMsg $false
        }
Return New-SVTest "Windows Updates" $ReturnValue
}

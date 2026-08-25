function Get-SVCheckWindowsUpdateStatus2($server) {
    $ReturnValue = @()
    $ReturnMsg = ""

    $WUstatus = Invoke-Command -ComputerName $server -ScriptBlock {(New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | Select-Object Title} -ErrorAction Continue    
    foreach ($item in $WUstatus) {
        $ReturnMsg = $item.title
        $ReturnValue += New-SVTestResult "Windows Updates" $ReturnMsg $false
        }
Return New-SVTest "Windows Updates" $ReturnValue
}

function Get-SVCheckWindowsUpdateHistory($server, $CheckFailedUpdates) {
    $FailedUpdates = @()
    $UniqueFailedUpdates = @()
    $SucceededUpdates = @()

   <#
    $QueuedUpdates=Invoke-Command -ComputerName $server -ScriptBlock {
            $updateObject = New-Object -ComObject Microsoft.Update.Session
            #$updateObject.ClientApplicationID = "Windows Queued Updates Script"
            $updateSearcher = $updateObject.CreateUpdateSearcher();
            try {$searchResults = $updateSearcher.Search("IsInstalled=0");
            $searchResults.Updates.Count }
            catch {Return $error}
            }
    #>

    try {
        $QueuedUpdates = Invoke-Command -ComputerName $server -ScriptBlock {
            $updateObject = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
            $updateSearcher = $updateObject.CreateUpdateSearcher();
            $searchResults = $updateSearcher.Search("IsInstalled=0");
            $searchResults.Updates.Count
            } -ErrorAction Stop
        }
    catch {
        $QueuedUpdates = "Exception: " + $_.Exception.Message
        }

    if ($QueuedUpdates -match 'Exception from HRESULT:') {
        $QueuedUpdates = " Exception: "+($QueuedUpdates.split(":")[1]).Trim()
        }

    if ($CheckFailedUpdates) {

        if ($QueuedUpdates -match '^Exception: ') {
            $updates = @()
        }
        else {
            try {
                $updates=Invoke-Command -ComputerName $server -ScriptBlock {
                    $UpdateSession = New-Object -ComObject "Microsoft.Update.Session" -ErrorAction Stop
                    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
                    $historyCount = $UpdateSearcher.GetTotalHistoryCount()
                    $UpdateSearcher.QueryHistory(0, $historyCount) | Select-Object Date, @{name="Operation"; expression={switch($_.operation){1 {"Installation"}; 2 {"Uninstallation"}; 3 {"Other"}}}}, @{name="Status"; expression={switch($_.resultcode){1 {"In Progress"}; 2 {"Succeeded"}; 3 {"Succeeded With Errors"};4 {"Failed"}; 5 {"Aborted"} } } }, Title
                    } -ErrorAction Stop
            }
            catch {
                $updates = @()
                $QueuedUpdates = "Exception: " + $_.Exception.Message
            }
        }
            #$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
            #$SearchResult = $Searcher.Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0")    

        foreach ($item in ($updates |sort)) {
            if ($item.status -eq "Failed") {
                if ($item.title.indexof("(") -gt 0) {
                    $FailedItem = $item.title.split("(")[1].split(")")[0]
                    $FailedUpdates += $FailedItem
                    }
                }
            elseif ($item.status -eq "Succeeded") {
                if ($item.title.indexof("(") -gt 0) {
                    $SucceededItem = $item.title.split("(")[1].split(")")[0]
                    $SucceededUpdates += $SucceededItem
                    }
                }
            }

        $FailedCnt = 0
        $Prev_FailedItem=""
        foreach ($FailedItem in ($FailedUpdates |sort)) {
            if ($FailedItem.trim() -ne $Prev_FailedItem.trim()) {
                $FailedCnt++
                $UniqueFailedUpdates += $faileditem.trim()
                #echo "$faileditem $Prev_FailedItem"
                }
            elseif ($FailedItem.trim() -eq $Prev_FailedItem.trim()) {
                echo "$faileditem $Prev_FailedItem"            
                }
            $Prev_FailedItem = $FailedItem
            }

        $FailedCnt=0
        foreach ($Item in $UniqueFailedUpdates) {
            if (!$SucceededUpdates.Contains($item)) {
                $FailedCnt++
                echo "Persistant Failed update"
                }
            }

        $FailedUpdatesCnt = "{0,3}" -f $FailedCnt
        $SucceededUpdatesCnt = "{0,4}" -f $SucceededUpdates.Count
        $QueuedUpdates = "{0,3}" -f $QueuedUpdates
    
        $ReturnMsg = "Updates Queued:"+$QueuedUpdates+" Failed:"+$FailedUpdatesCnt+" Succeeded:"+$SucceededUpdatesCnt

        } # end if ($CheckFailedUpdates)
    else {
        $QueuedUpdates = "{0,3}" -f $QueuedUpdates
        $ReturnMsg = "Updates Queued:"+$QueuedUpdates
        }

    if ([int]$FailedCnt -gt 15 -OR ($QueuedUpdates -match 'Exception: ') ) {
        $ReturnValue += New-SVTestResult "Windows Update Status" $ReturnMsg $false
        }
    else {
        $ReturnValue += New-SVTestResult "Windows Update Status" $ReturnMsg $true
        }

return New-SVTest "Windows Update Status" $ReturnValue
}

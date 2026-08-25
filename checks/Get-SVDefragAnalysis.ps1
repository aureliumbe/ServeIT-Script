function Get-SVDefragAnalysis($server){
    $ReturnValue = @()

    $volumes = @(gwmi Win32_Volume -ComputerName $server -Filter 'DriveType = 3')
    foreach ($volume in $volumes) {
        $analysis = $volume.DefragAnalysis().DefragAnalysis
        
	    $dlfse = ([decimal]($analysis.LargestFreeSpaceExtent))
	    $vols = ""
	    $i = 0
	    While ($dlfse -gt 1000) {
	        $i = $i + 1
	        $dlfse = ([decimal]::round($dlfse) / 1024)
	    }
	    switch ($i)
	        {
	        0 { $dlfsepostfix = "B" }
	        1 { $dlfsepostfix = "KB" }
	        2 { $dlfsepostfix = "MB" }
	        3 { $dlfsepostfix = "GB" }
	        4 { $dlfsepostfix = "TB" }
	        }
	    $objVal = "Frag.Files: " + $analysis.TotalFragmentedFiles + "- Frag.Folders: " + $analysis.FragmentedFolders + "- Pagefile fragm.: " + $analysis.TotalPageFileFragments + "- MFT fragm.: " + $analysis.TotalMFTFragments + " - Percent fragm.: " + $analysis.TotalPercentFragmentation + "% - Largest Freespace: " + ([decimal]::round($dlfse)) + $dlfsepostfix
        if($analysis.TotalPercentFragmentation -gt 5) {$ok = $false} else {$ok = $true}
		#$ReturnValue += New-SVTestResult $volume.DriveLetter $objVal $ok	    
	}
    return New-SVTest "Defrag" $ReturnValue 
}

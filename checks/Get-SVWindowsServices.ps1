Function Get-SVWindowsServices($server){
    $ReturnValue = @()
	$Services = Get-wmiobject win32_service -Filter "startmode = 'auto' AND state != 'running' AND Exitcode !=0 " -ComputerName $server
    
    If ($Services -ne $null) {
        
        $Services | foreach{
			#$ReturnValue += New-SVTestResult $_.name ("" + $_.state + ";" + $_.exitcode) $false
            $ReturnValue += New-SVTestResult $_.displayname ("" + $_.state + ";" + $_.exitcode) $false
        }
    }
    Else {
        $ReturnValue += New-SVTestResult "All Services" "running normally" $true
    }
    return New-SVTest "Services" $ReturnValue 
}

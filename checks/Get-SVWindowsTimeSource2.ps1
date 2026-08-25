function Get-SVWindowsTimeSource2($server){
    $ReturnValue = @()
    $Found=$false
    $PDCtimeSyncSource = "ntp.belbone.be,0x1"
    $PDC=Get-ADDomain | Select-Object PDCEmulator
    $DCs=Get-ADDomainController -Filter *
    $DCs=$DCs.Name
    $wmi = get-wmiobject -class Win32_OperatingSystem -computername $server
    #$OSCheck = (Get-WmiObject -comp $comp -class Win32_OperatingSystem ).Caption
    
    if ( [int]$wmi.version.split(".")[0] -gt 5 ) {
        #$TimeSource = Invoke-Command -ComputerName $server -ScriptBlock { w32tm /query /source }
        $TimeSource = Invoke-Command -ComputerName $server -ScriptBlock { w32tm /query /peers }
        If ( ($TimeSource -imatch 'Peer:' | unique) -like('*ntp.belbone.be*') ) {
            $TimeSource = (($TimeSource -imatch 'Peer:' | unique).split(":")[1].trim()).split(",")[0]
            }
        Else {
            $TimeSource = ((($TimeSource -imatch 'Peer:' | unique).split(":")[1].trim()).split(",")[0]).split(".")[0]
            }
        }
    Else {
        $TimeSource = Invoke-Command -ComputerName $server -ScriptBlock { net time /querysntp }
        $TimeSource=$TimeSource.split(":")[1].Trim()
        If ( ($TimeSource.split(",0x1") -contains "ntp.belbone.be") -or ($TimeSource.split(",0x1") -contains "time.windows.com") ) {
            $TimeSource=$TimeSource.split(",")[0]
            }
        else {          
            $TimeSource=$TimeSource.split(",")[0]
            }
        }    

    if ($server -eq $PDC.PDCEmulator.split(".")[0] ) {      
        If ( $TimeSource -contains "ntp.belbone.be" ) {
            $Found=$true
            $ReturnValue += New-SVTestResult "TimeSource" $TimeSource $true
            }
        else {
            $Found=$true
            $ReturnValue += New-SVTestResult "TimeSource" $TimeSource $false
            }
        }              
    else {
        foreach ($DC in $DCs) {           
                 if ($TimeSource -eq $dc) {
                     $Found=$true
                     $ReturnValue += New-SVTestResult "TimeSource" $TimeSource $true
                     }        
                }
        if (!$found) {
            if ( ([int]$wmi.version.split(".")[0] -lt "6") -and ($TimeSource -contains "time.windows.com") ) {
                $ReturnValue += New-SVTestResult "TimeSource" $TimeSource $true
                }
            else {
                $ReturnValue += New-SVTestResult "TimeSource" $TimeSource $false
                }
            }
        }
    return New-SVTest "Timesource" $ReturnValue
}

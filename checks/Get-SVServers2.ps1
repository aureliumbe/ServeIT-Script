function Get-SVServers2(){
    $ReturnValue = @()
    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0 
    $ips = @()
    $nstemp = $ns
    
    do  {        
        $pos = $nstemp.IndexOf(":")
        if ($pos -gt -1) {
            $nstemp = $nstemp.Substring($pos+1)
            }
        } while ($pos -gt -1)
    $nstemp = $nstemp.Trim()

    do  {
       if ($nstemp.split(" ")[$i].trim() -ne "") {
            $ips += $nstemp.split(" ")[$i].trim()
            }
       $i = $i +1
        } while ($i -ne ($nstemp.split(" ").count))

    foreach ($ip in $ipaddr) { 
        if ($ip.InterfaceAlias -notlike "Loopbac*") {
            $ip.ipaddress
            }
        }

    foreach ($ip in $ips | sort) {    

        #if ( [int]$OS_Version -gt 62 ) {
        $PSver = (Get-Host).Version.major
        if ( $PSver -gt 3) {
            try {
                #test-netconnectio bestaat pas vanaf windows 8 vandaar deze check
                $TcpTest = Test-NetConnection -ComputerName $ip -Port 53 -WarningAction SilentlyContinue
                $PingTest = Test-NetConnection -ComputerName $ip -WarningAction SilentlyContinue
                If ($TcpTest.TcpTestSucceeded -and $PingTest.PingSucceeded) {
                    $ReturnValue += New-SVTestResult "$ip" "DNS" $true
                    }
                else {
                    if ($TcpTest.TcpTestSucceeded) {
                        $ReturnValue += New-SVTestResult "$ip" "No Ping" $false
                        }
                    else {
                        if ($PingTest.PingSucceeded) {
                            $ReturnValue += New-SVTestResult "$ip" "No DNS servcice" $false
                            }
                        else {
                            $ReturnValue += New-SVTestResult "$ip" "Whole test failed" $false
                            }
                        }
                    }
                }
            catch {
                #If Powershell Version is older than 4.0, do only the ping check.
                if((Test-Connection -ComputerName $ip -Count 1 -Quiet) -eq $false) {
                    $ReturnValue += New-SVTestResult "$ip" "Whole test failed" $false
                    }
                else {
                    $ReturnValue += New-SVTestResult "$ip" "DNS" $true
                    }            
                }
            }
        else {
            #If Powershell Version is older than 4.0, do only the ping check.
            if((Test-Connection -ComputerName $ip -Count 1 -Quiet) -eq $false) {
                $ReturnValue += New-SVTestResult "$ip" "Whole test failed" $false
                }
            else {
                $ReturnValue += New-SVTestResult "$ip" "DNS" $true
                }
            }
        }
return New-SVTest "DNS Servers" $ReturnValue
}

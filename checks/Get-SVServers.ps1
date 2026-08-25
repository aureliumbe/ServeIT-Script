function Get-SVServers(){
    $ReturnValue = @()
    $ns = nslookup $domain | sort
    $ns = "" + $ns
    $i= 1
    $ips = @()
    do{
        if($ns.split(":")[4].split(" ")[$i].trim() -ne ""){
            $ips += $ns.split(":")[4].split(" ")[$i].trim()
        }
        $i = $i +1
    }while($i -ne ($ns.split(":")[4].split(" ").count))

    foreach($ip in $ips){
        if(((Get-WmiObject win32_operatingsystem).version.split(".")[0] -gt 5)-and((Get-WmiObject win32_operatingsystem).version.split(".")[1] -gt 2)){
            #test-netconnectio bestaat pas vanaf windows 8 vandaar deze check
            $test1 = Test-NetConnection -ComputerName $ip -Port 53 -WarningAction SilentlyContinue
            If ($test1.TcpTestSucceeded -and $test1.PingSucceeded){
                $ReturnValue += New-SVTestResult "$ip" "DNS" $true
            }else{
                if($test1.TcpTestSucceeded){
                    $ReturnValue += New-SVTestResult "$ip" "No Ping" $false
                }else{
                    if($test1.PingSucceeded){
                        $ReturnValue += New-SVTestResult "$ip" "No DNS servcice" $false
                    }else{
                        $ReturnValue += New-SVTestResult "$ip" "Whole test failed" $false
                    }
                }
            }
        }else{
            #indien er een versie lager dan windows 8 is, enkel ping check.
            if((Test-Connection -ComputerName $ip -Count 1 -Quiet) -eq $false){
                $ReturnValue += New-SVTestResult "$ip" "Whole test failed" $false
            }else{
                $ReturnValue += New-SVTestResult "$ip" "DNS" $true
            }
        }
    }
    return New-SVTest "DNS Servers" $ReturnValue
}

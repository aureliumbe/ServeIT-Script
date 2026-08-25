function Get-SVWinsServers() {    
    #$WINS_Servers = foreach ($item in $WINS_Servers1) { $item.replace(" - ","|").split("|")[1].trim()}
    
    foreach ($srv in $servers) {
        $WINS_Server_Config = Invoke-Command -ComputerName $srv.servername -ScriptBlock {netsh wins dump}
        if ($WINS_Server_Config.length -ne 0) {
            if ($WINS_Server_Config -like "*Wins Operation failed with Error There are no more endpoints available*") {
                #
                }
            else {
                $WINS_Servers += [System.Net.Dns]::GetHostbyName($srv.ServerName).Addresslist.IPAddressToString
                }
            }
        }
return $WINS_Servers
}

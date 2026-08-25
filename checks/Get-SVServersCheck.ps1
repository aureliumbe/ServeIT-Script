function Get-SVServersCheck($server) {

$ReturnValue = @()
$WINS_Servers1 = @()
$WINS_Servers_Stats = @()
$WINS_Server_VersionMaps = @()
$line = ""
$ResultMsg = ""
$ResultMsg2 = ""
$Replication_Partners = $true

$Language = Get-SVOsLanguage $server

$WINS_Server_Config = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins dump}

if ($WINS_Server_Config.length -ne 0) {
    if ($WINS_Server_Config -like "*Wins Operation failed with Error There are no more endpoints available*") {
        $ReturnMsg = "Not Installed"
        $ReturnValue += New-SVTestResult "WINS Server" $ReturnMsg $true        
        }
    else {
        $WINS_Server_Records = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins server show partner}
    
        # ***You have Read and Write access to the server ....***
        #
        # Currently there is no Replication partner for this WINS Server
        #
        # Command completed successfully.

        foreach ($line in $WINS_Server_Records) {
            if ($line.trim() -like "Currently there is no Replication partner for this WINS Server*") {
                Echo "No replication partners"
                $Replication_Partners = $false
                }
            }

        if ($Replication_Partners) {
            foreach ($line in $WINS_Server_Records) {
                if ($line.trim() -like "Total No. of Active Replication Partner*") {
                    $WINS_Active_Repl_Partners = $line.split(":")[1].trim()
                    }
                if ($line.Trim() -like "* - *") {
                    if ($line.trim() -notlike "Server Name*") {
                        $WINS_Servers1 += $line
                        }
                    }
                }

                $WINS_Server_Statistics = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins server show statistics}
                foreach ($line in $WINS_Server_Statistics) {
                    if ($line.trim() -like "Last planned replication*") {
                        $pos = $line.indexof(":")
                        $WINS_Last_Repl = ($line.substring($pos+1)).trim()
                        }
                    if ($line.trim() -like "No of Successful/Failed Queries*") {
                        $WINS_Queries = $line.split("=")[1].trim()
                        }
                    if ($line.trim() -like "* - *") {
                        if ($line.trim() -notlike "WINS Partner IP Address*") {
                            $WINS_Servers_Stats += $line
                            }
                        }
                    }       
    
                $NowMinus1Hour=(Get-Date).AddHours(-1).Ticks
                if ($Language -eq "English") {
                    $day=$WINS_Last_Repl.split("/")[1].trim()
                    $WINS_Repl_Day = "{0:2}" -f $day
                    $month=$WINS_Last_Repl.split("/")[0].trim()
                    $WINS_Repl_Month = "{0:2}" -f $month
                    }
                elseif ($Language -eq "Dutch" -or $Language -eq "French" -or $Language -eq "German") {
                    $day=$WINS_Last_Repl.split("/")[0].trim()
                    $WINS_Repl_Day = "{0:2}" -f $day            
                    $month=$WINS_Last_Repl.split("/")[1].trim()
                    $WINS_Repl_Month = "{0:2}" -f $month
                    }
                $year=($WINS_Last_Repl.split("/")[2]).split(" ")[0]
                $WINS_Repl_Year = "{0:4}" -f $year
                $WINS_Repl_Time = $WINS_Last_Repl.split(" ")[2]
                $WINS_Repl_Date2=$WINS_Repl_Year+"/"+$WINS_Repl_Month+"/"+$WINS_Repl_Day+" "+$WINS_Repl_Time
                $WINS_Repl_Date=(get-date "$WINS_Repl_Date2").Ticks
        
                $WINS_Server_VerNr = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins server show version}
                foreach ($item in $WINS_Server_VerNr) {
                    if ($item -like "IP Address*") {
                        $WINS_Server_VersionNr = $item.split("=")[2].trim()
                        }
                    } 
        
                if ($WINS_Repl_Date -lt $NowMinus1Hour) {
                    echo "Replication out of sync?"
                    $ReturnMsg = $server + " with " + $WINS_Active_Repl_Partners + " Active Replication Partner(s), VersionNr:" + $WINS_Server_VersionNr + ", Successful/Failed Queries:" +$WINS_Queries + ", last replication within 1 hour"
                    $ReturnValue += New-SVTestResult "WINS Server" $ReturnMsg $false
                    }
                else {
                    echo "Replication in sync?"
                    $ReturnMsg = $server + " with " + $WINS_Active_Repl_Partners + " Active Replication Partner(s), VersionNr:" + $WINS_Server_VersionNr + ", Successful/Failed Queries:" +$WINS_Queries + ", last replication within 1 hour"
                    $ReturnValue += New-SVTestResult "WINS Server" $ReturnMsg $true
                    }            
        
                foreach ($item in $WINS_Servers1) {
                    $pos = $item.indexof(" - ")
                    $WINS_SRV_NAME = $item.substring(0,$pos+1).trim()
                    $WINS_SRV_IP = $item.substring($pos+2).split("-").trim()[0]
                    $WINS_SRV_TYPE = $item.substring($pos+2).split("-").trim()[1]
                
                    $WINS_Server_VerNr = Invoke-Command -ComputerName $WINS_SRV_NAME.trim() -ScriptBlock {netsh wins server show version} -ErrorAction SilentlyContinue
                    if ($WINS_Server_VerNr -ne $null) {
                        foreach ($item in $WINS_Server_VerNr) {
                            if ($item -like "IP Address*") {
                                $WINS_Server_VersionNr = $item.split("=")[2].trim()
                                }
                            }
                        $ReturnMsg = "  + WINS Replica Server: " + $WINS_SRV_NAME + " IP: " + $WINS_SRV_IP + " (" + $WINS_SRV_TYPE + "), VersionNr:" + $WINS_Server_VersionNr
                        $ReturnValue += New-SVTestResult "WINS Server" $ReturnMsg $true
                        }
                    else {
                        $ReturnMsg = "  + WINS Replica Server: " + $WINS_SRV_NAME + " IP: " + $WINS_SRV_IP + " (" + $WINS_SRV_TYPE + "), does not exist"
                        $ReturnValue += New-SVTestResult "WINS Server" $ReturnMsg $false
                        }
                    }

                $WINS_Server_VersionMappings = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins server show versionmap}
                foreach ($line in $WINS_Server_VersionMappings) {
                    if ($line.trim() -like "* - *") {
                        if ($line.trim() -notlike "Owner ID*") {
                            $WINS_Server_VersionMaps += $line
                            }
                        }
                    }
                echo "Foreach line in WINS_Server_Records
                }
            echo "There are replication Partners
            }
        else {
            echo "There are No WINS Replication Partners"
            $ReturnMsg = "Installed without Replica"
            $ReturnValue += New-SVTestResult "WINS Server" $ReturnMsg $true 
            }
        }
    }
else {
    $ReturnMsg = "Not Installed"
    $ReturnValue += New-SVTestResult "WINS Server" $ReturnMsg $true
    }     

return New-SVTest "WINS Servers" $ReturnValue
}

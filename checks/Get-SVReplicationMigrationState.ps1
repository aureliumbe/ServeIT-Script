function Get-SVReplicationMigrationState() {

#$DCs=(Get-ADForest).Domains | % { Get-ADDomainController -Discover -DomainName  $_ } | % { Get-ADDomainController -server $_.Name -filter * } | Select Name
#$Server=$DCs[0].name
$DFSR_Migration_States = @()
$DFSR_Global_States = @()
$Compare_Value = ""
$DFSR_Global_State = $true

#DGO: Only test on Accessable DC's
#
foreach ($DC in $domain.DomainControllers | sort) {
    if ($Servers.servername.contains(($DC.Name.replace("."+$domain.name,"")).toupper())) {
        $Server=$DC.name.toupper()
        $Status1 = Invoke-Command -ComputerName $server -ScriptBlock {dfsrmig /getmigrationstate}
        $Status2 = Invoke-Command -ComputerName $server -ScriptBlock {dfsrmig /getglobalstate}
        $ResultMsg = $status1[0]
        $ResultMsg2 = $Status2[0]
    
        if ($Compare_Value -eq "") {
            $Compare_Value = $ResultMsg2
            $DFSR_Global_States += $server+"|"+$ResultMsg2.trim()
            $DFSR_Migration_States += $server+"|"+$ResultMsg.trim()
            }
        elseif ($Compare_Value -ne $ResultMsg2) {
                $DFSR_Global_State = $false
                $DFSR_Global_States += $server+"|"+$ResultMsg2.trim()
                $DFSR_Migration_States += $server+"|"+$ResultMsg.Trim()            
                }
            else {
                $DFSR_Global_States += $server+"|"+$ResultMsg2.trim()
                $DFSR_Migration_States += $server+"|"+$ResultMsg.Trim()            
                }
        }
    }

    if ($DFSR_Global_State) {
        if ($ResultMsg2 -eq $ResultMsg) {
            echo "$ResultMsg2"
            }
        else {
            echo "$ResultMsg2, $ResultMsg"
            }
        }
    else {
        $i = 0
        foreach ($item in $DFSR_Global_States) {
            #$ReturnMsg = $item.split("|")[1]+" ("+$item.split("|")[0]+")"
            if ($item.split("|")[1] -eq $DFSR_Migration_States[$i].split("|")[1]) {
                $ReturnMsg2 = $item.split("|")[1]+" ("+$item.split("|")[0]+")"
                $i = $i +1
                echo $ReturnMsg2
                }
            else {
                $ReturnMsg2 = $item.split("|")[1]+", "+$DFSR_Migration_States[$i].split("|")[1]+" ("+$item.split("|")[0]+")"
                $i = $i +1
                echo $ReturnMsg2
                }
            }
        }
}

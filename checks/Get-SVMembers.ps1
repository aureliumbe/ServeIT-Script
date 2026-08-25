function Get-SVMembers($comp) {
#
# Get the 'Remote Desktop Users' Security Group members
#
    $ReturnValue = @()
    $ReturnMsg = ""

    $RDS_SG_MEMBERS_SCRIPT= {
        $count = 0
        $Member_Server_RDS_Users = net localgroup "Remote Desktop Users"
        foreach ($item in $Member_Server_RDS_Users) {    
            if ($item -notlike "Alias*") {
                if ($item -notlike "Comment*") {
                    if ($item -notlike "") {
                        if ($item -notlike "Members*") {
                            if ($item -notlike "") {
                                if ($item -notlike "-------*") {
                                    if ($item -notlike "The command*") {
                                        #echo $item
                                        $count++
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        return $count
        }

    $count = Invoke-Command -ComputerName $comp -ScriptBlock $RDS_SG_MEMBERS_SCRIPT
    $RDS_SRV = Invoke-command -ComputerName $comp {Get-WmiObject -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" | select -ExpandProperty TerminalServerMode}

    if ($RDS_SRV -eq 0) {
        if ( $count -ge 1 ) {
            $ReturnMsg = "$count"
            $ReturnStatus = $false
            }
        else {
             $ReturnMsg = "$count"
            $ReturnStatus = $true
            }
        }
    elseif ($RDS_SRV -eq 1) {
        if ( $count -ge 0 ) {
            $ReturnMsg = "$count (RDS Server)"
            $ReturnStatus = $true
            }
        }

    $ReturnValue += New-SVTestResult "'Remote Desktop Users' Security Group members (needs manual review)" $ReturnMsg $ReturnStatus

return New-SVTest "'Remote Desktop Users' Security Group members" $ReturnValue
}

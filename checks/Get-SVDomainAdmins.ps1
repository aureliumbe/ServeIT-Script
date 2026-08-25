Function Get-SVDomainAdmins(){
    $MaxDomainAdmins = 3
    $ReturnValue = @()
	try {
        $members = get-ADGroupMember "Domain admins"
        }
    catch {
        try {
            $members = get-ADGroupMember "Domeinadministrators"
            }
        catch {}
        }

    $enabledCount = 0
    $vandaag = get-date

    
    foreach($member in $members | sort){
        echo $member
        if($member.objectclass -eq "user"){
            $user= get-aduser $member -Properties *
            $user.AccountExpirationDate
            if ($user.Enabled){
                if (($user.AccountExpirationDate -eq $null)-or($user.AccountExpirationDate -gt $vandaag)){
                    $enabledcount += 1
                    if($enabledCount -gt $MaxDomainAdmins){
                         $ReturnValue += New-SVTestResult $member.name "account is enabled" $false
                    }else{
                         $ReturnValue += New-SVTestResult $member.name "account is enabled" $true
                    }
                }else{
                    $ReturnValue += New-SVTestResult $member.name "account is expired" $true
                }
                
            }else{
                $ReturnValue += New-SVTestResult $member.name "account is disabled" $true
            }
        }
    }
    
    if ($enabledCount -gt $MaxDomainAdminsS){
        $ReturnValue += New-SVTestResult "aantal enabled admins" $enabledCount $false
    }else{
        $ReturnValue += New-SVTestResult "aantal enabled admins" $enabledCount $true
    }
Return New-SVTest "Domainadmin" $ReturnValue    
}

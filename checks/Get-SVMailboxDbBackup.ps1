function Get-SVMailboxDBBackup($exchServerName){
    $objResult = New-Object System.Object

    #error opvang
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServerName.$domain/PowerShell/ -Authentication Kerberos
    try {
        # import-pssession : No command proxies have been created, because all of the requested remote commands would shadow existing local commands.
        # Use the AllowClobber parameter if you want to shadow existing local commands.
        $retcode = import-pssession $session -AllowClobber
        }
    catch{}

    # Exchange 2010 Powershell Module
    #add-pssnapin Microsoft.Exchange.Management.PowerShell.E2010

    $DBs = Get-MailboxDatabase -Status |Select Name, last*
    foreach($db in $dbs){
        $naam =$db.Name 
        $fullbackup =$db.LastFullBackup
        if ($db.LastFullBackup -eq $null) {
            $fullbackup="NULL"
            }
        $objResult | Add-Member -type NoteProperty -name $naam -value $Fullbackup
    }
    $DBs = Get-PublicFolderDatabase -Status|Select Name, last*
    foreach($db in $dbs){
        $naam =$db.Name 
        $fullbackup =$db.LastFullBackup
        if ($db.LastFullBackup -eq $null) {
            $fullbackup="NULL"
            }
        $objResult | Add-Member -type NoteProperty -name $naam -value $FullBackup
    }
    # Enter-PSSession -computername $exchServerName
    # or
    # $session = New-PSSession -ComputerName $exchServerName
    # Enter-PSSession -Session $session
    # Exit-PSSession

    #Remove-PSSession $session
    Remove-PSSession -Session (Get-PSSession)
    return $objResult
}

function Get-SVMailboxDBSize($exchServerName){

    #$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $exchServerName -ErrorAction Continue    
    #foreach ($proc in $processes) {
    #if ($proc.name -like "store.exe") {
    #    }
        
    $objResult = New-Object System.Object

    #error opvang !!
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServerName.$domain/PowerShell/ -Authentication Kerberos
    try {
        # import-pssession : No command proxies have been created, because all of the requested remote commands would shadow existing local commands.
        # Use the AllowClobber parameter if you want to shadow existing local commands.
        $retcode = import-pssession $session -AllowClobber
        }
    catch{}
    #Import-PSSession $session -DisableNameChecking | Out-Null

    $DBs = Get-MailboxDatabase -Status | Select Name, DatabaseSize, AvailableNewMailboxSpace
           
    foreach($db in $dbs){
        $naam =$db.Name 
        $size =$db.DatabaseSize
        if ($db.DatabaseSize -eq $null) {
            $size="NULL"
            }
        $freespace = $db.AvailableNewMailboxSpace
        $objResult | Add-Member -type NoteProperty -name $naam -value $size
    }

    $DBs = Get-PublicFolderDatabase -Status|Select Name, DatabaseSize,AvailableNewMailboxSpace
    foreach($db in $dbs){
        $naam =$db.Name 
        $size =$db.DatabaseSize
        if ($db.DatabaseSize -eq $null) {
            $size="NULL"
            }
        $freespace = $db.AvailableNewMailboxSpace
        $objResult | Add-Member -type NoteProperty -name $naam -value $size
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

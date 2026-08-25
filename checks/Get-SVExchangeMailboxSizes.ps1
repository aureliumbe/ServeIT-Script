function Get-SVExchangeMailboxSizes($exchServerName){
    #$MBs = @()
    $MB = ""
    $objResult = New-Object System.Object

    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServerName.$domain/PowerShell/ -Authentication Kerberos
    try {
        # import-pssession : No command proxies have been created, because all of the requested remote commands would shadow existing local commands.
        # Use the AllowClobber parameter if you want to shadow existing local commands.
        $retcode = import-pssession $session -AllowClobber
        }
    catch{}
    #$MBs = Get-mailbox -ResultSize Unlimited | get-mailboxstatistics | sort-object totalitemsize -descending | ft displayname,itemcount,totalitemsize
    $MBs = Get-mailbox -ResultSize Unlimited | Get-MailboxStatistics | Select-Object DisplayName, @{Name="TotalItemSizeMB"; Expression={[math]::Round(($_.TotalItemSize.ToString().Split("(")[1].Split(" ")[0].Replace(",","")/1MB),0)}}, ItemCount | Sort-Object TotalItemSizeMB -Descending | ft DisplayName,ItemCount,TotalItemSizeMB

    # Enter-PSSession -computername $exchServerName
    # or
    # $session = New-PSSession -ComputerName $exchServerName
    # Enter-PSSession -Session $session
    # Exit-PSSession

    #Remove-PSSession $session
    Remove-PSSession -Session (Get-PSSession)
    return $MBs
}

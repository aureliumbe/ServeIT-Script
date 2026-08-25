function Get-SVExchangeVersion($exchServerName){
    $objResult = New-Object System.Object
#    $exchservername = "ebf-mail-01"
#    $domain = "ebf.local"
    
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServerName.$domain/PowerShell/ -Authentication Kerberos
    $retcode = import-pssession $session -AllowClobber
    
    $Exch_Version = Invoke-Command -ComputerName $exchservername -ScriptBlock {Get-Command  Exsetup.exe | ForEach-Object {$_.FileversionInfo}}
    $objResult | Add-Member -type NoteProperty -name $exchservername -value $Exch_Version.ProductVersion
    
    # Enter-PSSession -computername $exchServerName
    # or
    # $session = New-PSSession -ComputerName $exchServerName
    # Enter-PSSession -Session $session
    # Exit-PSSession

    #Remove-PSSession $session
    Remove-PSSession -Session (Get-PSSession)
    return $objResult
}

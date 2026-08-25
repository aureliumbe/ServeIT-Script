function Get-SVLdapssl() {
# https://www.youtube.com/watch?v=xC3ujXGkh_c
# http://vcloud-lab.com/entries/windows-2016-server-r2/configuring-secure-ldaps-on-domain-controller
$ReturnValue = @()

[int] $GCPortLDAP = 3268
[int] $GCPortLDAPSSL = 3269
[int] $PortLDAP = 389
[int] $PortLDAPSSL = 636
        
#Get all DC's
$DCs = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().DomainControllers

foreach ($DC in $DCs) {
    $GC_LDAP = [ADSI]"LDAP://$($dc.name):$GCPortLDAP"
    $GC_LDAPSSL = [ADSI]"LDAP://$($dc.name):$GCPortLDAPSSL"
    $LDAP = [ADSI]"LDAP://$($dc.name):$PortLDAP"
    $LDAPSSL = [ADSI]"LDAP://$($dc.name):$PortLDAPSSL"

    try {$Connection_GC_LDAP = [adsi]($GC_LDAP)} Catch {}
    If ($Connection_GC_LDAP.Path) {
        $ReturnMsg = "Global Catalog Unsecure Connection to LDAP://$($dc.name):$GCPortLDAP"
        $ReturnValue += New-SVTestResult "Domain Controller Secure LDAP" $ReturnMsg $true
        }
    Else {
        $ReturnMsg = "Global Catalog Unsecure Connection to LDAP://$($dc.name):$GCPortLDAP"
        $ReturnValue += New-SVTestResult "Domain Controller Secure LDAP" $ReturnMsg $false
        }

    try {$Connection_GC_LDAPSSL = [adsi]($GC_LDAPSSL)} Catch {}
    If ($Connection_GC_LDAPSSL.Path) {
        $ReturnMsg = "Global Catalog Secure   Connection to LDAP://$($dc.name):$GCPortLDAPSSL"
        $ReturnValue += New-SVTestResult "Domain Controller Secure LDAP" $ReturnMsg $true
        }
    Else {
        $ReturnMsg = "Global Catalog Secure   Connection to LDAP://$($dc.name):$GCPortLDAPSSL"
        $ReturnValue += New-SVTestResult "Domain Controller Secure LDAP" $ReturnMsg $false
        }

    try {$Connection_LDAP = [adsi]($LDAP)} Catch {}
    If ($Connection_LDAP.Path) {
        $ReturnMsg = "Standard Unsecure       Connection to LDAP://$($dc.name):$PortLDAP"
        $ReturnValue += New-SVTestResult "Domain Controller Secure LDAP" $ReturnMsg $true
        } 
    Else {
        $ReturnMsg = "Standard Unsecure       Connection to LDAP://$($dc.name):$PortLDAP"
        $ReturnValue += New-SVTestResult "Domain Controller Secure LDAP" $ReturnMsg $false
        }

    try {$Connection_LDAPSSL = [adsi]($LDAPSSL)} Catch {}
    If ($Connection_LDAPSSL.Path) {
        $ReturnMsg = "Standard Secure         Connection to LDAP://$($dc.name):$PortLDAPSSL"
        $ReturnValue += New-SVTestResult "Domain Controller Secure LDAP" $ReturnMsg $true
        } 
    Else {
        $ReturnMsg = "Standard Secure         Connection to LDAP://$($dc.name):$PortLDAPSSL"
        $ReturnValue += New-SVTestResult "Domain Controller Secure LDAP" $ReturnMsg $false
        }
    }

Return New-SVTest "Domain Controller Secure LDAP" $ReturnValue
}

Function Get-SVexchangeserver(){
    $ExchServers=@()
    add-type -assemblyName "System.DirectoryServices"

    $AdsiQueryServ = "LDAP://CN=Microsoft Exchange,CN=Services,CN=Configuration,$LdapDomain"
    $root = new-object system.DirectoryServices.Directoryentry $adsiQueryServ
#DGO if (...
    if ($root.distinguishedname -ne $null) {
    $searcher = new-object system.DirectoryServices.DirectorySearcher
    $searcher.searchRoot = $root
    $searcher.filter = "objectClass=msExchExchangeServer"
    $result = $searcher.findall()

    foreach($obj in $result){
		$isTransport = $obj.properties.objectclass
        if("$isTransport" -eq "top server msExchExchangeServer"){
        	$prop = $obj.properties
        	$ExchServers += $prop.cn
		    }
        }
    }
    return $ExchServers
}

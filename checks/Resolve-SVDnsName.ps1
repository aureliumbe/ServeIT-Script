function Resolve-SVDnsName($server) {

    $ns = nslookup $server
    $ServerIP = $ns.split(":")[8].trim()

return $ServerIP
}

Function Get-SVOSVersion($server) {
    $OS_Major_Version = (Get-WmiObject win32_operatingsystem -computername $server).version.split(".")[0]
    $OS_Minor_Version = (Get-WmiObject win32_operatingsystem -computername $server).version.split(".")[1]
    $OS_Version = $OS_Major_Version+$OS_Minor_Version

return $OS_Version
}

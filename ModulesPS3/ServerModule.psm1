#### Server Object ####
    [XML] $oServers = New-Object System.Xml.XmlDocument
    $decl = $oServers.CreateXmlDeclaration("1.0","UTF-8",$null)
    $oServers.AppendChild($decl)
    $oServersElement = $oservers.createNode("element", "Server", '') 
    $oServers.appendchild($oServersElement)

    #Functions and methods
    function get-ServersFromAD() {
        $AD_Servers = Get-ADComputer -Filter { (OperatingSystem -like "*server*") -AND (enabled -eq $true) } | Sort-Object Name
        $AD_Servers | Foreach-object { 
                add-Server($_.name)
        }
    }

    
    function get-ServerOS($sName) {

        return "1111"
    }

    function get-ServerArch($sName) {

        return "1111"
    }

    function get-ServerIsOnline($sName) {

        return "1111"
    }

    function get-ServerIsDc($sName) {

        return "1111"
    }
    function get-ServerIsExch($sName) {

        return "1111"
    }
    function get-ServerPSRemoting($sName) {

        return "1111"
    }

    function add-Server($sName) {
        $sArch = get-ServerArch($sname)
        $sOs = get-ServerOS($sName)
        $isOnline = get-ServerIsOnline($sname)
        $isDc = get-ServerIsDC($sname)
        $isExch = get-ServerIsExch($sname)
        $PSremoteing = get-ServerPsRemoting($sname)

        $c = $oservers.createNode("element", "Server", '')
        $c.setAttribute("Name", $sName)
        $c.setAttribute("isOnline", $isOnline)
        $e = $oservers.createNode("element", "Name", '')
        $e.innerText = $sname
        $c.appendChild($e)
        $e = $oservers.createNode("element", "OS", '')
        $e.innerText = $sOs
        $c.appendChild($e)
        $e = $oservers.createNode("element", "Arch", '')
        $e.innerText = $sArch
        $c.appendChild($e)
        $e = $oservers.createNode("element", "isDC", '')
        $e.innerText = $isDc
        $c.appendChild($e)
        $e = $oservers.createNode("element", "isExch", '')
        $e.innerText = $isExch
        $e = $oservers.createNode("element", "PSremoting", '')
        $e.innerText = $PSremoteing
        $c.appendChild($e)
        
        $oServersElement.appendChild($c)
    }
    function write-ServersToXML($path){
        $oServers.save($path)
    }
#####

class Servers {
    #Properties
    [XML] $oServers
    #constructor
    Servers() {
        $this.oServers = new-object System.Xml.XmlDocument
        $decl = $this.oServers.CreateXmlDeclaration("1.0", "UTF-8", $null)
        $this.oServers.AppendChild($decl)
        $this.oServers.createNode("element", "Servers", $null)
    }

    #Functions and methods
    [void] initialize() {
        $AD_Servers = Get-ADComputer -Filter { (OperatingSystem -like "*server*") -AND (enabled -eq $true) } | Sort-Object Name
        $AD_Servers | Foreach-object { 
            Awrite-Verbose("Testing connection for " + $_.Name) 
            If ((Test-Connection -ComputerName $_.Name -Count 1 -Quiet) -eq $false) {
                $this.addServer($_.name, "", "", $true)
            }
            Else {
                $this.addServer($_.name, "", "", $true)
            }
        }
    }

    [void] initialize([string] $sServersSearchbase) {
        $AD_Servers = Get-ADComputer -Filter { (OperatingSystem -like "*server*") -AND (enabled -eq $true) } -SearchBase $sServersSearchbase | Sort-Object Name
        $AD_Servers | Foreach-object { 
            Awrite-Verbose("Testing connection for " + $_.Name) 
            If ((Test-Connection -ComputerName $_.Name -Count 1 -Quiet) -eq $false) {
                $this.addServer($_.name, "", "", $true)
            }
            Else {
                $this.addServer($_.name, "", "", $true)
            }
        }
    }
    
    [string] sOS([string] $sName) {

        return ""
    }

    [string] sArch([string] $sName) {

        return ""
    }

    [boolean] bIsOnline([string] $sName) {

        return ""
    }

    [boolean] bIsDc([string] $sName) {

        return ""
    }
    [boolean] bIsExch([string] $sName) {

        return ""
    }
    [boolean] bPSRemoting([string] $sName) {

        return ""
    }

    [void] addServer([string] $sName) {
        $sArch = sArch($sname)
        $sOs = sOS($sName)
        $isOnline = bIsOnline($sname)
        $isDc = bIsDC($sname)
        $isExch = bIsExch($sname)
        $PSremoteing = bPsRemoting($sname)


        
        $root = $this.oservers.Servers
        $c = $root.createNode("element", "Server", $null)
        $c.setAttribute("Name", $sName)
        $c.setAttribute("isOnline", $isOnline)
        $e = $c.createNode("element", "Name", $null)
        $e.innerText = $sname
        $c.appendChild($e)
        $e = $c.createNode("element", "OS", $null)
        $e.innerText = $sOs
        $c.appendChild($e)
        $e = $c.createNode("element", "Arch", $null)
        $e.innerText = $sArch
        $c.appendChild($e)
        $e = $c.createNode("element", "isDC", $null)
        $e.innerText = $isDc
        $c.appendChild($e)
        $e = $c.createNode("element", "isExch", $null)
        $e.innerText = $isExch
        $e = $c.createNode("element", "PSremoting", $null)
        $e.innerText = $PSremoteing

        $c.appendChild($e)
        $root.appentChild($c)
    }
}


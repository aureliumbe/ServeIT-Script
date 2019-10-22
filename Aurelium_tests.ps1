class Tests
{
#Properties
    [XML] $oTests
#constructor
    Tests()
    {
      $this.oTests = new-object System.Xml.XmlDocument
      
      
      $decl = $this.oTests.CreateXmlDeclaration("1.0","UTF-8",$null)
      $this.oTests.AppendChild($decl)
      $this.oTests.createNode("element","Testen",$null)
    }

#Functions and methods
    [void] outputByServer(){

    }   
    [void] outputByTest(){

    } 
    [void] saveXml([string]$path){

    }
    [void] saveWerkbonOutput([string]$path){

    }
    [void] addTestResult([string]$name, [string]$servername, [boolean]$ok){
        
    }

    [void] getNableOutput(){

    }
}


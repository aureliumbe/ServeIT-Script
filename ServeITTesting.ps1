import-module .\modulesPS3\ServerModule.psd1

#### verbose functie ####
function write-Verbose($text){
    if($Verbose) {
        Write-Host $text -ForegroundColor DarkGreen | Out-Default
    }
 }
#####


write-Verbose("Getting Servers")
get-ServersFromAD
write-Verbose("Saving XML File")
write-ServersToXML(".\output\servers.xml")
write-Verbose("End Script")
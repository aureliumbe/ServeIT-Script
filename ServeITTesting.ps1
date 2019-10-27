import-module .\modulesPS3\ServerModule.psm1

get-Servers
$oservers.save(".\output\getservers.xml")
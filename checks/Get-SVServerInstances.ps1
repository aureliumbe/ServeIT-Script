function Get-SVServerInstances($comp) {
###########################################
$ReturnValue = @()

$Instances = Invoke-Command -ComputerName $comp -ScriptBlock {(get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances} -ErrorAction SilentlyContinue
if ($Instances -eq $null) {
    $ReturnValue += New-SVTestResult "SQL Server" "Not Installed" $true
    }
else {
    foreach ($Instance in $Instances) {
        $SQL_INSTANCE_KEY="HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
        $SQL_Instance_Detail = Invoke-Command -ComputerName $comp -ScriptBlock {(get-itemproperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL")} -ErrorAction SilentlyContinue
        $SQL_Instance_Properties = Invoke-Command -ComputerName $comp -ScriptBlock {PARAM($param1) (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$param1\Setup")} -ArgumentList $SQL_Instance_Detail.$Instance -ErrorAction SilentlyContinue

        #$SQL_Instance_Properties.PatchLevel.split(".")[0]
        Switch ($SQL_Instance_Properties.PatchLevel.split(".")[0]) {
            "16" {$ReturnMsg = "Version: 2022 - "+$SQL_Instance_Properties.Edition+" installed"}
            "15" {$ReturnMsg = "Version: 2019 - "+$SQL_Instance_Properties.Edition+" installed"}
            "14" {$ReturnMsg = "Version: 2017 - "+$SQL_Instance_Properties.Edition+" installed"}
            "13" {$ReturnMsg = "Version: 2016 - "+$SQL_Instance_Properties.Edition+" installed"}
            "12" {$ReturnMsg = "Version: 2014 - "+$SQL_Instance_Properties.Edition+" installed"}
            "11" {$ReturnMsg = "Version: 2012 - "+$SQL_Instance_Properties.Edition+" installed"}
            "10" {
                  if ($SQL_Instance_Properties.PatchLevel.split(".")[0] -eq "50") {
                      $ReturnMsg = "Version: 2008R2 - "+$SQL_Instance_Properties.Edition+" installed"}
                  else {
                      $ReturnMsg = "Version: 2008 - "+$SQL_Instance_Properties.Edition+" installed"}
                  }
            "9" {$ReturnMsg = "Version: 2005 - "+$SQL_Instance_Properties.Edition+" installed"}
            "8" {$ReturnMsg = "Version: 2000 - "+$SQL_Instance_Properties.Edition+" installed"}
            "7" {$ReturnMsg = "Version: 7.0 - "+$SQL_Instance_Properties.Edition+" installed"}
	    Default {$ReturnMsg = "Version: "+$SQL_Instance_Properties.PatchLevel+" - "+$SQL_Instance_Properties.Edition+" installed"}
            }
        $ReturnValue += New-SVTestResult "SQL Server" $ReturnMsg $true    
        }
    }
    
Return New-SVTest "SQL Server" $ReturnValue
}

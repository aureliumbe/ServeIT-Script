Function Get-SVWindowsForestFunctionalLevel() {
#
#DGO: Only test on Accessable DC's (Stihl)
#
#$AD_Forest_Func_Level = Get-ADForest
#$AD_Forest_Func_Level.Forestmode
#Get-ADForest | select forestmode | ft -Wrap –Auto
$SearchBase="CN=Partitions,CN=CONFIGURATION,"+$LdapDomain
#$AD_Forest_Func_Level=dsquery * $SearchBase -scope base -attr msDS-Behavior-Version
#$DCs=(Get-ADForest).Domains | % { Get-ADDomainController -Discover -DomainName  $_ } | % { Get-ADDomainController -server $_.Name -filter * } | Select Name
#$Server=$DCs[0].name

$FFLevels = @()
$Compare_Value = ""
$FFLevel_Status_Ok = $true

foreach ($DC in $domain.DomainControllers | sort) {
    if ($Servers.servername.contains(($DC.Name.replace("."+$domain.name,"")).toupper())) { 
        $Server=$DC.name.ToUpper()
        $AD_Forest_Func_Level = Invoke-Command -ComputerName $server -ScriptBlock {dsquery * $SearchBase -scope base -attr msDS-Behavior-Version}
        $AD_Forest_Func_Level=$AD_Forest_Func_Level[1]

        if ($Compare_Value -eq "") {
            $Compare_Value = $AD_Forest_Func_Level
            $FFLevels += $server+"|"+$AD_Forest_Func_Level.trim()
            }
        elseif ($Compare_Value -ne $AD_Forest_Func_Level) {
                $FFLevel_Status_Ok = $false
                $FFLevels += $server+"|"+$AD_Forest_Func_Level.Trim()
                }
            else {
                $FFLevels += $server+"|"+$AD_Forest_Func_Level.Trim()
                }
        }
    }

        if ($FFLevel_Status_Ok) {
            switch ($AD_Forest_Func_Level.trim()) {
                0 {echo "Windows Forest Functional Level: Windows Server 2000"}
                1 {echo "Windows Forest Functional Level: Windows Server 2003 interim"}
                2 {echo "Windows Forest Functional Level: Windows Server 2003"}
                3 {echo "Windows Forest Functional Level: Windows Server 2008"}
                4 {echo "Windows Forest Functional Level: Windows Server 2008 R2"}
                5 {echo "Windows Forest Functional Level: Windows Server 2012"}
                6 {echo "Windows Forest Functional Level: Windows Server 2012 R2"}
                7 {echo "Windows Forest Functional Level: Windows Server 2016"}
                10 {echo "Windows Forest Functional Level: Windows Server 2025"}
                }                
            }
        else {
            foreach ($item in $FFLevels) {
                $Server = $item.split("|")[0]
                $FFLevel = $item.split("|")[1]
                switch ($FFLevel) {            
                    0 {echo "Windows Forest Functional Level: Windows Server 2000 ($Server)"}
                    1 {echo "Windows Forest Functional Level: Windows Server 2003 interim ($Server)"}
                    2 {echo "Windows Forest Functional Level: Windows Server 2003 ($Server)"}
                    3 {echo "Windows Forest Functional Level: Windows Server 2008 ($Server)"}
                    4 {echo "Windows Forest Functional Level: Windows Server 2008 R2 ($Server)"}
                    5 {echo "Windows Forest Functional Level: Windows Server 2012 ($Server)"}
                    6 {echo "Windows Forest Functional Level: Windows Server 2012 R2 ($Server)"}
                    7 {echo "Windows Forest Functional Level: Windows Server 2016 ($Server)"}
                    10 {echo "Windows Forest Functional Level: Windows Server 2025 ($Server)"}
                    }
                }
            }
}

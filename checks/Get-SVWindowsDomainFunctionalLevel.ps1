function Get-SVWindowsDomainFunctionalLevel() {
#
$DFLevels = @()
$Compare_Value = ""
$DFLevel_Status_Ok = $true

$SearchBase=$LdapDomain

#DGO: Only test on Accessable DC's
#
foreach ($DC in $domain.DomainControllers | sort) {
    if ($Servers.servername.contains(($DC.Name.replace("."+$domain.name,"")).toupper())) { 
        $Server=$DC.name.toupper()
        $AD_Domain_Func_Level1 = Invoke-Command -ComputerName $server -ScriptBlock {dsquery * $SearchBase -scope base -attr msDS-Behavior-Version}
        $AD_Domain_Func_Level2 = Invoke-Command -ComputerName $server -ScriptBlock {dsquery * $SearchBase -scope base -attr ntMixedDomain}

        $AD_Domain_Func_Level=$AD_Domain_Func_Level1[1].trim()+$AD_Domain_Func_Level2[1].trim()

        if ($Compare_Value -eq "") {
            $Compare_Value = $AD_Domain_Func_Level
            $DFLevels += $server+"|"+$AD_Domain_Func_Level.trim()
            }
        elseif ($Compare_Value -ne $AD_Domain_Func_Level) {
                $DFLevel_Status_Ok = $false
                $DFLevels += $server+"|"+$AD_Domain_Func_Level.Trim()
                }
            else {
                $DFLevels += $server+"|"+$AD_Domain_Func_Level.Trim()
                }
        }
    }

    if ($DFLevel_Status_Ok) {
    switch ($AD_Domain_Func_Level.trim()) {
        00 {echo "Windows Domain Functional Level: Windows Server 2000 Native"}
        01 {echo "Windows Domain Functional Level: Windows Server 2000 Mixed"}
        20 {echo "Windows Domain Functional Level: Windows Server 2003"}
        30 {echo "Windows Domain Functional Level: Windows Server 2008"}
        40 {echo "Windows Domain Functional Level: Windows Server 2008 R2"}
        50 {echo "Windows Domain Functional Level: Windows Server 2012"}
        60 {echo "Windows Domain Functional Level: Windows Server 2012 R2"}
        70 {echo "Windows Domain Functional Level: Windows Server 2016"}
        100 {echo "Windows Domain Functional Level: Windows Server 2025"}
            }                
        }
    else {
        foreach ($item in $DFLevels) {
            $Server = $item.split("|")[0]
            $DFLevel = $item.split("|")[1]
            switch ($DFLevel) {            
                00 {echo "Windows Domain Functional Level: Windows Server 2000 Native ($Server)"}
                01 {echo "Windows Domain Functional Level: Windows Server 2000 Mixed ($Server)"}
                20 {echo "Windows Domain Functional Level: Windows Server 2003 ($Server)"}
                30 {echo "Windows Domain Functional Level: Windows Server 2008 ($Server)"}
                40 {echo "Windows Domain Functional Level: Windows Server 2008 R2 ($Server)"}
                50 {echo "Windows Domain Functional Level: Windows Server 2012 ($Server)"}
                60 {echo "Windows Domain Functional Level: Windows Server 2012 R2 ($Server)"}
                70 {echo "Windows Domain Functional Level: Windows Server 2016 ($Server)"}
                100 {echo "Windows Domain Functional Level: Windows Server 2025 ($Server)"}
                }
            }
        }
}

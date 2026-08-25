function Get-SVWindowsBPA($comp) {
#
#$COMP="SFC-DC-01"
$OS_Version = Get-SVOSVersion $comp
$ReturnValue = @()

if ( [int]$OS_Version -gt 60 ) {
    $return = Invoke-Command -ComputerName $comp -ScriptBlock {PARAM($Param1)        
        Import-Module Servermanager
        Import-Module bestpractices
        $BPA_Models = (Get-WindowsFeature | where {$_.BestPracticesModelId -like "microsoft*"}).BestPracticesModelId
        Foreach ($BPA_Model in $BPA_Models) {
            if ( ($BPA_Model -ne "Microsoft/Windows/FederationServices") ) {                
                $Installed = (Get-WindowsFeature | where {$_.BestPracticesModelID -eq $BPA_Model}).Installed                
                #echo -->$line<-- $Installed
                if ($Installed) {
                    $BPA_Results = Invoke-BPAModel -BestPracticesModelId $BPA_Model
                    foreach ($Line in $BPA_Results) {
                        if ($Line.Success -eq $true) {                            
                            $Message = "--> BPA Test: "+$Line.ModelID
                            #$ReturnValue += "`n" + $Message
                            echo $Message.trim()                            
                            $LineDetails = Get-BpaResult -BestPracticesModelID $Line.ModelID
                            if ($Line.ModelID -ne "Microsoft/Windows/Hyper-V") {
                                foreach ($item in $LineDetails) {
                                    #$item | Where-Object { ( ($item.Severity –eq 'Error') -OR ($item.Severity –eq 'Warning') ) -AND ($item.Excluded –eq $false) } | Select Title, Problem, Resolution, Help | FL Title, Problem, Resolution, Help
                                    $item | Where-Object { ( ($item.Severity -eq 'Error') -OR ($item.Severity -eq 'Warning') ) -AND ($item.Excluded -eq $false) } | Select-Object -Property @{Name="Title"; Expression={ $_.Title.ToString().Trim()}}, @{Name="Problem"; Expression={ $_.Problem.ToString().Trim()}}, @{Name="Resolution"; Expression={ $_.Resolution.ToString().Trim()}}, @{Name="Help"; Expression={ $_.Help.ToString().Trim()}} | FL Title, Problem, Resolution, Help
                                    #$item | Where-Object { ( ($item.Severity –eq 'Error') -OR ($item.Severity –eq 'Warning') ) -AND ($item.Excluded –eq $false) } | Select-Object -Property @{Name="Title"; Expression={ $_.Title.ToString().Trim()}}, @{Name="Problem"; Expression={ $_.Problem.ToString().Trim()}}, @{Name="Resolution"; Expression={ $_.Resolution.ToString().Trim()}}, @{Name="Help"; Expression={ [regex]::Replace($_.Help,'\s+',' ') }} | FL Title, Problem, Resolution, Help
                                    #if ( ( ($item.Severity –eq 'Error') -OR ($item.Severity –eq 'Warning') ) -AND ($item.Excluded –eq $false) ) {
                                        #$BPA_Title = $item.Title
                                        #$BPA_Problem = $Item.Problem
                                        #$BPA_Resolution = $Item.Resolution
                                        #$BPA_Help = $Item.Help
                                        #$ReturnValue += "`n`nTitle        : " + $BPA_Title.trim() + "`nProblem      : " + $BPA_Problem.trim() + "`nResolution   : " + $BPA_Resolution.trim() + "`nHelp         : " + $BPA_Help.trim() + "`r`n"
                                        #}                                  
                                    } # foreach ($item in $LineDetails)                                    
                                #echo $ReturnValue
                                } # if ($Line.ModelID -ne "Microsoft/Windows/Hyper-V")
                            } # if ($Line.Success -eq $true)
                        } # foreach ($Line in $BPA_Results)
                    } # if $installed
                } # IF $BPA_Model -ne "Microsoft/Windows/FederationServices"   
            } # Foreach ($BPA_Model in $BPA_Models)
        #return $ReturnValue
        #return $item
        } -ArgumentList $OS_Version
    } # if ( [int]$OS_Version -gt 60 )

Return $Return
}

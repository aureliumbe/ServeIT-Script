function Get-SVServer($comp) {
$ReturnValue = @()

$RDS_Server = Invoke-command -ComputerName $comp {Get-WmiObject -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" | select -ExpandProperty TerminalServerMode}

if ($RDS_Server) {
    $ReturnMsg = "Role installed"
    }
else {
    $ReturnMsg = "Role not installed"    
    }
$ReturnValue += New-SVTestResult "RDS Server" $ReturnMsg $true

Return New-SVTest "RDS Server" $ReturnValue
}

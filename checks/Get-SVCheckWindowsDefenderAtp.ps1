function Get-SVCheckWindowsDefenderAtp($comp){
$ReturnValue = @()
$hklm = 2147483650

$MS_Defender_Status = Invoke-Command -ComputerName $comp -scriptblock {Get-MpComputerStatus | select AMRunningMode, AMProductVersion, AMServiceEnabled, AntispywareEnabled, AntispywareSignatureLastUpdated, AntivirusEnabled, AntivirusSignatureLastUpdated, FullScanStartTime, FullScanEndTime, BehaviorMonitorEnabled,DefenderSignaturesOutOfDate, IoavProtectionEnabled, IsTamperProtected, NISEnabled, NISSignatureLastUpdated, OnAccessProtectionEnabled, RealTimeProtectionEnabled, QuickScanStartTime, QuickScanEndTime, RebootRequired}

if ( $MS_Defender_Status.AMServiceEnabled -AND $MS_Defender_Status.AntivirusEnabled -AND $MS_Defender_Status.AntispywareEnabled -AND $MS_Defender_Status.BehaviorMonitorEnabled -AND $MS_Defender_Status.IoavProtectionEnabled -AND $MS_Defender_Status.NISEnabled -AND $MS_Defender_Status.IsTamperProtected ) {
    $ReturnMsg =  "Windows Defender:Enabled - Mode:"+$MS_Defender_Status.AMRunningMode+" - Ver:"+$MS_Defender_Status.AMProductVersion+" - Last Full Scan:"+$MS_Defender_Status.FullScanEndTime.Day.ToString("00")+"-"+$MS_Defender_Status.FullScanEndTime.Month.ToString("00")+"-"+$MS_Defender_Status.FullScanEndTime.Year.ToString("0000")+" "+$MS_Defender_Status.FullScanEndTime.hour.ToString("00")+":"+$MS_Defender_Status.FullScanEndTime.Minute.ToString("00")+" - Last Quick Scan:"+$MS_Defender_Status.QuickScanEndTime.Day.ToString("00")+"-"+$MS_Defender_Status.QuickScanEndTime.Month.ToString("00")+"-"+$MS_Defender_Status.QuickScanEndTime.Year.ToString("0000")+" "+$MS_Defender_Status.QuickScanEndTime.hour.ToString("00")+":"+$MS_Defender_Status.QuickScanEndTime.Minute.ToString("00")
    $ReturnValue += New-SVTestResult "Antivirus Installed" $ReturnMsg $true
    }
else {
    if ( $MS_Defender_Status.DefenderSignaturesOutOfDate ) { $ReturnValue += New-SVTestResult "Antivirus Installed" "Defender Signatures Up2Date" $False}
    if ( -NOT $MS_Defender_Status.AntivirusEnabled ) { $ReturnValue += New-SVTestResult "Antivirus Installed" "AntiVirus Enabled" $False}
    If ( ($MS_Defender_Status.AntivirusSignatureLastUpdated).Ticks -lt (get-date).AddDays(-1).Ticks) { $ReturnValue += New-SVTestResult "Antivirus Installed" "Antivirus Signature Up2Date" $False}
    if ( -NOT $MS_Defender_Status.AntispywareEnabled ) { $ReturnValue += New-SVTestResult "Antivirus Installed" "AntiSpyware Enabled" $False}
    If ( ($MS_Defender_Status.AntispywareSignatureLastUpdated).Ticks -lt (get-date).AddDays(-1).Ticks) { $ReturnValue += New-SVTestResult "Antivirus Installed" "AntiSpyware Signature Up2Date" $False}
    if ( -NOT $MS_Defender_Status.BehaviorMonitorEnabled ) { $ReturnValue += New-SVTestResult "Antivirus Installed" "BehaviorMonitor Enabled" $False}
    if ( -NOT $MS_Defender_Status.IoavProtectionEnabled ) { $ReturnValue += New-SVTestResult "Antivirus Installed" "IoavProtection Enabled" $False}
    if ( -NOT $MS_Defender_Status.NISEnabled ) { $ReturnValue += New-SVTestResult "Antivirus Installed" "NIS Enabled" $False}
    If ( ($MS_Defender_Status.NISSignatureLastUpdated).Ticks -lt (get-date).AddDays(-1).Ticks) { $ReturnValue += New-SVTestResult "Antivirus Installed" "NIS Signature Up2Date" $False}
    if ( -NOT $MS_Defender_Status.IsTamperProtected ) { $ReturnValue += New-SVTestResult "Antivirus Installed" "Tamper Protected" $False}
    If ( ($MS_Defender_Status.FullScanEndTime).Ticks -lt (get-date).AddDays(-31).Ticks) { $ReturnValue += New-SVTestResult "Antivirus Installed" "Last FullScan EndTime" $False}
    If ( ($MS_Defender_Status.QuickScanEndTime).Ticks -lt (get-date).AddDays(-2).Ticks) { $ReturnValue += New-SVTestResult "Antivirus Installed" "Last QuickScan EndTime" $False}
    }

Return New-SVTest "Antivirus" $ReturnValue
}

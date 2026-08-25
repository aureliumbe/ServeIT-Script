function Get-SVVolumeHealth($comp){
#
# NTFS VOlume Health
#
$LogName="system"
$Source="Ntfs"
$Eventid=98
$Message="*NTFS Volume Status*"

$ReturnValue = @()
$ReturnMsg = ""
$StartTime = (Get-date).AddDays(-365)

$Events = Get-WinEvent -FilterHashtable @{LogName=$LogName;ID=$EventId;StartTime=$StartTime} -MaxEvents 1000 -ComputerName $comp -ErrorAction SilentlyContinue

    if ($Events -ne $null) {
        foreach ($item in $events) {
            if ( -NOT ($item.Message -like "*is healthy*") ) {
                $ReturnMsg = $item.message.Substring($item.message.IndexOf('(') + 0)
                $ReturnValue += New-SVTestResult "NTFS Volume Health" $ReturnMsg $false
                }
            }
        }

return New-SVTest "NTFS Volume Health" $ReturnValue
}

function Get-SVDiskspace($server){
     $ReturnValue = @()
    
    Get-WmiObject win32_LogicalDisk -ComputerName $server -Filter "DriveType = '3'" | foreach { 
        $volume = $_.DeviceID
		$free = [decimal]::round($_.Freespace/1024/1024/1024)
		$total=[decimal]::round($_.Size/1024/1024/1024)
		$percent ="" + [decimal]::round($_.FreeSpace/$_.Size*100) + "%"
		$space = "" + $free + "GB/" + $total + "GB: " + $percent
        $OK = if( [decimal]::round($_.FreeSpace/$_.Size*100) -lt 20) {$false} else {$true}
        $ReturnValue += New-SVTestResult $volume $space $OK
    }
    return New-SVTest "Diskspace" $ReturnValue 
}

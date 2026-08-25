Function Get-SVWindowsUptime($comp){
		function ConvertTo-SVDate($Bootup) {
		 [System.Management.ManagementDateTimeconverter]::ToDateTime($Bootup)
		}
        $ReturnValue = @()
		$NameSpace = "Root\CIMV2"
        $wmi = [WMISearcher]""
      	$wmi.options.timeout = '0:0:15' #set timeout to 30 seconds
      	$query = 'Select * from Win32_OperatingSystem'
      	$wmi.scope.path = "\\$comp\$NameSpace"
      
		$wmi.query = $query
		$wmiresult = $wmi.Get()

        foreach ($wmioutput in $wmiresult){
            $Bootup = $wmioutput.LastBootUpTime
            $LastBootUpTime = ConvertTo-SVDate($Bootup)
			$now = Get-Date
            $Reporttime = $now - $lastBootUpTime
            $d = "{0,3}" -f $Reporttime.Days
            $h = "{0,2}" -f $Reporttime.Hours
            $m = "{0,2}" -f $Reporttime.Minutes
            $ms= "{0,2}" -f $Reporttime.Milliseconds
            $a = "{0} days, {1} hours, {2:N0} minutes" -f $d,$h,$m
            if($d -gt 125) {$OK = $false} else {$OK = $true}
            $ReturnValue += New-SVTestResult "Windows Uptime" $a $OK
            return New-SVTest "Uptime" $ReturnValue
		}
}

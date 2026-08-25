function Get-SVAntiSpam($comp){

  $hklm = 2147483650
  $key = "SOFTWARE\Wow6432Node\GFI\MailEssentials\"
  $Version = "Version"
  $Build = "BuildLab"
  $GFI_ME_Version = ""
  $GFI_ME_Build = ""
  $GFI_ME_SubBuild = ""

  $ReturnValue = @()
  $CPUarch =  (Get-WmiObject win32_processor -computername $comp | Where-Object{$_.deviceID -eq "CPU0"}).AddressWidth
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%GFIScanM%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += New-SVTestResult "GFI ME" "Not Installed" $true
      return New-SVTest "GFI Mailessentials" $ReturnValue

      }
  else
      {
          If ([int]$CPUarch -eq 64)
            {
            $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
            $GFI_ME_Version = $wmi.GetStringValue($hklm, $Key, $Version)
            $GFI_ME_Version = $GFI_ME_Version.svalue
            $GFI_ME_Build = $wmi.GetStringValue($hklm, $Key, $Build)
            $GFI_ME_Build = $GFI_ME_Build.svalue
            }
         Else         
            {
            $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
            $GFI_ME_Version = $wmi.GetStringValue($hklm, $Key, $Version)
            $GFI_ME_Version = $GFI_ME_Version.svalue
            $GFI_ME_Build = $wmi.GetStringValue($hklm, $Key, $Build)
            $GFI_ME_Build = $GFI_ME_Build.svalue
            }

         if ($GFI_ME_Version -eq "") {
             $ReturnValue += New-SVTestResult "GFI ME" "Version unknown" $false
             }
         else
            {         
            $RetCode=$GFI_ME_Build
            #GFI_ME_Build="20.0.4837.5918-20150308-1353"
            $GFI_ME_Build=$RetCOde.Split("-")[1]
            $GFI_ME_SubBuild=$RetCOde.Split("-")[2]

            $BuildDateYear  =$GFI_ME_Build.Substring(0,4)
            $BuildDateMonth =$GFI_ME_Build.Substring(4,2)
            $BuildDateDay   =$GFI_ME_Build.Substring(6,2)
            $BuildDate      =$BuildDateYear+"/"+$BuildDateMonth+"/"+$BuildDateDay

            $BuildDateTicks =(get-date "$BuildDate").Ticks
            $TodayMinus365DaysTicks =((Get-Date).AddDays(-365)).Ticks

            $ReturnMsg = "Version " + $GFI_ME_Version + " " + $GFI_ME_Build + " " + $GFI_ME_SubBuild + " installed"
            $ReturnValue += New-SVTestResult "GFI ME" $ReturnMsg $true

            If ($BuildDateTicks -gt $TodayMinus365DaysTicks) {
                #$ReturnValue += New-SVTestResult "GFI Mailessentials Update Check" $val.'PatternDate' $true
                }
            else {
                #$ReturnValue += New-SVTestResult "GFI Mailessentials Update Check" $val.'PatternDate' $false
                }
            }
      }
Return New-SVTest "GFI Anti-SPAM" $ReturnValue
}

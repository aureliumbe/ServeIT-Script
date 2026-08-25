function Get-SVJavaRTE($comp) {

  $ReturnValue = @()
    
  $hklm = 2147483650
  $key_64 = "SOFTWARE\JavaSoft\Java Runtime Environment\"
  $key_32_on_64 = "SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment\"
  $Version = "CurrentVersion"
  $Family6Version = "Java6FamilyVersion"
  $Family7Version = "Java7FamilyVersion"
  $Family8Version = "Java8FamilyVersion"
  $Family9Version = "Java9FamilyVersion"
  
  $JAVA_RTE_x64_Version=""
  $JAVA_RTE_x86_Version=""
  $JAVA_RTE_x64_FamilyVer=""
  $JAVA_RTE_x86_FamilyVer=""
  $JAVA_RTE_x64_SUBVER=""
  $JAVA_RTE_x86_SUBVER=""
  $ReturnMsg=""

  Try {
    $ReturnMsg="Cannot remotely query the CPU Architecture"
    $CPUarch = get-wmiobject -class "Win32_Processor" -namespace "root\cimV2" -computername $comp -ErrorAction Continue    
    $CPUarch = ($CPUarch | Where-Object{$_.deviceID -eq "CPU0"}).AddressWidth
    
    $ReturnMsg="Cannot remotely query the Registry"
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
 
    $ReturnMsg=""
    if ([int]$CPUarch -eq "32") {      
        # Check for Java RTE 32bit version on a 32bit OS

        $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Family9Version)
        $JAVA_RTE_x64_Version9 = $JAVA_RTE_x64_Version.svalue           
        $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Family8Version)
        $JAVA_RTE_x64_Version8 = $JAVA_RTE_x64_Version.svalue           
        $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Family7Version)
        $JAVA_RTE_x64_Version7 = $JAVA_RTE_x64_Version.svalue
        $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Family6Version)
        $JAVA_RTE_x64_Version6 = $JAVA_RTE_x64_Version.svalue

        if ($JAVA_RTE_x64_Version9 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version9 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x64_Version8 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version8 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true            
            }
        elseif ($JAVA_RTE_x64_Version7 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version7 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true            
            }
        elseif ($JAVA_RTE_x64_Version6 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version6 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true            
            }
            else {
                $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Version)
                $JAVA_RTE_x64_Version = $JAVA_RTE_x64_Version.svalue
                if ($JAVA_RTE_x64_Version -ne $null) {
                    $key_SubVersion_x64 = $key_64+$JAVA_RTE_x64_Version
                    $JAVA_RTE_x64_FamilyVer = $wmi.GetStringValue($hklm, $key_SubVersion_x64, "JavaHome")
                    $JAVA_RTE_x64_FamilyVer = $JAVA_RTE_x64_FamilyVer.svalue
                    $pos = $JAVA_RTE_x64_FamilyVer.IndexOf($JAVA_RTE_x64_Version)
                    if ([int]$pos -gt 0) {
                        $JAVA_RTE_x64_SUBVER = $JAVA_RTE_x64_FamilyVer.Substring($pos,($JAVA_RTE_x64_FamilyVer.Length)-$pos)
                        #write-host $JAVA_RTE_x64_Version $JAVA_RTE_x64_FamilyVer $JAVA_RTE_x64_SUBVER

                        $ReturnMsg = "Version " + $JAVA_RTE_x64_SUBVER + " installed"
                        $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true
                        }
                        else {
                            $ReturnValue += New-SVTestResult "Java RTE 32bit" "Not Installed" $true
                            }                
                    }
                }
        }
    else {
        # Check for Java RTE 64bit version on a 64bit OS

        $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Family9Version)
        $JAVA_RTE_x64_Version9 = $JAVA_RTE_x64_Version.svalue           
        $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Family8Version)
        $JAVA_RTE_x64_Version8 = $JAVA_RTE_x64_Version.svalue           
        $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Family7Version)
        $JAVA_RTE_x64_Version7 = $JAVA_RTE_x64_Version.svalue
        $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Family6Version)
        $JAVA_RTE_x64_Version6 = $JAVA_RTE_x64_Version.svalue

        if ($JAVA_RTE_x64_Version9 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version9 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 64bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x64_Version8 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version8 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 64bit" $ReturnMsg $true            
            }
        elseif ($JAVA_RTE_x64_Version7 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version7 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 64bit" $ReturnMsg $true            
            }
        elseif ($JAVA_RTE_x64_Version6 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version6 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 64bit" $ReturnMsg $true            
            }
        else {
            $JAVA_RTE_x64_Version = $wmi.GetStringValue($hklm, $Key_64, $Version)
            $JAVA_RTE_x64_Version = $JAVA_RTE_x64_Version.svalue
            if ($JAVA_RTE_x64_Version -ne $null) {
                $key_SubVersion_x64 = $key_64+$JAVA_RTE_x64_Version
                $JAVA_RTE_x64_FamilyVer = $wmi.GetStringValue($hklm, $key_SubVersion_x64, "JavaHome")
                $JAVA_RTE_x64_FamilyVer = $JAVA_RTE_x64_FamilyVer.svalue
                $pos = $JAVA_RTE_x64_FamilyVer.IndexOf($JAVA_RTE_x64_Version)
                if ([int]$pos -gt 0) {
                    $JAVA_RTE_x64_SUBVER = $JAVA_RTE_x64_FamilyVer.Substring($pos,($JAVA_RTE_x64_FamilyVer.Length)-$pos)
                    $ReturnMsg = "Version " + $JAVA_RTE_x64_SUBVER + " installed"
                    $ReturnValue += New-SVTestResult "Java RTE 64bit" $ReturnMsg $true
                    }
                else {
                    $ReturnValue += New-SVTestResult "Java RTE 64bit" "Not Installed" $true
                    }                
                }
            else {
                $ReturnValue += New-SVTestResult "Java RTE 64bit" "Not Installed" $true
                }
            }
      
        # Check for Java RTE 32bit version on a 64bit OS

        $JAVA_RTE_x86_Version = $wmi.GetStringValue($hklm, $key_32_on_64, $Family9Version)
        $JAVA_RTE_x86_Version9 = $JAVA_RTE_x86_Version.svalue
        $JAVA_RTE_x86_Version = $wmi.GetStringValue($hklm, $key_32_on_64, $Family8Version)
        $JAVA_RTE_x86_Version8 = $JAVA_RTE_x86_Version.svalue
        $JAVA_RTE_x86_Version = $wmi.GetStringValue($hklm, $key_32_on_64, $Family7Version)
        $JAVA_RTE_x86_Version7 = $JAVA_RTE_x86_Version.svalue
        $JAVA_RTE_x86_Version = $wmi.GetStringValue($hklm, $key_32_on_64, $Family6Version)
        $JAVA_RTE_x86_Version6 = $JAVA_RTE_x86_Version.svalue

        if ($JAVA_RTE_x86_Version9 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x86_Version9 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x86_Version8 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x86_Version8 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x86_Version7 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x86_Version7 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x86_Version6 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x86_Version6 + " installed"
            $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true
            }
        else {
            $JAVA_RTE_x86_Version = $wmi.GetStringValue($hklm, $key_32_on_64, $Version)
            $JAVA_RTE_x86_Version = $JAVA_RTE_x86_Version.svalue
            if ($JAVA_RTE_x86_Version -ne $null) {
                $key_SubVersion_x86 = $key_32_on_64+$JAVA_RTE_x86_Version+"\"
                $JAVA_RTE_x86_FamilyVer = $wmi.GetStringValue($hklm, $key_SubVersion_x86, "JavaHome")
                $JAVA_RTE_x86_FamilyVer = $JAVA_RTE_x86_FamilyVer.svalue
                $pos = $JAVA_RTE_x86_FamilyVer.IndexOf($JAVA_RTE_x86_Version)
                if ([int]$pos -gt 0) {
                    $JAVA_RTE_x86_SUBVER = $JAVA_RTE_x86_FamilyVer.Substring($pos,($JAVA_RTE_x86_FamilyVer.Length)-$pos)
                    $ReturnMsg = "Version " + $JAVA_RTE_x86_SUBVER + " installed"
                    $ReturnValue += New-SVTestResult "Java RTE 32bit" $ReturnMsg $true
                    }
                else {
                    $ReturnValue += New-SVTestResult "Java RTE 32bit" "Not Installed" $true
                    }
                }
                else {
                    $ReturnValue += New-SVTestResult "Java RTE 32bit" "Not Installed" $true
                }
            }
      }
    }
    Catch {
        $ReturnValue += New-SVTestResult "Java RTE " $ReturnMsg $false
    }

Return New-SVTest "Java RTE" $ReturnValue
}

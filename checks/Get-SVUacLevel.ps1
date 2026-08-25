function Get-SVUACLevel($server) {
 
  $hklm = 2147483650
  $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  $ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin" 
  $PromptOnSecureDesktop_Name = "PromptOnSecureDesktop" 
  $EnableLUA = "EnableLUA"

  $ReturnValue = @()
  $ReturnMsg = ""
  
  # Check Windows Update Configuration
  $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $server
  
  $EnableLUA_Value = $wmi.GetDWORDValue($hklm, $Key, $EnableLUA)
  $EnableLUA_Value = $EnableLUA_Value.uValue  
  $ConsentPromptBehaviorAdmin_Value = $wmi.GetDWORDValue($hklm, $Key, $ConsentPromptBehaviorAdmin_Name)
  $ConsentPromptBehaviorAdmin_Value = $ConsentPromptBehaviorAdmin_Value.uValue
  $PromptOnSecureDesktop_Value = $wmi.GetDWORDValue($hklm, $Key, $PromptOnSecureDesktop_Name)
  $PromptOnSecureDesktop_Value = $PromptOnSecureDesktop_Value.uValue

    If ($EnableLUA_Value -eq $null -Or $EnableLUA_Value -eq 0) {
        $ReturnMsg = "Disabled"
        $ReturnValue += New-SVTestResult "Windows UAC" $ReturnMsg $false
        }
    elseIf($ConsentPromptBehaviorAdmin_Value -Eq 0 -And $PromptOnSecureDesktop_Value -Eq 0){ 
        $ReturnMsg = "Enabled with Never Notify"
        $ReturnMsg = "Enabled"
        $ReturnValue += New-SVTestResult "Windows UAC" $ReturnMsg $false
    } 
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 0){ 
        $ReturnMsg = "Enabled with Notify Me only when apps try to make changes to My Computer(do not Dim Desktop)"
        $ReturnMsg = "Enabled"
        $ReturnValue += New-SVTestResult "Windows UAC" $ReturnMsg $false
    }
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 1){ 
        $ReturnMsg = "Enabled with Notify Me only when apps try to make changes to My Computer(default)"
        $ReturnMsg = "Enabled"
        $ReturnValue += New-SVTestResult "Windows UAC" $ReturnMsg $true
    } 
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 2 -And $PromptOnSecureDesktop_Value -Eq 1){ 
        $ReturnMsg = "Enabled with Always notify"
        $ReturnMsg = "Enabled"
        $ReturnValue += New-SVTestResult "Windows UAC" $ReturnMsg $true
    } 
    Else{ 
        $ReturnMsg = "Unknown state"
        $ReturnValue += New-SVTestResult "Windows UAC" $ReturnMsg $false
    }
return New-SVTest "Windows UAC" $ReturnValue
}

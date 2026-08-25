Function Get-SVOSLanguage($server) {
$OS = [int](get-WMIObject win32_operatingsystem -computername $server).OSLanguage

switch ($OS) {
    "1043" {$Ret="Dutch"}
    "2067" {$Ret="Dutch"}
    "1033" {$Ret="English"}
    "2057" {$Ret="English"}
    "1036" {$Ret="French"}
    "2060" {$Ret="French"}
    "5132" {$Ret="French"}
    "4108" {$Ret="French"}
    "1031" {$Ret="German"}
    "4103" {$Ret="German"}
    }
return $Ret
}

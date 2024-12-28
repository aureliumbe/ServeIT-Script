#################################################################
####                                                         ####
####                Aurelium ServeIT script                  ####
####                                                         ####
#################################################################


#
# https://community.chocolatey.org/packages/   Check for software versions
#

##################### List of all Functions #####################
# Aget-NTFS_Volume_Health          Eventid: 98 Volume Corruption
# Aget-NPSextension_For_MFA
# Aget-RDS_SG_Members
# Aget-Check_Windows_Defender_ATP
# Aget-CheckWindowsUpdateStatus2
# Aget-Computer_SID
# Aget-AV_FortiClient
# Aget-IPv6_NIC_Settings
# Aget-All_DNS_Servers_IPv6_Address
# Aget-Check_FSLogix
# Aget-Check_TLS_1.2_Protocol
# Aget-Check_Power_Plan
# Aget-Check_IPsecoffload
# Aget-Check_RSS_NIC_SETTING
# Aget-Check_SMB_OPTIMIZED_SETTINGS
# Aget-Check_APC_POWERCHUTE_NETWORK_SHUTDOWN
# Aget-Check_Eaton_IntelligentPowerProtector
# Aget-Check_NIC_VM_QUEUING
# Aget-Check_Remote_Desktop_Connection_Manager($comp)
# Aget-Check_Cache_DB($comp)
# Aget-Check_4_TPM($comp)
# Aget-Check_UEFISecureboot($comp)
# Aget-Check_PrintNightmare($comp) (PrintNightmare Ready)
# Aget-DFSR_SYSVOL_Replication_Health($comp) (events 6013, 2213)
# Aget-Check_SMBv1($comp)
# Aget-SignedOrSecure_Channel_Communication($comp)
# Aget-ADRecycleBin()
# Aget-RDP_NLA($comp)
# Aget-DC_LDAPSSL()
# Aget-RDS_Server($comp)
# Aget-SQL_Server_Instances($comp)
# Aget-WindowsBPA($comp)
# Aget-AAD_Connect_Version($comp)
# Aget-DFSR_SYSVOL_Replication_Migration_State()
# Aget-WindowsDomainFunctionalLevel()
# Aget-WindowsForestFunctionalLevel()
# Aget-DFSR_Replication_Status2() Doesn't work on remote connection :(
# Aget-CheckWindowsDNSSettingsPerNIC2($server)
# Aget-CheckWindowsDNSSettingsPerNIC($server, $WINS_Servers)
# Aget-UACLevel($server)
# Aget-CheckWindowsUpdateStatus($server, $CheckFailedUpdates) 
# Aget-WindowsUpdateSettings($server)
# Aget-FirewallProfile($server)
# Aget-VM_Snapshots($server)
# Aget-DomainAdmins()
# Aget-WindowsServices($server)
# Aget-WindowsTimeSource2($server)
# Aget-WindowsTimeSource($server)
# Aget-WindowsUpdateSetting($server)
# Aget-WindowsUptime($comp)
# Aget-Acronis_Backup($comp)
# Aget-JavaRTE($comp)
# Aget-CarboniteBackup($comp)
# Aget-ArcservUDP_Backup($comp)
# Aget-OODrive_AdBE_Backup($comp)
# Aget-VeeamVMstatusFailed($OrigJobName)
# Aget-VeeamVMstatusSuccess($OrigJobName)
# Aget-Veeam11JobStatus()
# Aget-VeeamJobStatus($Veeam_Version)
# Aget-VeeamPSSnapin()
# Aget-VeeamBackup2($comp)
# Aget-VeeamEndpointBackup($comp)
# Aget-BackupExec4($BEjobs)
# Aget-BackupExec2()
# Aget-BackupExec($comp)
# Aget-MozyBackup($comp)
# Aget-AntiSpam($comp)
# Aget-AntiVirus($comp)
# Aget-No_AV_Installed($comp)
# Aget-AV_SOPHOS($comp)                                               Sophos AV
# Aget-AV_CHECKPOINT_EPP($comp)                                       Checkpoint Endpoint Protection AV
# Aget-AV_ESET($comp)                                                 ESET AV
# Aget-AV_WRSA($comp)                                                 Webroot SecureAnywhere AV
# Aget-AV_MSSE($comp)                                                 Microsoft Security Essentials AV / Windows Defender AV
# Aget-AV_McAfee($comp)                                               McAfee AV
# Aget-AV_SEP($comp)                                                  Symantec AV
# Aget-AV_TM($comp)                                                   Trendmicro AV
# Aget-ScheduledTasks($comp)
# Aget-OSLanguage($server)
# Aget-OSVersion($server)
# Aget-WINS_Servers_Check($server)
# Aget-Get_WINS_Servers() 
# Invoke-Tracert
# Aget-FSMO()
# Aget-PDC()
# Aget-DNS_Forwarders()
# Aget-DNS_Servers2()
# Aget-DNS_Servers()
# Aget-DHCP_Servers_Config()
# Aget-Authorised_DHCP_Servers()
# Aget-Diskspace($server)
# Aget-DefragAnalysis($server)
# Aget-Resolve-DnsName($server)
# Aget-ExchangeMailboxSizes($exchServerName)
# Aget-ExchangeVersion($exchServerName)
# Aget-MailboxDBBackup($exchServerName)
# Aget-MailboxDBSize($exchServerName)
# Aget-exchangeserver()
# Aimport-PSRemotingGPO()
#   Import-module grouppolicy
#   Import-Module "$PSScriptRoot\GPWmiFilter.psm1"
# AFindServerByName($ServerToFind)
# ACreate-TestResult($testitem,$testValue,$testResultaat)
# ACreate-Test($testname,[array]$arrtestresult)
# ACreate-Server($servername)
# Aget-PSRemotingEnabled($comp)
# Import-Module ActiveDirectory
# Import-Module ServerManager
# Awrite-Verbose($text)


# How to use a different (limited) AD SearchBase
# ServeIT.ps1 -verbose -ServersSearchbase "OU=Servers,DC=domain,DC=local"
# ServeIT.ps1 -verbose -ServersSearchbase "OU=My Business,DC=domain,DC=local"
# ServeIT.ps1 -verbose -ServersSearchBase "OU=\+BN,DC=emea,DC=dir"


###############################################
#### ServeIT Script Commandline parameters ####
###############################################
Param(        

    [switch]$Blauwdruk,
    [switch]$CheckDefrag,    
    [switch]$CheckFailedUpdates,
    [switch]$CheckQueuedUpdates,
    [switch]$CheckWindowsBPA,
	[switch]$CreateRemotingGPO,
    [switch]$OutputByServer,
    [String]$ServersSearchbase,
    [switch]$Verbose
)


#################################################################################
#### Check is PS Script is running with admin authorisation, else restart PS ####
#################################################################################
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
if( -not $IsAdmin){ 
    try 
    {  
        $arg = "-file `"$($MyInvocation.ScriptName)`"" 
        Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arg  
    } 
    catch 
    { 
        Write-Warning "Error - Failed to restart script with runas"

        break               
    } 
    exit # Quit this session of powershell  
}


########################################
#### Display ServeIT Script Version ####
########################################
Write-Host "Version 1.8Beta49-122" -ForegroundColor Yellow | Out-Default


#############################################
#### Display Disk Defrag Warning Message ####
#############################################
if($CheckDefrag){
	Write-Host "Defrag Analysis will be runned, this can take some time" -ForegroundColor red | Out-Default
}else{
    Write-Host "Defrag Analysis will not be executed" -ForegroundColor Cyan | Out-Default
}

"" | Out-Default


########################################
#### Verbose Screen Output Function ####
########################################
function Awrite-Verbose($text){
    if($Verbose) {
        Write-Host $text -ForegroundColor DarkGreen | Out-Default
    }
 }


########################################
#### Import AD ServerManager module ####
########################################
Import-Module ServerManager


######################################
#### Install AD Powershell module ####
######################################
"Checking Powershell Modules..." | Out-Default
if ( !(Get-WindowsFeature RSAT-AD-PowerShell).Installed ) { 
    Awrite-Verbose("Installing Powershell Modules")
    Add-WindowsFeature RSAT-AD-PowerShell -Confirm 
}


#####################################
#### Import AD Powershell module ####
#####################################
Import-Module ActiveDirectory


#######################
#### Empty Array's ####
#######################
$Badservers = @()
$Servers = @()
$WINS_Servers = @()


##########################
#### Global Variables ####
##########################
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $LdapDomain = $(([adsisearcher]"").Searchroot.path).split("/")[2]
    $source = "https://gallery.technet.microsoft.com/scriptcenter/Group-Policy-WMI-filter-38a188f3/file/103961/1/GPWmiFilter.psm1"
    }
catch {
    Write-Host "Error initializing default drive: 'Unable to find a default server with Active Directory Web Services running.'"
    Write-Host "AD Webservices of Windows 2012 AD is necessary"
    }

############################################ Common Data ############################################

try {
    Invoke-WebRequest $source -OutFile "$PSScriptRoot\GPWmiFilter.psm1"
    }
Catch
    {
    Write-Host "Invoke-Webrequest is not available in this OS/Powershell Version." -ForegroundColor Red | Out-Default
    }


############################################ Create necessary FUNCTIONS ############################################

###################
#### PreChecks ####
###################
function Aget-PSRemotingEnabled($comp){
    Awrite-Verbose("Checking for powershell remoting on $comp")
    try {
        $ErrorActionPreference = "Stop"
        #$test = Invoke-Command -ComputerName $comp { $true } -ErrorAction Stop -AsJob | Wait-Job -Timeout 1 -ErrorAction Stop | Receive-Job -ErrorAction Stop
        $test = Invoke-Command -ComputerName $comp { 1 }
    } catch {
        Write-Verbose $_
        return $false
    }
    if($test -eq $true) { 
        return $true
      }
    else {
        return $false
        }
 }


#######################################
#### Create ServeIT Script Objects ####
#######################################


##################################
#### Powershell Server Object ####
##################################
function ACreate-Server($servername){
	$server = New-Object psobject
	$testen = @()
    if($servername -ne "Network") {$remoting = Aget-PSRemotingEnabled($servername)} else {$remoting = $false}
    $Server | add-member -Type NoteProperty -name "ServerName" -Value $servername
    $Server | add-member -Type NoteProperty -name "PSRemoting" -Value $remoting
	$Server | add-member -Type NoteProperty -name "Tests" -Value $testen	
	return $server
}


#######################################
#### Powershell Unique Test Object ####
#######################################
function ACreate-Test($testname,[array]$arrtestresult){
	$test = New-Object psobject
	$test | Add-Member -Type noteProperty -Name "testName" -Value $testname 
	$test | Add-Member -Type noteProperty -Name "testResult" -Value $arrtestresult
	return $Test
}


######################################
#### Powershell TestResult Object ####
######################################
function ACreate-TestResult($testitem,$testValue,$testResultaat){
	$testresult = New-Object psobject
	$testresult | Add-Member -Type noteProperty -Name "testItem" -Value $testItem
	$testresult | Add-Member -Type noteProperty -Name "testValue" -Value $testValue 
	$testresult | Add-Member -Type noteProperty -Name "testResultaat" -Value $testResultaat 
	return $testresult 
}


##############################
### AD Find Server By Name ###
##############################
Function AFindServerByName($ServerToFind){
	foreach($serv in $Servers){
		if($serv.servername -eq $ServerToFind){
			return $serv
		}
	}
}


#########################################
#### Create Aurelium PS Remoting GPO ####
#########################################
Function  Aimport-PSRemotingGPO(){
	import-module grouppolicy
	Import-Module "$PSScriptRoot\GPWmiFilter.psm1"
	
	$CreateGPO = $true
	get-gpo -all | foreach{
		if ($_.DisplayName -eq "Aurelium PS Remoting GPO"){$CreateGPO = $false}
	}
	if ($CreateGPO){
		$CreateWMIFilter = $true
		get-GPWmiFilter -all | foreach{
			if ($_.Name -eq "AureliumServerFilter"){$CreateWMIFilter = $false}
		}
		if ($CreateWMIFilter){
			#create WMI Filter
			$psGPOfilter = New-GPWmiFilter -Name "AureliumServerFilter" -Expression 'select * from Win32_OperatingSystem where (ProductType > "1")' -Description 'Queries for the Domain Servers' -PassThru
		}else{
			$psGPOfilter = get-GPWmiFilter -Name "AureliumServerFilter"
		}
		
		#Create GPO + Link to AD
		$psGPO = new-gpo -name "Aurelium PS Remoting GPO" 
		$psGPO | new-gplink -target $LdapDomain 

		#Link filter aan GPO
		$psGPO.WmiFilter = $psGPOfilter

		#Create GPO settings
		Set-GPRegistryValue -Name "Aurelium PS Remoting GPO" -key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName AllowAutoConfig -Type DWORD -value 1
		Set-GPRegistryValue -Name "Aurelium PS Remoting GPO" -key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName IPv4Filter -Type String -value *
		Set-GPRegistryValue -Name "Aurelium PS Remoting GPO" -key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName IPv6Filter -Type String -value *
		Set-GPRegistryValue -Name "Aurelium PS Remoting GPO" -key "HKLM\Software\Policies\Microsoft\WindowsFirewall" -ValueName PolicyVersion -Type Dword -value 522
		Set-GPRegistryValue -Name "Aurelium PS Remoting GPO" -key "HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName WINRM-HTTP-Compat-In-TCP -Type String -value "v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|App=System|Name=@FirewallAPI.dll,-35001|Desc=@FirewallAPI.dll,-35002|EmbedCtxt=@FirewallAPI.dll,-30252|"
		Set-GPRegistryValue -Name "Aurelium PS Remoting GPO" -key "HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName WINRM-HTTP-In-TCP -Type String -value "v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5985|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30252|"
	}
} 


#############################################
#### Get Exchange Server(s) in AD DOmain ####
#############################################
Function Aget-exchangeserver(){
    $ExchServers=@()
    add-type -assemblyName "System.DirectoryServices"

    $AdsiQueryServ = "LDAP://CN=Microsoft Exchange,CN=Services,CN=Configuration,$LdapDomain"
    $root = new-object system.DirectoryServices.Directoryentry $adsiQueryServ
#DGO if (...
    if ($root.distinguishedname -ne $null) {
    $searcher = new-object system.DirectoryServices.DirectorySearcher
    $searcher.searchRoot = $root
    $searcher.filter = "objectClass=msExchExchangeServer"
    $result = $searcher.findall()

    foreach($obj in $result){
		$isTransport = $obj.properties.objectclass
        if("$isTransport" -eq "top server msExchExchangeServer"){
        	$prop = $obj.properties
        	$ExchServers += $prop.cn
		    }
        }
    }
    return $ExchServers
}


####################################
#### Get Exchange Database Size ####
####################################
function Aget-MailboxDBSize($exchServerName){

    #$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $exchServerName -ErrorAction Continue    
    #foreach ($proc in $processes) {
    #if ($proc.name -like "store.exe") {
    #    }
        
    $objResult = New-Object System.Object

    #error opvang !!
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServerName.$domain/PowerShell/ -Authentication Kerberos
    try {
        # import-pssession : No command proxies have been created, because all of the requested remote commands would shadow existing local commands.
        # Use the AllowClobber parameter if you want to shadow existing local commands.
        $retcode = import-pssession $session -AllowClobber
        }
    catch{}
    #Import-PSSession $session -DisableNameChecking | Out-Null

    $DBs = Get-MailboxDatabase -Status | Select Name, DatabaseSize, AvailableNewMailboxSpace
           
    foreach($db in $dbs){
        $naam =$db.Name 
        $size =$db.DatabaseSize
        if ($db.DatabaseSize -eq $null) {
            $size="NULL"
            }
        $freespace = $db.AvailableNewMailboxSpace
        $objResult | Add-Member -type NoteProperty -name $naam -value $size
    }

    $DBs = Get-PublicFolderDatabase -Status|Select Name, DatabaseSize,AvailableNewMailboxSpace
    foreach($db in $dbs){
        $naam =$db.Name 
        $size =$db.DatabaseSize
        if ($db.DatabaseSize -eq $null) {
            $size="NULL"
            }
        $freespace = $db.AvailableNewMailboxSpace
        $objResult | Add-Member -type NoteProperty -name $naam -value $size
    }
    # Enter-PSSession -computername $exchServerName
    # or
    # $session = New-PSSession -ComputerName $exchServerName
    # Enter-PSSession -Session $session
    # Exit-PSSession

    #Remove-PSSession $session
    Remove-PSSession -Session (Get-PSSession)
    return $objResult
}


##############################################
#### Get Exchange Last Full Backup Status ####
##############################################
function Aget-MailboxDBBackup($exchServerName){
    $objResult = New-Object System.Object

    #error opvang
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServerName.$domain/PowerShell/ -Authentication Kerberos
    try {
        # import-pssession : No command proxies have been created, because all of the requested remote commands would shadow existing local commands.
        # Use the AllowClobber parameter if you want to shadow existing local commands.
        $retcode = import-pssession $session -AllowClobber
        }
    catch{}

    # Exchange 2010 Powershell Module
    #add-pssnapin Microsoft.Exchange.Management.PowerShell.E2010

    $DBs = Get-MailboxDatabase -Status |Select Name, last*
    foreach($db in $dbs){
        $naam =$db.Name 
        $fullbackup =$db.LastFullBackup
        if ($db.LastFullBackup -eq $null) {
            $fullbackup="NULL"
            }
        $objResult | Add-Member -type NoteProperty -name $naam -value $Fullbackup
    }
    $DBs = Get-PublicFolderDatabase -Status|Select Name, last*
    foreach($db in $dbs){
        $naam =$db.Name 
        $fullbackup =$db.LastFullBackup
        if ($db.LastFullBackup -eq $null) {
            $fullbackup="NULL"
            }
        $objResult | Add-Member -type NoteProperty -name $naam -value $FullBackup
    }
    # Enter-PSSession -computername $exchServerName
    # or
    # $session = New-PSSession -ComputerName $exchServerName
    # Enter-PSSession -Session $session
    # Exit-PSSession

    #Remove-PSSession $session
    Remove-PSSession -Session (Get-PSSession)
    return $objResult
}


#####################################
#### Get Exchange Server Version ####
#####################################
function Aget-ExchangeVersion($exchServerName){
    $objResult = New-Object System.Object
#    $exchservername = "ebf-mail-01"
#    $domain = "ebf.local"
    
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServerName.$domain/PowerShell/ -Authentication Kerberos
    $retcode = import-pssession $session -AllowClobber
    
    $Exch_Version = Invoke-Command -ComputerName $exchservername -ScriptBlock {Get-Command  Exsetup.exe | ForEach-Object {$_.FileversionInfo}}
    $objResult | Add-Member -type NoteProperty -name $exchservername -value $Exch_Version.ProductVersion
    
    # Enter-PSSession -computername $exchServerName
    # or
    # $session = New-PSSession -ComputerName $exchServerName
    # Enter-PSSession -Session $session
    # Exit-PSSession

    #Remove-PSSession $session
    Remove-PSSession -Session (Get-PSSession)
    return $objResult
}


###################################
#### Get Exchange Mailbox Size ####
###################################
function Aget-ExchangeMailboxSizes($exchServerName){
    #$MBs = @()
    $MB = ""
    $objResult = New-Object System.Object

    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$exchServerName.$domain/PowerShell/ -Authentication Kerberos
    try {
        # import-pssession : No command proxies have been created, because all of the requested remote commands would shadow existing local commands.
        # Use the AllowClobber parameter if you want to shadow existing local commands.
        $retcode = import-pssession $session -AllowClobber
        }
    catch{}
    #$MBs = Get-mailbox -ResultSize Unlimited | get-mailboxstatistics | sort-object totalitemsize -descending | ft displayname,itemcount,totalitemsize
    $MBs = Get-mailbox -ResultSize Unlimited | Get-MailboxStatistics | Select-Object DisplayName, @{Name="TotalItemSizeMB"; Expression={[math]::Round(($_.TotalItemSize.ToString().Split("(")[1].Split(" ")[0].Replace(",","")/1MB),0)}}, ItemCount | Sort-Object TotalItemSizeMB -Descending | ft DisplayName,ItemCount,TotalItemSizeMB

    # Enter-PSSession -computername $exchServerName
    # or
    # $session = New-PSSession -ComputerName $exchServerName
    # Enter-PSSession -Session $session
    # Exit-PSSession

    #Remove-PSSession $session
    Remove-PSSession -Session (Get-PSSession)
    return $MBs
}


########################################
#### Resolve Hostname to IP Address ####
########################################
function Aget-Resolve-DnsName($server) {

    $ns = nslookup $server
    $ServerIP = $ns.split(":")[8].trim()

return $ServerIP
}


################################
#### Get Disk Fragmentation ####
################################
#
# Attention, can take a lot of time to complete
#
function Aget-DefragAnalysis($server){
    $ReturnValue = @()

    $volumes = @(gwmi Win32_Volume -ComputerName $server -Filter 'DriveType = 3')
    foreach ($volume in $volumes) {
        $analysis = $volume.DefragAnalysis().DefragAnalysis
        
	    $dlfse = ([decimal]($analysis.LargestFreeSpaceExtent))
	    $vols = ""
	    $i = 0
	    While ($dlfse -gt 1000) {
	        $i = $i + 1
	        $dlfse = ([decimal]::round($dlfse) / 1024)
	    }
	    switch ($i)
	        {
	        0 { $dlfsepostfix = "B" }
	        1 { $dlfsepostfix = "KB" }
	        2 { $dlfsepostfix = "MB" }
	        3 { $dlfsepostfix = "GB" }
	        4 { $dlfsepostfix = "TB" }
	        }
	    $objVal = "Frag.Files: " + $analysis.TotalFragmentedFiles + "- Frag.Folders: " + $analysis.FragmentedFolders + "- Pagefile fragm.: " + $analysis.TotalPageFileFragments + "- MFT fragm.: " + $analysis.TotalMFTFragments + " - Percent fragm.: " + $analysis.TotalPercentFragmentation + "% - Largest Freespace: " + ([decimal]::round($dlfse)) + $dlfsepostfix
        if($analysis.TotalPercentFragmentation -gt 5) {$ok = $false} else {$ok = $true}
		#$ReturnValue += ACreate-TestResult $volume.DriveLetter $objVal $ok	    
	}
    return ACreate-Test "Defrag" $ReturnValue 
}


###################################
#### Get Free/Total Disk Space ####
###################################
function Aget-Diskspace($server){
     $ReturnValue = @()
    
    Get-WmiObject win32_LogicalDisk -ComputerName $server -Filter "DriveType = '3'" | foreach { 
        $volume = $_.DeviceID
		$free = [decimal]::round($_.Freespace/1024/1024/1024)
		$total=[decimal]::round($_.Size/1024/1024/1024)
		$percent ="" + [decimal]::round($_.FreeSpace/$_.Size*100) + "%"
		$space = "" + $free + "GB/" + $total + "GB: " + $percent
        $OK = if( [decimal]::round($_.FreeSpace/$_.Size*100) -lt 20) {$false} else {$true}
        $ReturnValue += ACreate-TestResult $volume $space $OK
    }
    return ACreate-Test "Diskspace" $ReturnValue 
}


#########################################
#### Get DHCP, AD Authorised Servers ####
#########################################
function Aget-Authorised_DHCP_Servers(){
    $ReturnValue = @()
    $ReturnMsg = ""
    $SearchBase="CN=CONFIGURATION,"+$LdapDomain
            
    try {
        $Auth_DHCP_Servers = Get-ADObject -SearchBase $SearchBase -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" | sort
        }
    catch {echo "No Permission to Read DHCP AD_Object"}

    foreach ($DHCP_Server in $Auth_DHCP_Servers) {
        $DHCP_Scopes = ""
        $DHCP_Servername = ((($DHCP_Server.DistinguishedName).split(","))[0]).Split("=")[1]
        if ($DHCP_Servername -notlike "*DhcpRoot*") {
            $FoundDhcp = $False
            try {
                $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $DHCP_Servername -ErrorAction SilentlyContinue
                foreach ($proc in $processes) {
                    if ($proc.name -eq "svchost.exe" ) {
                        $ProcCMD = $proc.CommandLine
                        if ($ProcCMD -ne $null) {
                            If ($ProcCMD.ToUpper().contains('DHCP') ) {
                                $FoundDhcp = $True
                                }
                            }
                        }
                    }
                }
            catch{}

          If ($FoundDhcp) {
                $ReturnValue += ACreate-TestResult $DHCP_Servername.ToUpper() "DHCP Server Responding" $true
                }
            else{
                $ReturnValue += ACreate-TestResult $DHCP_Servername.ToUpper() "DHCP Server Not Responding" $false
                }
            }
        }
             
               
return ACreate-Test "DHCP Authorized Servers" $ReturnValue
}


#######################################
#### Get DHCP Server Configuration ####
#######################################
function Aget-DHCP_Servers_Config(){
    $ReturnValue = @()
    $ReturnMsg = ""
    $SearchBase="CN=CONFIGURATION,"+$LdapDomain
    
    try {
        $Auth_DHCP_Servers = Get-ADObject -SearchBase $SearchBase -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" | sort
        }
    catch {echo "No Permission to Read DHCP AD_Object"}

    foreach ($DHCP_Server in $Auth_DHCP_Servers) {
        $DHCP_Scopes = ""
        $DHCP_Servername = ((($DHCP_Server.DistinguishedName).split(","))[0]).Split("=")[1]
        if ($DHCP_Servername -notlike "*DhcpRoot*") {
            if((Test-Connection -ComputerName $DHCP_Servername -Count 1 -Quiet) -eq $false) {
                }
            else{
                $DHCP_Server_Dump = Invoke-Command -ComputerName $DHCP_Servername -ScriptBlock {netsh dhcp server dump all}
                foreach ($item in $DHCP_Server_Dump) {
                    if ($item -match ("Dhcp Server \\\\$DHCP_Servername add scope") -gt 0) {
                        $pos = $item.indexof("add scope ")
                        if ($pos -gt 0) {
                            #echo $item.substring($pos+10)
                            $Server_Scope_Subnet = ($item.substring($pos+10)).split(" """)[0]
                            $Server_Scope_SubnetMask = ($item.substring($pos+10)).split(" """)[1]
                            #$temp_item = $item.substring($pos+10+$scope_subnet.length+1+$Scope_SubnetMask.length+1)
                            $Server_Scope_Name = ($item.substring($pos+10)).split("""")[1]
                            $Server_Scope_Description = ($item.substring($pos+10)).split("""")[3]
                            }

                        $ReturnMsg = "$DHCP_Servername.ToUpper() DHCP Scope: $Server_Scope_Subnet $Server_Scope_SubnetMask $Server_Scope_Name $Server_Scope_Description"
                        $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                        #
                        # End of if ($item -match ("Dhcp Server \\\\$DHCP_Servername add scope") -gt 0)
                        #
                        }

                    if ($item -match ("Dhcp Server \\\\$DHCP_Servername set optionvalue") -gt 0) {
                        # 3 "Router" IPADDRESS 1 comment="Array of router addresses ordered by preference" 0.0.0.0
                        # 4 "Time Server" IPADDRESS 1 comment="Array of time server addresses, by preference" 0.0.0.0
                        # 5 "Name Servers" IPADDRESS 1 comment="Array of name servers [IEN 116], by preference" 0.0.0.0
                        # 6 "DNS Servers" IPADDRESS 1 comment="Array of DNS servers, by preference" 0.0.0.0
                        #15 "DNS Domain Name" STRING 0 comment="DNS Domain name for client resolutions" ""
                        #44 "WINS/NBNS Servers" IPADDRESS 1 comment="NBNS Address(es) in priority order" 0.0.0.0
                        #46 "WINS/NBT Node Type" BYTE 0 comment="0x1 = B-node, 0x2 = P-node, 0x4 = M-node, 0x8 = H-node" 0
                        #51 "Lease" DWORD 0 comment="Client IP address lease time in seconds" 0
                        $pos = $item.indexof("set optionvalue 3 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_Router = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option:  3 Router: $DhcpServerOption_Router"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 4 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_TimeServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option:  4 Timeservers: $DhcpServerOption_TimeServers"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 5 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_NameServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option:  5 Nameservers: $DhcpServerOption_NameServers"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 6 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_DNSServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option:  6 DNS Servers: $DhcpServerOption_DNSServers"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 15 STRING")
                        if ($pos -gt 0) {
                            $DhcpServerOption_DomainName = ($item.substring($pos+26))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option: 15 DomainName: $DhcpServerOption_DomainName"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 44 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpServerOption_WINSServers = ($item.substring($pos+29))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option: 44 WINS Servers: $DhcpServerOption_WINSServers"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 46 BYTE")
                        if ($pos -gt 0) {
                            $DhcpServerOption_WINSNodeType = ($item.substring($pos+24))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option: 46 WINS Node Type: $DhcpServerOption_WINSNodeType"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 51 DWORD")
                        if ($pos -gt 0) {
                            $DhcpServerOption_DHCPLease = ($item.substring($pos+25))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Server Option: 51 DHCP Lease(s): $DhcpServerOption_DHCPLease"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        #
                        # End of if ($item -match ("Dhcp Server \\\\$DHCP_Servername set optionvalue") -gt 0)
                        #
                        }


                    if ($item -match ("Dhcp Server \\\\$DHCP_Servername scope $Server_Scope_Subnet set optionvalue") -gt 0) {
                        # 3 "Router" IPADDRESS 1 comment="Array of router addresses ordered by preference" 0.0.0.0
                        # 4 "Time Server" IPADDRESS 1 comment="Array of time server addresses, by preference" 0.0.0.0
                        # 5 "Name Servers" IPADDRESS 1 comment="Array of name servers [IEN 116], by preference" 0.0.0.0
                        # 6 "DNS Servers" IPADDRESS 1 comment="Array of DNS servers, by preference" 0.0.0.0
                        #15 "DNS Domain Name" STRING 0 comment="DNS Domain name for client resolutions" ""
                        #44 "WINS/NBNS Servers" IPADDRESS 1 comment="NBNS Address(es) in priority order" 0.0.0.0
                        #46 "WINS/NBT Node Type" BYTE 0 comment="0x1 = B-node, 0x2 = P-node, 0x4 = M-node, 0x8 = H-node" 0
                        #51 "Lease" DWORD 0 comment="Client IP address lease time in seconds" 0                        
                        $pos = $item.indexof("set optionvalue 3 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_Router = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  3 Router: $DhcpScopeOption_Router"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 4 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_TimeServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  4 Timeservers: $DhcpScopeOption_TimeServers"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 5 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_NameServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  5 Nameservers: $DhcpScopeOption_NameServers"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 6 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_DNSServers = ($item.substring($pos+28))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  6 DNS Servers: $DhcpScopeOption_DNSServers"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 15 STRING")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_DomainName = ($item.substring($pos+26))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option:  7 DomainName: $DhcpScopeOption_DomainName"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 44 IPADDRESS")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_WINSServers = ($item.substring($pos+29))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option: 44 WINS Servers: $DhcpScopeOption_WINSServers"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 46 BYTE")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_WINSNodeType = ($item.substring($pos+24))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option: 46 WINS Node Type: $DhcpScopeOption_WINSNodeType"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        $pos = $item.indexof("set optionvalue 51 DWORD")
                        if ($pos -gt 0) {
                            $DhcpScopeOption_DHCPLease = ($item.substring($pos+25))
                            $ReturnMsg = "$DHCP_Servername.ToUpper() Scope $Server_Scope_Subnet Scope Option: 51 DHCP Lease(s): $DhcpScopeOption_DHCPLease"
                            $ReturnValue += ACreate-TestResult "DHCP Server Config" $ReturnMsg $true
                            }

                        #
                        # End of if ($item -match ("Dhcp Server \\\\$DHCP_Servername scope $Server_Scope_Subnet set optionvalue") -gt 0)
                        #
                        }
                    }

                #
                # End of if((Test-Connection -ComputerName $DHCP_Servername -Count 1 -Quiet) -eq $true)
                #
                }

            #
            # End of if ($DHCP_Servername -notlike "*DhcpRoot*")
            #
            }

        #
        # foreach ($DHCP_Server in $Auth_DHCP_Servers)
        #
        }
        
return ACreate-Test "DHCP Server Config" $ReturnValue
}


#################################################
###### Get DNS Servers v2 in the AD Domain ######
#################################################
function Aget-DNS_Servers(){
    $ReturnValue = @()
    $ns = nslookup $domain | sort
    $ns = "" + $ns
    $i= 1
    $ips = @()
    do{
        if($ns.split(":")[4].split(" ")[$i].trim() -ne ""){
            $ips += $ns.split(":")[4].split(" ")[$i].trim()
        }
        $i = $i +1
    }while($i -ne ($ns.split(":")[4].split(" ").count))

    foreach($ip in $ips){
        if(((Get-WmiObject win32_operatingsystem).version.split(".")[0] -gt 5)-and((Get-WmiObject win32_operatingsystem).version.split(".")[1] -gt 2)){
            #test-netconnectio bestaat pas vanaf windows 8 vandaar deze check
            $test1 = Test-NetConnection -ComputerName $ip -Port 53 -WarningAction SilentlyContinue
            If ($test1.TcpTestSucceeded -and $test1.PingSucceeded){
                $ReturnValue += ACreate-TestResult "$ip" "DNS" $true
            }else{
                if($test1.TcpTestSucceeded){
                    $ReturnValue += ACreate-TestResult "$ip" "No Ping" $false
                }else{
                    if($test1.PingSucceeded){
                        $ReturnValue += ACreate-TestResult "$ip" "No DNS servcice" $false
                    }else{
                        $ReturnValue += ACreate-TestResult "$ip" "Whole test failed" $false
                    }
                }
            }
        }else{
            #indien er een versie lager dan windows 8 is, enkel ping check.
            if((Test-Connection -ComputerName $ip -Count 1 -Quiet) -eq $false){
                $ReturnValue += ACreate-TestResult "$ip" "Whole test failed" $false
            }else{
                $ReturnValue += ACreate-TestResult "$ip" "DNS" $true
            }
        }
    }
    return ACreate-Test "DNS Servers" $ReturnValue
}


#################################################
###### Get DNS Servers v2 in the AD Domain ######
#################################################
function Aget-DNS_Servers2(){
    $ReturnValue = @()
    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0 
    $ips = @()
    $nstemp = $ns
    
    do  {        
        $pos = $nstemp.IndexOf(":")
        if ($pos -gt -1) {
            $nstemp = $nstemp.Substring($pos+1)
            }
        } while ($pos -gt -1)
    $nstemp = $nstemp.Trim()

    do  {
       if ($nstemp.split(" ")[$i].trim() -ne "") {
            $ips += $nstemp.split(" ")[$i].trim()
            }
       $i = $i +1
        } while ($i -ne ($nstemp.split(" ").count))

    foreach ($ip in $ipaddr) { 
        if ($ip.InterfaceAlias -notlike "Loopbac*") {
            $ip.ipaddress
            }
        }

    foreach ($ip in $ips | sort) {    

        #if ( [int]$OS_Version -gt 62 ) {
        $PSver = (Get-Host).Version.major
        if ( $PSver -gt 3) {
            try {
                #test-netconnectio bestaat pas vanaf windows 8 vandaar deze check
                $TcpTest = Test-NetConnection -ComputerName $ip -Port 53 -WarningAction SilentlyContinue
                $PingTest = Test-NetConnection -ComputerName $ip -WarningAction SilentlyContinue
                If ($TcpTest.TcpTestSucceeded -and $PingTest.PingSucceeded) {
                    $ReturnValue += ACreate-TestResult "$ip" "DNS" $true
                    }
                else {
                    if ($TcpTest.TcpTestSucceeded) {
                        $ReturnValue += ACreate-TestResult "$ip" "No Ping" $false
                        }
                    else {
                        if ($PingTest.PingSucceeded) {
                            $ReturnValue += ACreate-TestResult "$ip" "No DNS servcice" $false
                            }
                        else {
                            $ReturnValue += ACreate-TestResult "$ip" "Whole test failed" $false
                            }
                        }
                    }
                }
            catch {
                #If Powershell Version is older than 4.0, do only the ping check.
                if((Test-Connection -ComputerName $ip -Count 1 -Quiet) -eq $false) {
                    $ReturnValue += ACreate-TestResult "$ip" "Whole test failed" $false
                    }
                else {
                    $ReturnValue += ACreate-TestResult "$ip" "DNS" $true
                    }            
                }
            }
        else {
            #If Powershell Version is older than 4.0, do only the ping check.
            if((Test-Connection -ComputerName $ip -Count 1 -Quiet) -eq $false) {
                $ReturnValue += ACreate-TestResult "$ip" "Whole test failed" $false
                }
            else {
                $ReturnValue += ACreate-TestResult "$ip" "DNS" $true
                }
            }
        }
return ACreate-Test "DNS Servers" $ReturnValue
}


#################################################
###### Get DNS Forwarders in the AD Domain ######
#################################################
function Aget-DNS_Forwarders(){
$ReturnValue = @()
#   DNS server settings
#   DGO: Only test on Accessable DC's
#
    #$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    foreach ($dc in ($domain.DomainControllers.name | sort) ) {
        $dnsconfig = Invoke-Command -ComputerName $dc -ScriptBlock {dnscmd /exportsettings ; type "C:\Windows\System32\dns\DnsSettings.txt"}
        #$dnsforwarders.IPAddress
        foreach ($line in $dnsconfig) {
            if ($line -like "*Forwarders=ADDRLISt:*") {
                #echo $line
                $DNSfwdrs = $line.split(":")[1]
                }
            }
        $DNSfwdrs = $DNSfwdrs.replace(",",", ")
        $ReturnMsg = $dc.ToUpper() + " -> " + $DNSfwdrs
        #echo $ReturnMsg
        $ReturnValue += ACreate-TestResult "DNS Forwarders" $ReturnMsg $true
        }

return ACreate-Test "DNS Forwarders" $ReturnValue
}


###############################
###### Get AD PDC Server ######
###############################
function Aget-PDC() {
    $ReturnValue = @()

    $temp_pdc = netdom /query pdc
    foreach ($item in $temp_pdc) {
        if ($item -notlike "Primary domain controller for the domain*") {
            if ($item -ne "") {
                if ($item -notlike "The Command completed successfully*") {
                    $ReturnValue += ACreate-TestResult "Primary Domain Controller" $item $true
                    }
                }
            }
        }
return ACreate-Test "Primary Domain Controller" $ReturnValue
}


#################################
###### Get AD FSMO Servers ######
#################################
function Aget-FSMO() {
    $ReturnValue = @()
    $fsmo = @()

    $temp_fsmo = netdom /query fsmo
    foreach ($item in $temp_fsmo) {
        if ($item -notlike "The Command completed successfully*") {
            if ($item -ne "") {
                #$fsmo += $item
                $ReturnValue += ACreate-TestResult "FSMO Roles" $item $true
                }
            }
        }

return ACreate-Test "FSMO Roles" $ReturnValue
}


################################
###### Start a Traceroute ######
################################
function Invoke-Tracert {
    param([string]$RemoteHost)

    tracert -d -h 1 $RemoteHost |ForEach-Object{
        if ($_.Trim() -match "^\d{1,2}\s+") {
            $n,$a1,$a2,$a3,$target,$null = $_.Trim()-split"\s{2,}"
            $target
            }
        }
}


##############################
###### WINS Functions ########
##############################
function Aget-Get_WINS_Servers() {    
    #$WINS_Servers = foreach ($item in $WINS_Servers1) { $item.replace(" - ","|").split("|")[1].trim()}
    
    foreach ($srv in $servers) {
        $WINS_Server_Config = Invoke-Command -ComputerName $srv.servername -ScriptBlock {netsh wins dump}
        if ($WINS_Server_Config.length -ne 0) {
            if ($WINS_Server_Config -like "*Wins Operation failed with Error There are no more endpoints available*") {
                #
                }
            else {
                $WINS_Servers += [System.Net.Dns]::GetHostbyName($srv.ServerName).Addresslist.IPAddressToString
                }
            }
        }
return $WINS_Servers
}


###################################
#### Check WINS Servers Status ####
###################################
function Aget-WINS_Servers_Check($server) {

$ReturnValue = @()
$WINS_Servers1 = @()
$WINS_Servers_Stats = @()
$WINS_Server_VersionMaps = @()
$line = ""
$ResultMsg = ""
$ResultMsg2 = ""
$Replication_Partners = $true

$Language = Aget-OSLanguage $server

$WINS_Server_Config = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins dump}

if ($WINS_Server_Config.length -ne 0) {
    if ($WINS_Server_Config -like "*Wins Operation failed with Error There are no more endpoints available*") {
        $ReturnMsg = "Not Installed"
        $ReturnValue += ACreate-TestResult "WINS Server" $ReturnMsg $true        
        }
    else {
        $WINS_Server_Records = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins server show partner}
    
        # ***You have Read and Write access to the server ....***
        #
        # Currently there is no Replication partner for this WINS Server
        #
        # Command completed successfully.

        foreach ($line in $WINS_Server_Records) {
            if ($line.trim() -like "Currently there is no Replication partner for this WINS Server*") {
                Echo "No replication partners"
                $Replication_Partners = $false
                }
            }

        if ($Replication_Partners) {
            foreach ($line in $WINS_Server_Records) {
                if ($line.trim() -like "Total No. of Active Replication Partner*") {
                    $WINS_Active_Repl_Partners = $line.split(":")[1].trim()
                    }
                if ($line.Trim() -like "* - *") {
                    if ($line.trim() -notlike "Server Name*") {
                        $WINS_Servers1 += $line
                        }
                    }
                }

                $WINS_Server_Statistics = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins server show statistics}
                foreach ($line in $WINS_Server_Statistics) {
                    if ($line.trim() -like "Last planned replication*") {
                        $pos = $line.indexof(":")
                        $WINS_Last_Repl = ($line.substring($pos+1)).trim()
                        }
                    if ($line.trim() -like "No of Successful/Failed Queries*") {
                        $WINS_Queries = $line.split("=")[1].trim()
                        }
                    if ($line.trim() -like "* - *") {
                        if ($line.trim() -notlike "WINS Partner IP Address*") {
                            $WINS_Servers_Stats += $line
                            }
                        }
                    }       
    
                $NowMinus1Hour=(Get-Date).AddHours(-1).Ticks
                if ($Language -eq "English") {
                    $day=$WINS_Last_Repl.split("/")[1].trim()
                    $WINS_Repl_Day = "{0:2}" -f $day
                    $month=$WINS_Last_Repl.split("/")[0].trim()
                    $WINS_Repl_Month = "{0:2}" -f $month
                    }
                elseif ($Language -eq "Dutch" -or $Language -eq "French" -or $Language -eq "German") {
                    $day=$WINS_Last_Repl.split("/")[0].trim()
                    $WINS_Repl_Day = "{0:2}" -f $day            
                    $month=$WINS_Last_Repl.split("/")[1].trim()
                    $WINS_Repl_Month = "{0:2}" -f $month
                    }
                $year=($WINS_Last_Repl.split("/")[2]).split(" ")[0]
                $WINS_Repl_Year = "{0:4}" -f $year
                $WINS_Repl_Time = $WINS_Last_Repl.split(" ")[2]
                $WINS_Repl_Date2=$WINS_Repl_Year+"/"+$WINS_Repl_Month+"/"+$WINS_Repl_Day+" "+$WINS_Repl_Time
                $WINS_Repl_Date=(get-date "$WINS_Repl_Date2").Ticks
        
                $WINS_Server_VerNr = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins server show version}
                foreach ($item in $WINS_Server_VerNr) {
                    if ($item -like "IP Address*") {
                        $WINS_Server_VersionNr = $item.split("=")[2].trim()
                        }
                    } 
        
                if ($WINS_Repl_Date -lt $NowMinus1Hour) {
                    echo "Replication out of sync?"
                    $ReturnMsg = $server + " with " + $WINS_Active_Repl_Partners + " Active Replication Partner(s), VersionNr:" + $WINS_Server_VersionNr + ", Successful/Failed Queries:" +$WINS_Queries + ", last replication within 1 hour"
                    $ReturnValue += ACreate-TestResult "WINS Server" $ReturnMsg $false
                    }
                else {
                    echo "Replication in sync?"
                    $ReturnMsg = $server + " with " + $WINS_Active_Repl_Partners + " Active Replication Partner(s), VersionNr:" + $WINS_Server_VersionNr + ", Successful/Failed Queries:" +$WINS_Queries + ", last replication within 1 hour"
                    $ReturnValue += ACreate-TestResult "WINS Server" $ReturnMsg $true
                    }            
        
                foreach ($item in $WINS_Servers1) {
                    $pos = $item.indexof(" - ")
                    $WINS_SRV_NAME = $item.substring(0,$pos+1).trim()
                    $WINS_SRV_IP = $item.substring($pos+2).split("-").trim()[0]
                    $WINS_SRV_TYPE = $item.substring($pos+2).split("-").trim()[1]
                
                    $WINS_Server_VerNr = Invoke-Command -ComputerName $WINS_SRV_NAME.trim() -ScriptBlock {netsh wins server show version} -ErrorAction SilentlyContinue
                    if ($WINS_Server_VerNr -ne $null) {
                        foreach ($item in $WINS_Server_VerNr) {
                            if ($item -like "IP Address*") {
                                $WINS_Server_VersionNr = $item.split("=")[2].trim()
                                }
                            }
                        $ReturnMsg = "  + WINS Replica Server: " + $WINS_SRV_NAME + " IP: " + $WINS_SRV_IP + " (" + $WINS_SRV_TYPE + "), VersionNr:" + $WINS_Server_VersionNr
                        $ReturnValue += ACreate-TestResult "WINS Server" $ReturnMsg $true
                        }
                    else {
                        $ReturnMsg = "  + WINS Replica Server: " + $WINS_SRV_NAME + " IP: " + $WINS_SRV_IP + " (" + $WINS_SRV_TYPE + "), does not exist"
                        $ReturnValue += ACreate-TestResult "WINS Server" $ReturnMsg $false
                        }
                    }

                $WINS_Server_VersionMappings = Invoke-Command -ComputerName $Server -ScriptBlock {netsh wins server show versionmap}
                foreach ($line in $WINS_Server_VersionMappings) {
                    if ($line.trim() -like "* - *") {
                        if ($line.trim() -notlike "Owner ID*") {
                            $WINS_Server_VersionMaps += $line
                            }
                        }
                    }
                echo "Foreach line in WINS_Server_Records
                }
            echo "There are replication Partners
            }
        else {
            echo "There are No WINS Replication Partners"
            $ReturnMsg = "Installed without Replica"
            $ReturnValue += ACreate-TestResult "WINS Server" $ReturnMsg $true 
            }
        }
    }
else {
    $ReturnMsg = "Not Installed"
    $ReturnValue += ACreate-TestResult "WINS Server" $ReturnMsg $true
    }     

return ACreate-Test "WINS Servers" $ReturnValue
}


##############################
###### Get OS Version ########
##############################
Function Aget-OSVersion($server) {
    $OS_Major_Version = (Get-WmiObject win32_operatingsystem -computername $server).version.split(".")[0]
    $OS_Minor_Version = (Get-WmiObject win32_operatingsystem -computername $server).version.split(".")[1]
    $OS_Version = $OS_Major_Version+$OS_Minor_Version

return $OS_Version
}


#########################
#### Get OS Language ####
#########################
Function Aget-OSLanguage($server) {
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


#####################################
#### Get Windows Scheduled Tasks ####
#####################################
Function Aget-ScheduledTasks($comp){

    	$ReturnValue = @()
	
	    $ST = new-object -com Schedule.Service
        $ST.connect($comp)
        $Rootfolder = $ST.GetFolder("\")
        $ScheduledTasks = $Rootfolder.GetTasks(0)
	    $counter = 0
        foreach ($task in $ScheduledTasks | Select Name, State, Enabled, LastRunTime, LastTaskResult, NextRunTime, @{Name="RunAs";Expression={[xml]$xml = $_.xml ; $xml.Task.Principals.principal.userID}}){
       	    $taskname =$task.Name
            if ($taskname -ne "CreateExplorerShellUnelevatedTask") {
                if ([int]$taskname.Length -gt 30) {
                    $taskname = $taskname.Substring(0,30)
                    }
	            $taskresult=$task.LastTaskResult
                $taskEnabled = $task.Enabled
	            if ((-not( ([int]$taskresult -eq 0) -or ([int]$taskresult -eq 1) )) -and $taskenabled -and ($taskname -notlike "Optimize Start Menu*" -OR $taskname -notlike $CreateExplorerShellUnelevatedTask) ){
                    $counter = $counter +1
                    $ReturnValue += ACreate-TestResult $taskname  $taskresult $false
                    }
                }
            }

	    if ([int]$counter -eq 0){
		    $ReturnValue += ACreate-TestResult "All Tasks" "0" $true
	        }

    return ACreate-Test "Scheduled Tasks" $ReturnValue
}


###################################################
####### Get Trend micro Antivirus Status ##########
###################################################
function Aget-AV_TM($comp){

	$ReturnValue = @()

	#Trendmicro WFBS Variables
	$OfcService_64_Key = "SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.\"
	$OfcService_32_Key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.\"
    $OfcServices_Key = "SYSTEM\CurrentControlSet\Services\TmPreFilter\Parameters\"
	#$OfcService_Version_Key = "ofcservice_ver"
	$Client_Version_Key ="TmListen_Ver"
	$Server_Version_Key = "ofcservice_ver"
	$TmFilter_Version_Key = "TmFilter-Ver"
	$Tm_PatternDate_Key = "PatternDate"
    $UpdateFrom_Key = "UpdateFrom"
    #RCS = DWORD = 101 => 202 (RDS)
    $RCS_Key = "RCS"    
    #EnableMiniFilter = DWORD = 0 => 1 (RDS)
    $EnableMiniFilter_Key = "EnableMiniFilter"
	$Server_Version = ""
	$Client_Version = ""
	$TmFilter_Version = ""
	$Tm_PatternDate = ""
    $UpdateFrom = ""
    $RCS_Val = ""
    $MiniFIlter_Val = ""
    $TM_WFBS_Services = $false
    $Tm_AV_Ok = $false

    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp

	If ([int]$CPUarch -eq 64) {
		# Check for Trendmicro WFBS version on a 64 bit machine TmListen_Ver=19.0.3273          
		$Client_Version = $wmi.GetStringValue($hklm, $OfcService_64_Key, $Client_Version_Key)
		$Client_Version = $Client_Version.svalue
		$Server_Version = $wmi.GetStringValue($hklm, $OfcService_64_Key, $Server_Version_Key)
		$Server_Version = $Server_Version.svalue
		$UpdateFrom = $wmi.GetStringValue($hklm, $OfcService_64_Key, $UpdateFrom_Key)
		$UpdateFrom = $UpdateFrom.svalue
        # RCS_Val = 202 for (RDS/Citrix Server)
        $RCS_Val = $wmi.GetDWORDValue($hklm, $OfcService_64_Key, $RCS_Key)
        $RCS_Val = $RCS_Val.uvalue
		# Check for Trendmicro WFBS version on a 64 bit machine TmFilter_Ver=9.850.1008
		# Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
		$Tm_PatternDate = $wmi.GetStringValue($hklm, $OfcService_64_Key, $Tm_PatternDate_Key)
		$Tm_PatternDate = $Tm_PatternDate.svalue
		}
	Else {
		# Check for Trendmicro WFBS version on a 32 bit machine TmListen_Ver=19.0.3273          
		$Client_Version = $wmi.GetStringValue($hklm, $OfcService_32_Key, $Client_Version_Key)
		$Client_Version = $Client_Version.svalue
		$Server_Version = $wmi.GetStringValue($hklm, $OfcService_32_Key, $Server_Version_Key)
		$Server_Version = $Server_Version.svalue
		$UpdateFrom = $wmi.GetStringValue($hklm, $OfcService_32_Key, $UpdateFrom_Key)
		$UpdateFrom = $UpdateFrom.svalue		# Check for Trendmicro WFBS version on a 32 bit machine TmFilter_Ver=9.850.1008
        # RCS_Val = 202 for (RDS/Citrix Server)
        $RCS_Val = $wmi.GetDWORDValue($hklm, $OfcService_32_Key, $RCS_Key)
        $RCS_Val = $RCS_Val.uvalue
		# Check for Trendmicro WFBS version on a 32 bit machine PatternDate=20160226
		$Tm_PatternDate = $wmi.GetStringValue($hklm, $OfcService_32_Key, $Tm_PatternDate_Key)
		$Tm_PatternDate = $Tm_PatternDate.svalue
		}
    $MiniFilter_Val = $wmi.GetDWORDValue($hklm, $OfcServices_Key, $EnableMiniFilter_Key)
    $MiniFIlter_Val = $MiniFilter_Val.uvalue

	if ($Client_Version -eq "") {
        $Tm_AV_Ok=$false
        $ReturnMsg = "TM WFBS Version unknown"
        }
    else {
        if ([int]$Server_Version.length -eq 0 -AND [int]$Client_Version.length -gt 0 ) {
            $Tm_AV_Ok=$true
            $TM_WFBS_Services = $true
            $ReturnMsg = "WFBS Services Client - Version " + $Client_Version
            #$ReturnValue += ACreate-TestResult "Antivirus installed" $ReturnMsg $true
            }
        else {
            if ([int]$Server_Version.length -gt 0 -AND [int]$Client_Version.length -gt 0 ) {
                $Tm_AV_Ok=$true
                $TM_WFBS_Services = $false
                $ReturnMsg = "WFBS Client/Server(" + $UpdateFrom.split("://")[3] + ") - Version " + $Client_Version + " / " + $Server_Version
                #$ReturnValue += ACreate-TestResult "Antivirus installed" $ReturnMsg $true
                }
            }
          
            $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            

            $PatternYear=$Tm_PatternDate.Substring(0,4)
            $PatternMonth=$Tm_PatternDate.Substring(4,2)
            if ([int]$PatternMonth -gt 12) {
                $PatternMonth=$Tm_PatternDate.Substring(6,2)
                $PatternDay=$Tm_PatternDate.Substring(4,2)
                }
            else {
                $PatternDay=$Tm_PatternDate.Substring(6,2)
                }
            $PatternDate2=$PatternYear+"/"+$PatternMonth+"/"+$PatternDay

            $PatternDate=(get-date "$PatternDate2").Ticks
            #$TodayDate=(get-date).TicksM

            $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2

            if ($PatternDate -gt $TodayMinus7Days) {
                $AV_Ok=$true                
                $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            else {
                $AV_Ok=$false
                $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            
            ######################################
            $RCS_CpmConfig = 0
            try {
                $RDS_Server = Invoke-Command -ComputerName $comp -scriptblock {Import-Module ServerManager; Get-WindowsFeature RDS-RD-Server} -ErrorAction SilentlyContinue
                #If get-windowsfeature RDS-Server gives an error, do following instruction on remote server Import-Module ServerManager
                #$RDS_Server=Get-WmiObject -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" | select -ExpandProperty TerminalServerMode
                }
            catch {}
            if ($RDS_Server.Installed) {
                if ($TM_WFBS_Services) {
                    try {
                        $RCS_CpmConfig_Val = Get-Content -Path "C:\Program Files (x86)\Trend Micro\Client Server Security Agent\HostedAgent\CPM\CpmConfig.ini" | Where-Object { $_ -match 'RCS =' }
                        $RCS_CpmConfig_Val = Invoke-Command -ComputerName $comp -scriptblock {Get-Content -Path "C:\Program Files (x86)\Trend Micro\Client Server Security Agent\HostedAgent\CPM\CpmConfig.ini" | Where-Object { $_ -match 'RCS =' } } -ErrorAction SilentlyContinue
                        }
                    catch {}
                    if ($RCS_CpmConfig_Val) {
                        $RCS_CpmConfig = $RCS_CpmConfig_Val.split("=")[1].trim()
                        #echo $RCS_CpmConfig
                        }                    
                    if ($RCS_Val -eq 202) {
                        $ReturnMsg = "WFBS Services Client - RDS/CTX -> RCS: " + $RCS_Val + " (OK)"
                        }
                    else {
                        $ReturnMsg = "WFBS Services Client - RDS/CTX -> RCS: " + $RCS_Val + " (NOK)"
                        }
                    if ($MiniFilter_Val -eq 1) {
                        $ReturnMsg = $ReturnMsg + " - MiniFilter: " + $MiniFilter_Val + " (OK)"
                        }
                    else {
                        $ReturnMsg = $ReturnMsg + " - MiniFilter: " + $MiniFilter_Val + " (NOK)"
                        }
                    if ($RCS_CpmConfig -eq 1) {
                        $ReturnMsg = $ReturnMsg + " - RCS Services: " + $RCS_CpmConfig + " (OK)"
                        }
                    else {
                        $ReturnMsg = $ReturnMsg + " - RCS Services: " + $RCS_CpmConfig + " (NOK)"
                        }
                    }                    
                else {
                    if ($RCS_Val -eq 202) {
                        $ReturnMsg = "WFBS Client/Server(" + $UpdateFrom.split("://")[3] + ") - RDS/CTX -> RCS: " + $RCS_Val + " (OK)"
                        }
                    else {
                        $ReturnMsg = "WFBS Client/Server(" + $UpdateFrom.split("://")[3] + ") - RDS/CTX -> RCS: " + $RCS_Val + " (NOK)"
                        }
                    if ($MiniFilter_Val -eq 1) {
                        $ReturnMsg = $ReturnMsg + " - MiniFilter: " + $MiniFilter_Val + " (OK)"
                        }
                    else {
                        $ReturnMsg = $ReturnMsg + " - MiniFilter: " + $MiniFilter_Val + " (NOK)"
                        }
                    }
                
                if ($TM_WFBS_Services) {
                    if ( ($MiniFilter_Val -eq 0) -or ($RCS_Val -eq 101) -or ($RCS_CpmConfig -eq 0) ) {
                        $AV_Ok=$false
                        }                
                    }
                else {
                    if ( ($MiniFilter_Val -eq 0) -or ($RCS_Val -eq 101) ) {
                        $AV_Ok=$false
                        }
                    }
                                
                $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            ######################################

        }
    Return ACreate-Test "Antivirus" $ReturnValue
}


####################################################################
####### Get Symantec Endpoint Protection Antivirus Status ##########
####################################################################
function Aget-AV_SEP($comp) {

    $ReturnValue = @()

    #Symantec SEP AV Variables
    $SEP_64_key1 = "SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\"
    $SEP_32_key1 = "SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\"
    $SEP_64_key2 = "SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\"
    $SEP_32_key2 = "SOFTWARE\Symantec\Symantec Endpoint Protection\AV\"
    $SEP_Version_Key = "PRODUCTVERSION"
    $SEP_PatternVersion_Key = "PatternFileDate"
    $SEP_Version = ""
    $SEP_PatternVersion = ""
    $SEP_AV_Ok = $false

    If ([int]$CPUarch -eq 64) {
        # Check for SEP version on a 64 bit machine PRODUCTERSION=12.1.5337.5000, PatternFileDate=46 01 26 00 00 00 00 00 / 46, 8, 8, 0
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $SEP_Version = $wmi.GetStringValue($hklm, $SEP_64_key1, $SEP_Version_Key)
        $SEP_Version = $SEP_Version.svalue
        # Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
        $SEP_PatternVersion = $wmi.GetBinaryValue($hklm, $SEP_64_key2, $SEP_PatternVersion_Key)
        $SEP_PatternVersion = $SEP_PatternVersion.uvalue
        }
    Else {
        # Check for SEP version on a 32 bit machine PRODUCTERSION=12.1.5337.5000, PatternFileDate=46 01 26 00 00 00 00 00
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $SEP_Version = $wmi.GetStringValue($hklm, $SEP_32_key1, $SEP_Version_Key)
        $SEP_Version = $SEP_Version.svalue
        # Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
        $SEP_PatternVersion = $wmi.GetBinaryValue($hklm, $SEP_32_key2, $SEP_PatternVersion_Key)
        $SEP_PatternVersion = $SEP_PatternVersion.uvalue
        }

    if ($SEP_Version -eq "") {
        $SEP_AV_Ok = $false        
        $ReturnMsg = "SEP Unknown Version"       
        }
    else {         
        $ReturnMsg = "SEP version " + $SEP_Version
        #$ReturnValue += ACreate-TestResult "Antivirus installed" $ReturnMsg $true
        if ([int]$SEP_PatternVersion.count -gt 3) {
            $year = $SEP_PatternVersion[0]+1970
            $month = $SEP_PatternVersion[1]+1
            $day = $SEP_PatternVersion[2]
            }
                  $SEP_PatternYear = "{0:D4}" -f $year
                  $SEP_PatternMonth = "{0:D2}" -f $month
                  $SEP_PatternDay = "{0:D2}" -f $day


                  $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            

                  $PatternDate2=$SEP_PatternYear+"/"+$SEP_PatternMonth+"/"+$SEP_PatternDay

                  $PatternDate=(get-date "$PatternDate2").Ticks
                  #$TodayDate=(get-date).Ticks

                  if ($PatternDate -gt $TodayMinus7Days) {
                      $AV_Ok = $true
                      $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                      $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                      }
                  else {
                      $AV_Ok = $false
                      $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                      $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                      }
        }        
    Return ACreate-Test "Antivirus" $ReturnValue            
}


##################################################################
####### Get McAfee Endpoint Protection Antivirus Status ##########
##################################################################
function Aget-AV_McAfee($comp){

    $ReturnValue = @()

    #McAfee McShield AV Variables
    $McAfee_64_key1 = "SOFTWARE\Wow6432Node\McAfee\DesktopProtection\"
    $McAfee_32_key1 = "SOFTWARE\McAfee\DesktopProtection\"
    $McAfee_64_key2 = "SOFTWARE\Wow6432Node\McAfee\AVEngine\"
    $McAfee_32_key2 = "SOFTWARE\McAfee\AVEngine\"
    $McAfee_Version_Key = "szProductVer"
    $McAfee_DatVersion_Key = "AVDatDate"
    $McAfee_Version = ""
    $McAfee_DatVersion = ""

    If ([int]$CPUarch -eq 64){
        # Check for McAfee McShield version on a a 64 bit machine szProductVer=8.8.0.1445, AVDatDate=2016/02/25
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $McAfee_Version = $wmi.GetStringValue($hklm, $McAfee_64_key1, $McAfee_Version_Key)
        $McAfee_Version = $McAfee_Version.svalue
        # Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
        $McAfee_DatVersion = $wmi.GetStringValue($hklm, $McAfee_64_key2, $McAfee_DatVersion_Key)
        $McAfee_DatVersion = $McAfee_DatVersion.svalue
        # Check for McAfee McShield version on a a 64 bit machine szProductVer=8.8.0.1445, AVDatDate=2016/02/25
        }
    else {
        # Check for McAfee McShield version on a a 32 bit machine szProductVer=8.8.0.1445, AVDatDate=2016/02/25
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $McAfee_Version = $wmi.GetStringValue($hklm, $McAfee_32_key1, $McAfee_Version_Key)
        $McAfee_Version = $McAfee_Version.svalue
        # Check for Trendmicro WFBS version on a 64 bit machine PatternDate=20160226
        $McAfee_DatVersion = $wmi.GetStringValue($hklm, $McAfee_32_key2, $McAfee_DatVersion_Key)
        $McAfee_DatVersion = $McAfee_DatVersion.svalue               
            
        }

    if ($McAfee_Version -eq ""){
        $ReturnValue += ACreate-TestResult "Antivirus installed" "McAfee Unknown Version" $false
        #return $ReturnValue
        }
    else {         
              $ReturnMsg = "McAfee Version " + $McAfee_Version

              $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            
              #$McAfee_DatVersion="20170608"

              $PatternYear=$McAfee_DatVersion.Substring(0,4)
              $PatternMonth=$McAfee_DatVersion.Substring(5,2)
              if ([int]$PatternMonth -gt 12) {
                  $PatternMonth=$McAfee_DatVersion.Substring(8,2)
                  $PatternDay=$McAfee_DatVersion.Substring(5,2)
                  }
              else {
                  $PatternDay=$McAfee_DatVersion.Substring(8,2)
                  }
              $PatternDate2=$PatternYear+"/"+$PatternMonth+"/"+$PatternDay

              $PatternDate=(get-date "$PatternDate2").Ticks
              #$TodayDate=(get-date).Ticks

              if ($PatternDate -gt $TodayMinus7Days) {
                  $AV_Ok = $true
                  $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                  $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                  }
              else {
                  $AV_Ok = $false
                  $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                  $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                  }
        }
    Return ACreate-Test "Antivirus" $ReturnValue            
}


#####################################################
##### Get Windows Defender ATP Antivirus Status #####
#####################################################
function Aget-Check_Windows_Defender_ATP($comp){
$ReturnValue = @()
$hklm = 2147483650

$MS_Defender_Status = Invoke-Command -ComputerName $comp -scriptblock {Get-MpComputerStatus | select AMRunningMode, AMProductVersion, AMServiceEnabled, AntispywareEnabled, AntispywareSignatureLastUpdated, AntivirusEnabled, AntivirusSignatureLastUpdated, FullScanStartTime, FullScanEndTime, BehaviorMonitorEnabled,DefenderSignaturesOutOfDate, IoavProtectionEnabled, IsTamperProtected, NISEnabled, NISSignatureLastUpdated, OnAccessProtectionEnabled, RealTimeProtectionEnabled, QuickScanStartTime, QuickScanEndTime, RebootRequired}

if ( $MS_Defender_Status.AMServiceEnabled -AND $MS_Defender_Status.AntivirusEnabled -AND $MS_Defender_Status.AntispywareEnabled -AND $MS_Defender_Status.BehaviorMonitorEnabled -AND $MS_Defender_Status.IoavProtectionEnabled -AND $MS_Defender_Status.NISEnabled -AND $MS_Defender_Status.IsTamperProtected ) {
    $ReturnMsg =  "Windows Defender:Enabled - Mode:"+$MS_Defender_Status.AMRunningMode+" - Ver:"+$MS_Defender_Status.AMProductVersion+" - Last Full Scan:"+$MS_Defender_Status.FullScanEndTime.Day.ToString("00")+"-"+$MS_Defender_Status.FullScanEndTime.Month.ToString("00")+"-"+$MS_Defender_Status.FullScanEndTime.Year.ToString("0000")+" "+$MS_Defender_Status.FullScanEndTime.hour.ToString("00")+":"+$MS_Defender_Status.FullScanEndTime.Minute.ToString("00")+" - Last Quick Scan:"+$MS_Defender_Status.QuickScanEndTime.Day.ToString("00")+"-"+$MS_Defender_Status.QuickScanEndTime.Month.ToString("00")+"-"+$MS_Defender_Status.QuickScanEndTime.Year.ToString("0000")+" "+$MS_Defender_Status.QuickScanEndTime.hour.ToString("00")+":"+$MS_Defender_Status.QuickScanEndTime.Minute.ToString("00")
    $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $true
    }
else {
    if ( $MS_Defender_Status.DefenderSignaturesOutOfDate ) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "Defender Signatures Up2Date" $False}
    if ( -NOT $MS_Defender_Status.AntivirusEnabled ) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "AntiVirus Enabled" $False}
    If ( ($MS_Defender_Status.AntivirusSignatureLastUpdated).Ticks -lt (get-date).AddDays(-1).Ticks) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "Antivirus Signature Up2Date" $False}
    if ( -NOT $MS_Defender_Status.AntispywareEnabled ) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "AntiSpyware Enabled" $False}
    If ( ($MS_Defender_Status.AntispywareSignatureLastUpdated).Ticks -lt (get-date).AddDays(-1).Ticks) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "AntiSpyware Signature Up2Date" $False}
    if ( -NOT $MS_Defender_Status.BehaviorMonitorEnabled ) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "BehaviorMonitor Enabled" $False}
    if ( -NOT $MS_Defender_Status.IoavProtectionEnabled ) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "IoavProtection Enabled" $False}
    if ( -NOT $MS_Defender_Status.NISEnabled ) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "NIS Enabled" $False}
    If ( ($MS_Defender_Status.NISSignatureLastUpdated).Ticks -lt (get-date).AddDays(-1).Ticks) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "NIS Signature Up2Date" $False}
    if ( -NOT $MS_Defender_Status.IsTamperProtected ) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "Tamper Protected" $False}
    If ( ($MS_Defender_Status.FullScanEndTime).Ticks -lt (get-date).AddDays(-31).Ticks) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "Last FullScan EndTime" $False}
    If ( ($MS_Defender_Status.QuickScanEndTime).Ticks -lt (get-date).AddDays(-2).Ticks) { $ReturnValue += ACreate-TestResult "Antivirus Installed" "Last QuickScan EndTime" $False}
    }

Return ACreate-Test "Antivirus" $ReturnValue
}


###############################################################
##### Get Microsoft Security Essentials Antivirus Status ######
###############################################################
function Aget-AV_MSSE($comp) {

    $ReturnValue = @()

    #Microsoft Security Essentials AV Variables
    $MSSE_key1 = "SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates\"
    $MSSE_key2 = "SOFTWARE\Microsoft\Microsoft Antimalware\Signature Updates\"
    $MSSE_Version_Key = "AVSignatureVersion"
    # "AVSignatureApplied"=hex:00,9b,55,8c,89,61,d2,01
    $MSSE_PatternVersion_Key = "AVSignatureApplied"
    # BinaryToDate($MSSE_PatternVersion_Key)
    $MSSE_Version = ""
    $MSSE_PatternVersion = ""
  
    #Microsoft Windows Defender AV Variables (Windows 2016)
    $MSWD_key1 = "SOFTWARE\Microsoft\Windows Defender\Signature Updates\"
    $MSWD_key2 = "SOFTWARE\Microsoft\Windows Defender\Signature Updates\"
    $MSWD_Version_Key = "AVSignatureVersion"
    # "AVSignatureApplied"=hex:00,9b,55,8c,89,61,d2,01
    $MSWD_PatternVersion_Key = "AVSignatureApplied"
    # BinaryToDate($MSSE_PatternVersion_Key)
    $MSWD_Version = ""
    $MSWD_PatternVersion = ""
    $MSSE_AV_Ok = $false
    $MSWD_AV_Ok = $false

    If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $MSSE_Version = $wmi.GetStringValue($hklm, $MSSE_key1, $MSSE_Version_Key)
        $MSSE_Version = $MSSE_Version.svalue
	    If ($MSSE_Version.length -ne 0) {                          
            $MSSE_PatternVersion = $wmi.GetBinaryValue($hklm, $MSSE_key2, $MSSE_PatternVersion_Key)
            $MSSE_PatternVersion = $MSSE_PatternVersion.uvalue
            }
        elseif ([int]$MSSE_Version.length -eq 0) {
            $MSWD_Version = $wmi.GetStringValue($hklm, $MSWD_key1, $MSWD_Version_Key)
            $MSWD_Version = $MSWD_Version.svalue
            If ([int]$MSWD_Version.length -ne 0) {
                $MSWD_PatternVersion = $wmi.GetBinaryValue($hklm, $MSWD_key2, $MSWD_PatternVersion_Key)
                $MSWD_PatternVersion = $MSWD_PatternVersion.uvalue
	            }
            }
            else {
                $AV_Ok = $false        
                $ReturnMsg = "MS Security Essentials/MS Windows Defender Unknown Version"
                #$ReturnValue += ACreate-TestResult "Antivirus installed" "MS Security Essentials/MS Windows Defender Unknown Version" $AV_Ok
				}
            }
	Else {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $MSSE_Version = $wmi.GetStringValue($hklm, $MSSE_key1, $MSSE_Version_Key)
        $MSSE_Version = $MSSE_Version.svalue
		If ($MSSE_Version -ne "") {                          
            $MSSE_PatternVersion = $wmi.GetBinaryValue($hklm, $MSSE_key2, $MSSE_PatternVersion_Key)
            $MSSE_PatternVersion = $MSSE_PatternVersion.uvalue
            }
        elseif ($MSSE_Version -eq "") {
            $MSWD_Version = $wmi.GetStringValue($hklm, $MSWD_key1, $MSWD_Version_Key)
            $MSWD_Version = $MSWD_Version.svalue
            If ($MSWD_Version -ne "") {
                $MSWD_PatternVersion = $wmi.GetBinaryValue($hklm, $MSWD_key2, $MSWD_PatternVersion_Key)
                $MSWD_PatternVersion = $MSWD_PatternVersion.uvalue
		        }
            }
            else {
                $AV_Ok = $false        
                $ReturnMsg = "MS Security Essentials/MS Windows Defender Unknown Version"
                #$ReturnValue += ACreate-TestResult "Antivirus installed" "MS Security Essentials/MS Windows Defender Unknown Version" $AV_Ok
		        }
            }				  

            If ($MSSE_PatternVersion -eq "" -and $MSWD_PatternVersion -eq "" ) {
                $AV_Ok = $false        
                $ReturnMsg = "MS Security Essentials/MS Windows Defender Unknown Version"
                #$ReturnValue += ACreate-TestResult "Antivirus installed" "MS Security Essentials/MS Windows Defender Unknown Version" $AV_Ok
			    }
			Else {
                if ($MSSE_PatternVersion -ne "") {
                    $ReturnMsg = "MS Security Essentials - Version " + $MSSE_Version

                    if ([int]$MSSE_PatternVersion.count -gt 3) {                        
                        $Seconds = $MSSE_PatternVersion[7]*[math]::pow( 2,56) + $MSSE_PatternVersion[6]*[math]::pow( 2,48) + $MSSE_PatternVersion[5]*[math]::pow( 2,40) + $MSSE_PatternVersion[4]*[math]::pow( 2,32) + $MSSE_PatternVersion[3]*[math]::pow( 2,24) + $MSSE_PatternVersion[2]*[math]::pow( 2,16) + $MSSE_PatternVersion[1]*[math]::pow( 2,8) + $MSSE_PatternVersion[0]
                        $LastModDay=[datetime]::FromFileTime($Seconds).ToString('yyyyMMdd')

                        }
                                           
                              $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            

                              $PatternYear=$LastModDay.Substring(0,4)
                              $PatternMonth=$LastModDay.Substring(4,2)
                              $PatternDay=$LastModDay.Substring(6,2)

                              $PatternDate2=$PatternYear+"/"+$PatternMonth+"/"+$PatternDay

                              $PatternDate=(get-date "$PatternDate2").Ticks

                              if ($PatternDate -gt $TodayMinus7Days) {
                                  $AV_Ok = $true
                                  $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                                  $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                                  #$ReturnValue += ACreate-TestResult "Antivirus Update" $LastModDay $true
                                  }
                              else {
                                  $AV_Ok = $false
                                  $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                                  $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok                        
                                  #$ReturnValue += ACreate-TestResult "Antivirus Update" $LastModDay $false
                                  }
                    }
                    elseif ($MSWD_PatternVersion -ne "") {
                            $ReturnMsg = "MS Windows Defender - Version " + $MSWD_Version
                            #$ReturnValue += ACreate-TestResult "Antivirus installed" $ReturnMsg $true
                            if ([int]$MSWD_PatternVersion.count -gt 3) {
                                $Seconds = $MSWD_PatternVersion[7]*[math]::pow( 2,56) + $MSWD_PatternVersion[6]*[math]::pow( 2,48) + $MSWD_PatternVersion[5]*[math]::pow( 2,40) + $MSWD_PatternVersion[4]*[math]::pow( 2,32) + $MSWD_PatternVersion[3]*[math]::pow( 2,24) + $MSWD_PatternVersion[2]*[math]::pow( 2,16) + $MSWD_PatternVersion[1]*[math]::pow( 2,8) + $MSWD_PatternVersion[0]
                                $LastModDay=[datetime]::FromFileTime($Seconds).ToString('yyyyMMdd')
                                }

                              $TodayMinus7Days=((Get-Date).AddDays(-8)).Ticks            

                              $PatternYear=$LastModDay.Substring(0,4)
                              $PatternMonth=$LastModDay.Substring(4,2)
                              $PatternDay=$LastModDay.Substring(6,2)

                              $PatternDate2=$PatternYear+"/"+$PatternMonth+"/"+$PatternDay

                              $PatternDate=(get-date "$PatternDate2").Ticks
                              #$TodayDate=(get-date).Ticks

                              if ($PatternDate -gt $TodayMinus7Days) {
                                  $AV_Ok = $true
                                  $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                                  $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                                  }
                              else {
                                  $AV_Ok = $false
                                  $ReturnMsg = $ReturnMsg + " - Pattern: " + $PatternDate2
                                  $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                                  }
                            }
                }
        Return ACreate-Test "Antivirus" $ReturnValue   
}


###########################################################
####### Get Webroot SecureAnywhere Antivirus Status #######
###########################################################
function Aget-AV_WRSA($comp) {

    #Webroot SecureAnywhere AV Variables
    # initialOSBuildNumber = hexwaarde= 0x00001db1 = 7601
    #Webroot_64_Key = "SOFTWARE\Wow6432Node\webroot\"
    #Webroot_Version_Key = "initialOSBuildNumber"
    #Service is WRSA / WRSVC
    # "C:\Program Files (x86)\Webroot\WRSA.exe"
    #File Version 9.0.8.72
    #Product Version 9.0.8.72
    #Date Modified 4/03/2016 10:25
    #SOFTWARE\Wow6432Node\WRData\Status\UpdateTime=DWORD=1489597941
    #SOFTWARE\Wow6432Node\WRData\Status\Version=SZString=9.0.15.50    
    
    $ReturnValue = @()

    $WRSA_key1 = "SOFTWARE\Wow6432Node\WRData\Status\"
    $WRSA_key2 = "SOFTWARE\Wow6432Node\WRData\Status\"
    $WRSA_Version_Key = "Version"
    $WRSA_PatternVersion_Key = "UpdateTime"
    $WRSA_Version = ""
    $WRSA_PatternVersion = ""

    If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $WRSA_Version = $wmi.GetStringValue($hklm, $WRSA_key1, $WRSA_Version_Key)
        $WRSA_Version = $WRSA_Version.svalue
		If ([int]$WRSA_Version.length -ne 0) {                          
            $WRSA_PatternVersion = $wmi.GetDWORDValue($hklm, $WRSA_key2, $WRSA_PatternVersion_Key)
            $WRSA_PatternVersion = $WRSA_PatternVersion.uvalue
		    $ReturnMsg = "Webroot SecureAnywhere Endpoint Protection - Version " + $WRSA_Version + " installed"
			#$ReturnValue += ACreate-TestResult "Antivirus installed" $ReturnMsg $true
            }
        elseif ([int]$WRSA_Version.length -eq 0) {
            $ReturnValue += ACreate-TestResult "Antivirus installed" "Webroot SecureAnywhere Endpoint Protection Unknown Version" $false
			#return $ReturnValue
			}
        }

        #$WRSA_PatternVersion="1489500000"
        $Diff1="{0:D8}" -f (Get-Date -UFormat "%Y%m%d")
        $Diff2=get-date "1/1/1970"
        $Diff2=$Diff2.AddSeconds($WRSA_PatternVersion)
        $Diff2="{0:D8}" -f (Get-Date $Diff2 -UFormat "%Y%m%d")
        $Diff0=$Diff1-$Diff2
        #$Diff0=$Diff1-20160101
        If ([int]$Diff0 -lt 7) {
            $AV_Ok = $true
            $ReturnMsg = $ReturnMsg + " - Pattern: " + $Diff2
            $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
            }
        else {
            $AV_Ok = $false
            $ReturnMsg = $ReturnMsg + " - Pattern: " + $Diff2
            $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
            }
        Return ACreate-Test "Antivirus" $ReturnValue
}


#########################################
####### Get ESET Antivirus Status #######
#########################################
function Aget-AV_ESET($comp) {

    # process = C:\Program Files\ESET\ESET Security\ekrn.exe en C:\Program Files\ESET\RemoteAdministrator\Agent\ERAAgent.exe

    $ReturnValue = @()

    $ESET_key1 = "SOFTWARE\ESET\ESET Security\CurrentVersion\Info\"
    $ESET_key2 = "SOFTWARE\ESET\ESET Security\CurrentVersion\Info\"
    $ESET_Lic_Key = "SOFTWARE\ESET\ESET Security\CurrentVersion\LicenseInfo\"
    $ESET_Version_Key = "ProductVersion"
    $ESET_PatternVersion_Key = "ScannerVersion"
    $ESET_Lic_Expiration = "ExpirationDate"
    $ESET_Version = ""
    $ESET_PatternVersion = ""

    #If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $ESET_Version = $wmi.GetStringValue($hklm, $ESET_key1, $ESET_Version_Key)
        $ESET_Version = $ESET_Version.svalue

        If ([int]$ESET_Version.length -eq 0) {
            $ReturnValue += ACreate-TestResult "Antivirus installed" "ESET File Security Unknown Version" $false
			#return $ReturnValue
			}
		ElseIf ([int]$ESET_Version.length -ne 0) {                          
            $ESET_PatternVersion = $wmi.GetStringValue($hklm, $ESET_key2, $ESET_PatternVersion_Key)
            $ESET_PatternVersion = $ESET_PatternVersion.svalue
		    $ReturnMsg = "ESET File Security - Version " + $ESET_Version

            $Diff2 = $ESET_PatternVersion.split("(")[1].split(")")[0]
            $Diff1="{0:D8}" -f (Get-Date -UFormat "%Y%m%d")
            $Diff0=$Diff1-$Diff2
            If ([int]$Diff0 -lt 7) {
                $AV_Ok = $true
                $ReturnMsg = $ReturnMsg + " - Pattern: " + $ESET_PatternVersion
                $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            else {
                $AV_Ok = $false
                $ReturnMsg = $ReturnMsg + " - Pattern: " + $ESET_PatternVersion
                $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $AV_Ok
                }
            }
        #}
        Return ACreate-Test "Antivirus" $ReturnValue
}


###############################################
####### Get Checkpoint Antivirus Status #######
###############################################
function Aget-AV_CHECKPOINT_EPP($comp) {

    # process = C:\Program Files (x86)\CheckPoint\Endpoint Security\Endpoint Common\bin\cpda.exe

    $ReturnValue = @()

    $CP_EPP_key1 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\"
    $CP_EPP_key2 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\Anti-Malware"
    $CP_EPP_key3 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\AntiBot"
    $CP_EPP_key4 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\Device Agent"
    $CP_EPP_key5 = "SOFTWARE\Wow6432Node\Checkpoint\Endpoint Security\Threat Emulation"
    $CP_EPP_key1_Version_Key = "Version"
    $CP_EPP_key1_LastInstall ="LastInstallFinishTime"
    $CP_EPP_key2_Version_Key = "AVEngineVersion"
    $CP_EPP_key2_Lic_Exp_Key = "AVEngineLicense"
    $CP_EPP_key3_Version_Key = "Version"
    $CP_EPP_key4_Version_Key = "Version"
    $CP_EPP_key4_Pattern_Key = "PATVersion"
    $CP_EPP_key5_Version_Key = "Version"
    $CP_EPP_Version = ""
    $CP_EPP_PatternVersion = ""

    #If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $CP_EPP_Version = $wmi.GetStringValue($hklm, $CP_EPP_key1, $CP_EPP_key1_Version_Key)
        $CP_EPP_Version = $CP_EPP_Version.svalue

        If ([int]$CP_EPP_Version.length -eq 0) {
            $ReturnValue += ACreate-TestResult "Antivirus installed" "Checkpoint Endpoint Security Unknown Version" $false
			#return $ReturnValue
			}
		ElseIf ([int]$CP_EPP_Version.length -ne 0) {
            $CP_EPP_PatternVersion = $wmi.GetDWORDValue($hklm, $CP_EPP_key1, $CP_EPP_key1_LastInstall)
            $CP_EPP_PatternVersion = $CP_EPP_PatternVersion.uvalue
		    $ReturnMsg = "Checkpoint Endpoint Security - Version: " + $CP_EPP_Version

            $ReturnMsg = $ReturnMsg + " - Date:" + $CP_EPP_PatternVersion
            $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $true
            }
        #}
        Return ACreate-Test "Antivirus" $ReturnValue
}


###########################################
####### Get Sophos Antivirus Status #######
###########################################
function Aget-AV_SOPHOS($comp) {

# process = C:\Program Files\Sophos\Sophos File Scanner\SophosFileScanner.exe

# Sophos AV
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\Version: 2.20.4.1 REG_SZ
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\InstallState: 0 REG_DW
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\LastGoodInstallTime: 1640098001691 REG_QW (Last Update: 21-12-2021 15h46)
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\E17FE03B-0501-4aaa-BC69-0129D965F311\LongName: Sophos Anti-Virus for Windows REG_SZ
#
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\E17FE03B-0501-4aaa-BC69-0129D965F311\InstalledVersion: 10.8.11.41 REG_SZ
# Regkey: HKLM\SOFTWARE\Sophos\Sophos File Scanner\Application\ProductVersion: 1.9.7.2 REG_SZ (C:\Program Files\Sophos\Sophos File Scanner\SophosFileScanner.exe of (SophosFS.exe)
# Regkey: HKLM\SOFTWARE\Sophos\Sophos File Scanner\Application\Versions\EngineVersion: 3.83.3 REG_SZ
# Regkey: HKLM\SOFTWARE\Sophos\Sophos File Scanner\Application\Versions\VirusDataVersion: 2021122003 REG_SZ
# Regkey: HKLM\SOFTWARE\WOW6432Node\Sophos\AutoUpdate\ProductVersion: 6.11.299 REG_SZ

    $ReturnValue = @()

    $CP_EPP_key1 = "SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\E17FE03B-0501-4aaa-BC69-0129D965F311\"
    $CP_EPP_key2 = "SOFTWARE\Sophos\Sophos File Scanner\Application\Versions\"
    $CP_EPP_key3 = "SOFTWARE\WOW6432Node\Sophos\AutoUpdate\UpdateStatus\Details\"
    $CP_EPP_key4 = "SOFTWARE\Sophos\Sophos File Scanner\Application\Versions\"
    $CP_EPP_key1_Version_Key = "InstalledVersion"
    $CP_EPP_key3_LastInstall ="LastGoodInstallTime"
    $CP_EPP_key2_Version_Key = "EngineVersion"
    $CP_EPP_key4_Pattern_Key = "VirusDataVersion"
    $CP_EPP_Version = ""
    $CP_EPP_PatternVersion = ""

    #If ([int]$CPUarch -eq 64) {
        $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
        $CP_EPP_Version = $wmi.GetStringValue($hklm, $CP_EPP_key1, $CP_EPP_key1_Version_Key)
        $CP_EPP_Version = $CP_EPP_Version.svalue

        If ([int]$CP_EPP_Version.length -eq 0) {
            $ReturnValue += ACreate-TestResult "Antivirus installed" "Sophos Antivirus Unknown Version" $false
			#return $ReturnValue
			}
		ElseIf ([int]$CP_EPP_Version.length -ne 0) {
            $CP_EPP_PatternVersion = $wmi.GetStringValue($hklm, $CP_EPP_key4, $CP_EPP_key4_Pattern_Key)
            $CP_EPP_PatternVersion = $CP_EPP_PatternVersion.svalue
		    $ReturnMsg = "Sophos Antivirus - Version: " + $CP_EPP_Version
            $CP_EPP_EngineVersion = $wmi.GetStringValue($hklm, $CP_EPP_key2, $CP_EPP_key2_Version_Key)
            $CP_EPP_EngineVersion = $CP_EPP_EngineVersion.svalue
		    $ReturnMsg = "Sophos Antivirus - InstallVersion: " + $CP_EPP_Version + " - EngineVersion: " + $CP_EPP_EngineVersion

            $ReturnMsg = $ReturnMsg + " - Date:" + $CP_EPP_PatternVersion
            $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $true
            }
        #}
        Return ACreate-Test "Antivirus" $ReturnValue
}


##################################################
####### Check FortiClient Antivirus status #######
##################################################
function Aget-AV_FortiClient($comp) {

<#    
    PMV: Antivirus Check for FortiClient, check of FortiClient actief is als AV:
    (Get-ItemProperty HKLM:\SOFTWARE\Fortinet\FortiClient\FA_AV -Name Enabled).enabled -eq 1
    
    Forticlient Versie:
    Get-WmiObject -Class Win32_Product | where {$_.name -like "*FortiClient*"} | select Version
    SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{17748981-CA57-4D18-8B08-5685F656221D}

    en potentieel last update time (maar deze ben ik niet 100% zeker dat die datum/tijd klopt)
    [System.DateTimeOffset]::FromUnixTimeSeconds((Get-ItemProperty HKLM:\SOFTWARE\Fortinet\FortiClient\FA_UPDATE -Name lastupdatetime).lastupdatetime).dateTime.toString("dd/MM/yyyy hh:mm:ss")
    er moet mss wel gechecked worden of de registry directory "sFortinet\FortiClient\FA_AV" bestaat, want op mijn pc staat die bvb niet (ik heb enkel forticlient voor vpn)
#>
    $ReturnValue = @()
    $hklm = 2147483650

    $Forticlient_Enabled_key = "SOFTWARE\Fortinet\FortiClient\FA_AV\"
    $Forticlient_LastUpdateTime_key = "SOFTWARE\Fortinet\FortiClient\FA_UPDATE\"
    
    $Forticlient_Enabled_Item = "Enabled"
    $Forticlient_LastUpdateTime_Item = "lastupdatetime"

    $Forticlient_Enabled = ""
    $Forticlient_LastUpdateTime_Value = ""

    $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -ErrorAction Continue
    foreach ($proc in $processes) {
        if ($proc.name -eq "fmon.exe") {
            $Filename = $Proc.ExecutablePath
            }
        }

    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename

    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
    $Forticlient_Enabled = $wmi.GetDWORDValue($hklm, $Forticlient_Enabled_key, $Forticlient_Enabled_Item)
    $Forticlient_Enabled = $Forticlient_Enabled.uvalue

    $Forticlient_LastUpdateTime_Value = $wmi.GetDWORDValue($hklm, $Forticlient_LastUpdateTime_key, $Forticlient_LastUpdateTime_Item)
    $Forticlient_LastUpdateTime_Value = $Forticlient_LastUpdateTime_Value.uvalue
    $Forticlient_LastUpdateTime_Value = [System.DateTimeOffset]::FromUnixTimeSeconds($Forticlient_LastUpdateTime_Value).dateTime.toString("dd/MM/yyyy")
        
    If ([int]$Filename.length -eq 0) {
        $ReturnValue += ACreate-TestResult "Antivirus installed" "FortiClient Unknown Version" $false
		}
    Else {
	    $ReturnMsg = "FortiClient - Version: " + $FileVersion
        $ReturnMsg = $ReturnMsg + " - Date:" + $Forticlient_LastUpdateTime_Value
        $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $true
        }

    Return ACreate-Test "Antivirus" $ReturnValue
}


######################################################
####### Check N-Able Managed Antivirus Console #######
######################################################
function Aget-AV_NABLEAV($comp) {

    $ReturnValue = @()
    $hklm = 2147483650

    $Forticlient_Enabled_key = "SOFTWARE\Fortinet\FortiClient\FA_AV\"
    $Forticlient_LastUpdateTime_key = "SOFTWARE\Fortinet\FortiClient\FA_UPDATE\"
    
    $Forticlient_Enabled_Item = "Enabled"
    $Forticlient_LastUpdateTime_Item = "lastupdatetime"

    $Forticlient_Enabled = ""
    $Forticlient_LastUpdateTime_Value = ""

    $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -ErrorAction Continue
    foreach ($proc in $processes) {
        if ($proc.name -eq "epconsole.exe") {
            $Filename = $Proc.ExecutablePath
            }
        }

    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename
        
    If ([int]$Filename.length -eq 0) {
        $ReturnValue += ACreate-TestResult "Antivirus installed" "N-Able Managed Antivirus Unknown Version" $false
		}
    Else {
	    $ReturnMsg = "N-Able Managed Antivirus - Version: " + $FileVersion
        $ReturnMsg = $ReturnMsg + " - Date:" + $Forticlient_LastUpdateTime_Value
        $ReturnValue += ACreate-TestResult "Antivirus Installed" $ReturnMsg $true
        }

    Return ACreate-Test "Antivirus" $ReturnValue
}


###################################################
####### Dummy/Empty Antivirus Status Script #######
###################################################
function Aget-No_AV_Installed($comp) {
    $ReturnValue = @()

    $ReturnValue += ACreate-TestResult "Antivirus Installed" "No known Anti-Virus software" $false
    Return ACreate-Test "Antivirus" $ReturnValue
}


################################################
####### Get Antivirus Status Main Script #######
################################################
function Aget-AntiVirus($comp) {

    $hklm = 2147483650

    $AV_Installed = $false
    $ReturnValue = @()
    $ReturnValue2 = @()

    $CPUarch =  (Get-WmiObject win32_processor -computername $comp | Where-Object{$_.deviceID -eq "CPU0"}).AddressWidth
    $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -ErrorAction Continue    
    foreach ($proc in $processes) {
        switch ($proc.name) 
            { 
            "SophosFileScanner.exe" { $ReturnValue2 = Aget-AV_SOPHOS $comp ;$AV_Installed = $true}
            "epconsole.exe" { $ReturnValue2 = Aget-AV_NABLEAV $comp ;$AV_Installed = $true}
            "NTRTScan.exe" { $ReturnValue2 = Aget-AV_TM $comp ;$AV_Installed = $true}
            "mcshield.exe" { $ReturnValue2 = Aget-AV_McAfee $comp ;$AV_Installed = $true}
            "ccSvcHst.exe" { $ReturnValue2 = Aget-AV_SEP $comp ;$AV_Installed = $true}
            "WRSA.exe" { $ReturnValue2 = Aget-AV_WRSA $comp ;$AV_Installed = $true}
            "ekrn.exe" { $ReturnValue2 = Aget-AV_ESET $comp ;$AV_Installed = $true}
            "cpda.exe" { $ReturnValue2 = Aget-AV_CHECKPOINT_EPP $comp ;$AV_Installed = $true}
            "fmon.exe" { $ReturnValue2 = Aget-AV_FortiClient $comp ;$AV_Installed = $true}
            "MsSense.exe" {$ReturnValue2 = Aget-Check_Windows_Defender_ATP $comp ;$AV_Installed = $true}
            }
        }

    if (-NOT $AV_Installed) {
        foreach ($proc in $processes) {
            if ($proc.name -eq "MsMpEng.exe") { 
                $ReturnValue2 = Aget-AV_MSSE $comp
                $AV_Installed = $true
                }
            else {
                $ReturnValue2 = Aget-No_AV_Installed $comp
                }
            }
        }
    Return ACreate-Test "Antivirus" $ReturnValue2.testresult
}


#######################################################
####### Get GFI Mailessentials Anti-SPAM Status #######
#######################################################
function Aget-AntiSpam($comp){

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
      $ReturnValue += ACreate-TestResult "GFI ME" "Not Installed" $true
      return ACreate-Test "GFI Mailessentials" $ReturnValue

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
             $ReturnValue += ACreate-TestResult "GFI ME" "Version unknown" $false
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
            $ReturnValue += ACreate-TestResult "GFI ME" $ReturnMsg $true

            If ($BuildDateTicks -gt $TodayMinus365DaysTicks) {
                #$ReturnValue += ACreate-TestResult "GFI Mailessentials Update Check" $val.'PatternDate' $true
                }
            else {
                #$ReturnValue += ACreate-TestResult "GFI Mailessentials Update Check" $val.'PatternDate' $false
                }
            }
      }
Return ACreate-Test "GFI Anti-SPAM" $ReturnValue
}


######################################
####### Get Mozy Backup Status #######
######################################
function Aget-MozyBackup($comp) {
#
# File version of MozyPro : 2.28.2.432 "C:\Program Files\MozyPro\oem.dll"
# MozyProBackup.exe
# MozyProStat.exe

# HKLM\Software\MozyPro\state\
# "last_successful_seed_time"="2013-05-17 23:27:54"
# "last_successful_backup_time"="2016-03-06 21:36:43"
# "last_successful_backup_files"="634919"
# "last_successful_backup_size"="575098801098"

  $hklm = 2147483650
  $key = "SOFTWARE\MozyPro\state\"
  $Last_BU_Time_Key = "last_successful_backup_time"
  $Last_BU_Files_Key = "last_successful_backup_files"
  $Last_BU_Size_Key = "last_successful_backup_size"
  $Last_BU_Time = ""
  $Last_BU_Date = ""
  $Last_BU_Files = ""
  $Last_BU_Size = ""

  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%MozyProBackup%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += ACreate-TestResult "MozyPro Backup" "Not Installed" $true
      return ACreate-Test "MozyPro Backup" $ReturnValue
      }
  else
      {
      $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
      $Last_BU_Time = $wmi.GetStringValue($hklm, $Key, $Last_BU_Time_Key)
      $Last_BU_Time = $Last_BU_Time.svalue
      $Last_BU_Files = $wmi.GetStringValue($hklm, $Key, $Last_BU_Files_Key)
      $Last_BU_Files = $Last_BU_Files.svalue
      $Last_BU_Size = $wmi.GetStringValue($hklm, $Key, $Last_BU_Size_Key)
      $Last_BU_Size = $Last_BU_Size.svalue

      $filename = "\Program Files\MozyPro\oem.dll" 
      $obj = New-Object System.Collections.ArrayList 
      $filepath = Test-Path "\\$comp\c$\$filename"
      if ($filepath -eq "True") {
          $file = Get-Item "\\$comp\c$\$filename" 
          $MozyPro_Version = ($file.VersionInfo).fileversion
          }      
      $ReturnMsg = "Version " + $MozyPro_Version + " installed"
      $ReturnValue += ACreate-TestResult "MozyPro Backup" $ReturnMsg $true

      $Last_BU_Date = $Last_BU_Time.split(" ")[0]
      $Last_BU_Date = $Last_BU_Date.replace("-","/")
      $BackupDateTicks =(get-date "$Last_BU_Date").Ticks
      $Last_BU_Date ="{0:D8}" -f $Last_BU_Date.replace("/","")
      $TodayMinus5DaysTicks =((Get-Date).AddDays(-5)).Ticks
            
      $ReturnMsg1 = "Last Successful Backup Time " + $Last_BU_Date
      $ReturnMsg2 = "Last Successful Backup Files " + $Last_BU_Files
      $ReturnMsg3 = "Last Successful Backup Size " +  [math]::Round(($Last_BU_Size/1024/1024/1024),2) + " GBytes"
      
      If ($BackupDateTicks -gt $TodayMinus5DaysTicks) {
          $ReturnValue += ACreate-TestResult "MozyPro Status" $ReturnMsg1 $true
          $ReturnValue += ACreate-TestResult "MozyPro Status" $ReturnMsg2 $true
          $ReturnValue += ACreate-TestResult "MozyPro Status" $ReturnMsg3 $true
          }
      else {
          $ReturnValue += ACreate-TestResult "MozyPro Status" $ReturnMsg1 $false
          $ReturnValue += ACreate-TestResult "MozyPro Status" $ReturnMsg2 $false
          $ReturnValue += ACreate-TestResult "MozyPro Status" $ReturnMsg3 $false
          }
      }
Return ACreate-Test "MozyPro Backup" $ReturnValue
}


############################################
####### Get BackupExec Backup Status #######
############################################
function Aget-BackupExec($comp) {

  $hklm = 2147483650
  $BE_Version_key = "SOFTWARE\Symantec\Backup Exec For Windows\Backup Exec\Server\"
  $BE_SWUpdate_key = "SOFTWARE\Symantec\Backup Exec For Windows\Backup Exec\User Interface\"
  $Version = "ExeVersion"
  $Status = "Status"
  $SWUpdate = "Software Update Aailable"
  $BackupExec_Version = ""
  $BackupExec_Status = ""
  $BackupExec_SWUpdate = ""
  
  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'bengine%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += ACreate-TestResult "Symantec BackupExec" "Not Installed" $true
      return ACreate-Test "Symantec BackupExec" $ReturnValue

      }
  else
      {
      #      
      $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
      $BackupExec_Version = $wmi.GetStringValue($hklm, $BE_Version_key, $Version)
      $BackupExec_Version = $BackupExec_Version.svalue
      $BackupExec_Status = $wmi.GetStringValue($hklm, $BE_Version_key, $Status)
      $BackupExec_Status = $BackupExec_Status.svalue
      $BackupExec_SWUpdate = $wmi.GetStringValue($hklm, $BE_SWUpdate_key, $SWUpdate)
      $BackupExec_SWUpdate = $BackupExec_SWUpdate.svalue

      $ReturnMsg = "Version " + $BackupExec_Version + " installed"
      $ReturnValue += ACreate-TestResult "Symantec BackupExec" $ReturnMsg $true

      ############################
      $BEjobs = Invoke-Command -ComputerName $comp -scriptblock (get-item Function:\Aget-BackupExec2).scriptblock -ErrorAction Continue
          
      $BEjobs.Split("!") | foreach {
        $ReturnMsg = " + Job: " + $_
        if ($_ -like '*Succeeded*') {
            $ReturnValue += ACreate-TestResult "Symantec BackupExec" $ReturnMsg $true   
            }
        elseif ($_ -eq "" -OR $_ -eq " " -OR $_ -eq "  ") {
                }
                else {
                     $ReturnValue += ACreate-TestResult "Symantec BackupExec" $ReturnMsg $false
                     }
        }
      }
Return ACreate-Test "Symantec BackupExec" $ReturnValue
}


#######################################
####### BackupExec subscript v2 #######
#######################################
function Aget-BackupExec2() {

Import-module "C:\Program Files\Symantec\Backup Exec\Modules\BEMCLI"

$BEJobs = get-BEJob | Select Name | sort-object Name
foreach ($BEJob in $BEJobs) {
    $LastJob = Get-BEJob $BEJob.Name | Get-BEJobHistory | Select -Last 1
    $CustomEndTime ='{0:dd/MM/yyyy hh:mm:ss}' -f $Lastjob.Endtime
    $ReturnMsg = $ReturnMsg + $LastJob.Name + " " + $LastJob.JobStatus + " " + $CustomEndTime + "!"
    }        
      
Return $ReturnMsg
}


#######################################
####### BackupExec subscript v4 #######
#######################################
function Aget-BackupExec4($BEjobs) {

   $BEjobs.Split("!") | foreach {
   $ReturnMsg = "BackupExec - Job:" + $_
   $ReturnValue += ACreate-TestResult "Symantec BackupExec" $ReturnMsg $true   
   }

Return ACreate-Test "Symantec BackupExec" $ReturnValue
}


#######################################
####### Get Veeam Backup Status #######
#######################################
function Aget-VeeamEndpointBackup($comp) {
$file = ""
$filename = ""
$filepath = ""
$ReturnValue = @()
  
$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%Veeam.Endpoint.Service%'" -ErrorAction Continue
if ($processes -eq $null) {
    $ReturnValue += ACreate-TestResult "Veeam Endpoint Backup" "Not Installed" $true
    return ACreate-Test "Veeam Endpoint Backup" $ReturnValue
    }
else {
    $Filename = $Processes.ExecutablePath    
    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename

    $ReturnValue += ACreate-TestResult "Veeam Endpoint Backup" "Version: $FileVersion Installed" $true
    return ACreate-Test "Veeam Endpoint Backup" $ReturnValue
    }

}


##########################################
####### Get Veeam Backup Status v2 #######
##########################################
function Aget-VeeamBackup2($comp) {
#
#https://richiban.uk/2012/08/23/ensuring-you-get-the-clr-version-you-want-when-remoting-in-powershell/
#
#After creating the files c:\windows\System32\wsmprovhost.exe.config and c:\windows\SysWOW64\wsmprovhost.exe.config with the following content, everything worked fine:
#<?xml version="1.0"?>
#<configuration>
#    <startup useLegacyV2RuntimeActivationPolicy="true">
#         <supportedRuntime version="v4.0.30319"/>        
#         <supportedRuntime version="v2.0.50727"/>        
#    </startup>
#</configuration>

  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  #$CPUarch =  (Get-WmiObject win32_processor -computername $comp | Where-Object{$_.deviceID -eq "CPU0"}).AddressWidth
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%Veeam.Backup.Service%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += ACreate-TestResult "Veeam Backup" "Not Installed" $true
      return ACreate-Test "Veeam Backup" $ReturnValue
      }
  else
      {
      $filename = $processes.Path
      $filename = $filename.replace("Veeam.Backup.Service.exe","Veeam.Backup.Core.dll")
      $filename = $filename.replace("C:\","")
      #$filename = "\Program Files\Veeam\Backup and Replication\Veeam.Backup.Core.dll"
      $obj = New-Object System.Collections.ArrayList 
      $filepath = Test-Path "\\$comp\c$\$filename"
      if ($filepath -eq "True") {
          $file = Get-Item "\\$comp\c$\$filename" 
          $Veeam_Version = ($file.VersionInfo).fileversion
          }
      #last_successful_backup_time
      $ReturnMsg = "Version " + $Veeam_Version + " installed"
      $ReturnValue += ACreate-TestResult "Veeam Backup" $ReturnMsg $true
      
      try {
        if ($Veeam_Version.split(".")[0] -lt 11) {
            $retcode = Invoke-Command -ComputerName $comp -ScriptBlock {Add-PSSnapin VeeamPSSnapin} -ErrorAction Stop
            $vbrTapeJobs = Invoke-Command -ComputerName $comp -ScriptBlock {Add-PSSnapin VeeamPSSnapin; Get-VBRTapeJob} -ErrorAction Stop
            }
        else {            
            $retcode = Invoke-Command -ComputerName $comp -ScriptBlock {Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process; Import-Module Veeam.Backup.PowerShell} -ErrorAction Stop
            $vbrTapeJobs = Invoke-Command -ComputerName $comp -ScriptBlock {Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process; Import-Module Veeam.Backup.PowerShell; Get-VBRTapeJob} -ErrorAction Stop
            }

        if ($vbrTapeJobs) {
            $CustomNextRun ='{0:dd/MM/yyyy HH:mm:ss}' -f $vbrTapeJobs.NextRun
            ##$ReturnMsg = " + Job: " + $vbrTapeJobs.Name + " - Status: " + $vbrTapeJobs.LastResult + " - NextRun: " + $CustomNextRun + " - Result: " + $vbrTapeSessionResult + " - State: " + $vbrTapeSession.state
            $ReturnMsg = " + Job: " + $vbrTapeJobs.Name + " - Status: " + $vbrTapeJobs.LastResult + " - State: " + $vbrTapeJobs.LastState + " - NextRun: " + $CustomNextRun
            $ReturnValue += ACreate-TestResult "Veeam Backup" $ReturnMsg $true
            }
                     
            $VeeamVMjobStatus = Invoke-Command -ComputerName $comp -scriptblock ${Function:Aget-VeeamJobStatus} -ArgumentList $Veeam_Version -ErrorAction Continue

            ## $VeeamVMjobStatus = Invoke-Command -ComputerName $comp -scriptblock (get-item Function:\Aget-VeeamJobStatus).ScriptBlock -ErrorAction Continue
            ## $VeeamVMjobStatus = Invoke-Command -ComputerName $comp -scriptblock ${Function:Aget-VeeamJobStatus} -ArgumentList $Veeam_Version

        }
      catch {
        Write-host "*****************************************************************************************************"
        Write-host "The Veeam PSSnapin is installed/Registered, but can not be executed."
        Write-host "Propably a Powershell (Version) incompatibility"
        Write-host "Check the following link:"
        Write-host "https://richiban.uk/2012/08/23/ensuring-you-get-the-clr-version-you-want-when-remoting-in-powershell/"
        Write-host "*****************************************************************************************************"
        Write-host ""
        }        

      if ($VeeamVMjobStatus) {
        $VeeamVMjobStatus.Split("!") | foreach {
            $ReturnMsg = $_
            if ( ($_ -like '*Success*') -or ($_ -like '*Warning*') ) {
                $ReturnValue += ACreate-TestResult "Veeam Backup" $ReturnMsg $true   
                }
            elseif ($_ -like '*Failed*') {
                $ReturnValue += ACreate-TestResult "Veeam Backup" $ReturnMsg $false
                }
            elseif ($_ -like '*None*') {
                $ReturnValue += ACreate-TestResult "Veeam Backup" $ReturnMsg $true
                }
            }
        }
      else {
        $ReturnMsg = " + No Veeam Backup Jobs, or the free ZIP version"
        $ReturnValue += ACreate-TestResult "Veeam Backup" $ReturnMsg $true
        }
  }
Return ACreate-Test "Veeam Backup" $ReturnValue
}


#########################################
####### Check for Veeam PS Snapin #######
#########################################
function Aget-VeeamPSSnapin() {
#
$PSSnapIns = Get-PSSnapin -Registered
$VeeamSnapIn=0

foreach ($SnapIn in $PSSnapIns) {
    if ($SnapIn.name -eq "VeeamPSSnapIn") {
        # Write-Host "Checking if Veeam SnapIn is Registered..."
        $VeeamSnapIn = 1
        # On Veeam v9/10 use Add-PSSnapin VeeamPSSnapin -ErrorAction SilentlyContinue
        # From Veeam v11 on use Import-Module Veeam.Backup.PowerShell i.s.o Add-PSSnapin VeeamPSSnapin
        }
    }

Return $VeeamSnapIn
}


######################################################
####### Get Veeam Job Status Details subscript #######
######################################################
function Aget-VeeamJobStatus($Veeam_Version) {

if ($Veeam_Version.split(".")[0] -lt 11) {
    Add-PSSnapin VeeamPSSnapin
    }
else {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    Import-Module Veeam.Backup.PowerShell
    }

# Find all Backup, BackupSync and Replica jobs
$VbrJobs = Get-VBRJob | Where-Object {$_.JobType -eq "Backup" -or $_.JobType -eq "BackupSync" -or $_.JobType -eq "Replica"} | Sort-Object typetostring, JobType, name

Foreach($Job in $VbrJobs) {
    #Get Job Name
    $Jobname = $Job.Name
    $session=Get-VBRBackupSession | Where {$_.jobId -eq $job.Id.Guid} | Sort EndTimeUTC -Descending | Select -First 1
    if ($session -ne $null) {
        #Get VMs in Job
        #$Objects = $Job.GetObjectsInJob()
        $jobsessiontasks=$session.gettasksessions() | Sort Name
               
        #Get Last Backup
        $Backup = Get-VBRBackup | Where{$_.JobName -eq "$JobName" -and $_.jobId -eq $job.Id.Guid}
        #$LastBackup = $Backup.LastPointCreationTime
        $LastBackup = $Backup.MetaUpdateTime
        $CustomLastBackup ='{0:dd/MM/yyyy HH:mm:ss}' -f $LastBackup        

        #Get Last Backup Result
        $Result = $Job.GetLastResult()
                
        #write-host $Jobname " - " $LastBackup " - " $Result
        $ReturnMsg = $ReturnMsg + " + Job: " + $Jobname + " - " + $CustomLastBackup + " - " + $Result + "!"

        foreach ($VM in $jobsessiontasks) {
            #write-host "   -> " $VM.name $VM.status
            $ReturnMsg = $ReturnMsg + "   -> VM: " + $VM.name + " - " + $VM.status + "!"
            }
        }
    }
Return $ReturnMsg
}


##########################################################
####### Get Veeam v11 Job Status Details subscript #######
##########################################################
function Aget-Veeam11JobStatus() {

# Find all Backup, BackupSync and Replica jobs
$VbrJobs = Get-VBRJob | Where-Object {$_.JobType -eq "Backup" -or $_.JobType -eq "BackupSync" -or $_.JobType -eq "Replica"} | Sort-Object typetostring, JobType, name

Foreach($Job in $VbrJobs) {
    #Get Job Name
    $Jobname = $Job.Name
    $session=Get-VBRBackupSession | Where {$_.jobId -eq $job.Id.Guid} | Sort EndTimeUTC -Descending | Select -First 1
    if ($session -ne $null) {
        #Get VMs in Job
        #$Objects = $Job.GetObjectsInJob()
        $jobsessiontasks=$session.gettasksessions() | Sort Name
               
        #Get Last Backup
        $Backup = Get-VBRBackup | Where{$_.JobName -eq "$JobName" -and $_.jobId -eq $job.Id.Guid}
        #$LastBackup = $Backup.LastPointCreationTime
        $LastBackup = $Backup.MetaUpdateTime
        $CustomLastBackup ='{0:dd/MM/yyyy HH:mm:ss}' -f $LastBackup        

        #Get Last Backup Result
        $Result = $Job.GetLastResult()
                
        #write-host $Jobname " - " $LastBackup " - " $Result
        $ReturnMsg = $ReturnMsg + " + Job: " + $Jobname + " - " + $CustomLastBackup + " - " + $Result + "!"

        foreach ($VM in $jobsessiontasks) {
            #write-host "   -> " $VM.name $VM.status
            $ReturnMsg = $ReturnMsg + "   -> VM: " + $VM.name + " - " + $VM.status + "!"
            }
        }
    }
Return $ReturnMsg
}


##########################################################
####### Get Veeam Success Status Details subscript #######
##########################################################
function Aget-VeeamVMstatusSuccess($OrigJobName) {

if ($Veeam_Version.split(".")[0] -lt 11) {
    Add-PSSnapin VeeamPSSnapin
    }
else {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    Import-Module Veeam.Backup.PowerShell
    }

# Find all backup job sessions that have ended in the last x hours
$vbrjobs = Get-VBRJob | Where-Object {$_.JobType -eq "Backup" -or $_.JobType -eq "Replica"}
$vbrsessions = Get-VBRBackupSession | Where-Object {($_.JobType -eq "Backup" -or $_.JobType -eq "BackupSync" -or $_.JobType -eq "Replica") -and $_.EndTime -ge (Get-Date).addhours(-24)} | sort-object Name

# Find all successfully backed up VMs in selected sessions (i.e. VMs not ending in failure) and update status to "Protected"
if ($vbrsessions) {
    foreach ($session in $vbrsessions) {
        foreach ($vm in ($session.gettasksessions() | Where-Object {$_.Status -ne "Failed" -and $_.JobName -eq $OrigJobName} | ForEach-Object { $_ } | sort-object Name )) {
            #Write-Host $vm.Name $vm.JobName $vm.Status
            $ReturnMsg = $ReturnMsg + $vm.Name + " " + $vm.JobName + " " + $vm.Status + "!"
            }
        }
    }
Return $ReturnMsg
}


#########################################################
####### Get Veeam Failed Status Details subscript #######
#########################################################
function Aget-VeeamVMstatusFailed($OrigJobName) {

if ($Veeam_Version.split(".")[0] -lt 11) {
    Add-PSSnapin VeeamPSSnapin
    }
else {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    Import-Module Veeam.Backup.PowerShell
    }

# Find all backup job sessions that have ended in the last x hours
$vbrjobs = Get-VBRJob | Where-Object {$_.JobType -eq "Backup" -or $_.JobType -eq "Replica"}
$vbrsessions = Get-VBRBackupSession | Where-Object {($_.JobType -eq "Backup" -or $_.JobType -eq "BackupSync" -or $_.JobType -eq "Replica") -and $_.EndTime -ge (Get-Date).addhours(-24)} | sort-object Name

# Find all successfully backed up VMs in selected sessions (i.e. VMs not ending in failure) and update status to "Protected"
if ($vbrsessions) {
    foreach ($session in $vbrsessions) {
        foreach ($vm in ($session.gettasksessions() | Where-Object {$_.Status -eq "Failed" -and $_.JobName -eq $OrigJobName} | ForEach-Object { $_ } | sort-object Name)) {
            #Write-Host $vm.Name $vm.JobName $vm.Status
            $ReturnMsg = $ReturnMsg + $vm.Name + " " + $vm.JobName + " " + $vm.Status + "!"
            }
        }
    }
Return $ReturnMsg
}


###########################################
####### Get O&O Drive Backup Status #######
###########################################
function Aget-OODrive_AdBE_Backup($comp) {

  $processes = $null
  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%VVSvrDae%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += ACreate-TestResult "OODrive AdBE Backup" "Not Installed" $true
      return ACreate-Test "OODrive AdBE Backup" $ReturnValue
      }
  else
      {
      $filename = "Program Files (x86)\AdBE\CentralControl\VVAdmin.exe"

      $obj = New-Object System.Collections.ArrayList 
      $filepath = Test-Path "\\$comp\c$\$filename"
      if ($filepath -eq "True") {
          $file = Get-Item "\\$comp\c$\$filename" 
          $AdBE_Backup_Version = ($file.VersionInfo).fileversion
          $BuildDate = (($file.LastWriteTime).Day).ToString()
          $BuildDate = $BuildDate + "/" + (($file.LastWriteTime).Month).ToString()
          $BuildDate = $BuildDate + "/" + (($file.LastWriteTime).Year).ToString()
          $BuildDate = $BuildDate + " " + (($file.LastWriteTime).Hour).ToString()
          $BuildDate = $BuildDate + ":" + (($file.LastWriteTime).Minute).ToString()
          }
      #last_successful_backup_time
      $ReturnMsg = "Version " + $AdBE_Backup_Version + " Build: " + $BuildDate + " installed"
      $ReturnValue += ACreate-TestResult "OODrive AdBE Backup" $ReturnMsg $true
      }
Return ACreate-Test "OODrive AdBE Backup" $ReturnValue
}


##########################################
####### Get Arcserve Backup Status #######
##########################################
function Aget-ArcservUDP_Backup($comp) {

# COPRO
#$comp="CRMSERVER"

$file = ""
$filename = ""
$filepath = ""
$ReturnValue = @()
  
#$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%jobeng.exe%'" -ErrorAction Continue
#$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%DBEng.exe%'" -ErrorAction Continue
$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like '%DatastoreInstService.exe'" -ErrorAction Continue

if ($processes -eq $null) {
    $ReturnValue += ACreate-TestResult "Arcserv Backup" "Not Installed" $true
    return ACreate-Test "Arcserv Backup" $ReturnValue
    }
else {
    $filename = $processes.Path
    #$filename = $filename.replace("Veeam.Backup.Service.exe","Veeam.Backup.Core.dll")
    $filename = $filename.replace("C:\","")
    #$filename = "\Program Files\Veeam\Backup and Replication\Veeam.Backup.Core.dll"
    $obj = New-Object System.Collections.ArrayList 
    $filepath = Test-Path "\\$comp\c$\$filename"
    if ($filepath -eq "True") {
        $file = Get-Item "\\$comp\c$\$filename" 
        $Arcserv_Version = ($file.VersionInfo).fileversion
        }
      
    #last_successful_backup_time
    $ReturnMsg = "Version " + $ArcServ_Version + " installed"
    $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $true

    $All_ArcServeUPD_Jobs = Invoke-Command -ComputerName $comp -scriptblock {Invoke-Sqlcmd -Query "SELECT DISTINCT A.jobId, A.jobType, A.jobMethod, A.jobStatus, A.productType, A.jobUTCStartTime, A.jobUTCEndTime, A.serverId, A.agentId, B.nodeName FROM as_edge_d2dJobHistory_lastJob A INNER JOIN as_edge_session_details B ON A.agentId = B.nodeId ORDER BY A.jobUTCStartTime;" -ServerInstance "CRMSERVER\ARCSERVE_APP" -Database "arcserveUDP" } -ErrorAction SilentlyContinue

    foreach ($job in $All_ArcServeUPD_Jobs) {
        if ($job.jobStatus -eq "1") {
            if ($job.jobType -eq "0" -OR $job.jobType -eq "3") {
                #Write-Host Incremental Backup of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup OK"
                $ReturnMsg = " + Job: Incremental Backup Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $true
                }
            elseif ($job.jobType -eq "11" -OR $job.jobType -eq "15") {
                #Write-Host File System Catalog of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup OK"
                $ReturnMsg = " + Job: File System Catalog Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $true
                }
            elseif ($job.jobType -eq "32") {
                #Write-Host Merge on RPS of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup OK"
                $ReturnMsg = " + Job: Merge Job on RPS:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $true
                }
            elseif ($job.jobType -eq "51") {
                #Write-Host Purge Job of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup OK"
                $ReturnMsg = " + Job: Purge Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $true
                }
            }
        else {
            if ($job.jobType -eq "0" -OR $job.jobType -eq "3") {
                #Write-Host Incremental Backup of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup NOK"
                $ReturnMsg = " + Job: Incremental Backup Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $false
                }
            elseif ($job.jobType -eq "11" -OR $job.jobType -eq "15") {
                #Write-Host File System Catalog of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup NOK"
                $ReturnMsg = " + Job: File System Catalog Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $false
                }
            elseif ($job.jobType -eq "32") {
                #Write-Host Merge on RPS of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup NOK"
                $ReturnMsg = " + Job: Merge Job on RPS:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $false
                }
            elseif ($job.jobType -eq "51") {
                #Write-Host Purge Job of Server:($job.nodename) Start Time:($job.jobUTCStartTime) Job Status:($job.jobStatus) => "Backup NOK"
                $ReturnMsg = " + Job: Purge Job:"+($job.nodename)+" Start Time:"+($job.jobUTCStartTime)
                $ReturnValue += ACreate-TestResult "Arcserv Backup" $ReturnMsg $false
                }
            }
        }

    }
Return ACreate-Test "Arcserv Backup" $ReturnValue
}


###########################################
####### Get Carbonite Backup Status #######
###########################################
# Werkt niet meer, vanaf bepaalde versie is er geen 'default' login/wachtwoord meer voor de Database
function Aget-CarboniteBackup($comp) {

  $hklm = 2147483650
  $BE_Version_key = "SOFTWARE\Zmanda\ZWC\1.0\Install\"
  
  $file = ""
  $filename = ""
  $filepath = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'ZWCService.exe%'" -ErrorAction Continue
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'ZCBService.exe%'" -ErrorAction Continue

  if ($processes -eq $null)
      {
      $ReturnValue += ACreate-TestResult "Carbonite Backup" "Not Installed" $true
      return ACreate-Test "Carbonite Backup" $ReturnValue

      }
  else
      {
      $filename = $processes.Path
      #$filename = $filename.replace("C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\bin\ZWCService.exe")
      #$filename = "C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\Database\bin\mysql.exe"
      $filename = $filename.replace("\bin\ZCBService.exe","\Database\bin\mysql.exe")
     
      #$CarboniteJobs = & "C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\Database\bin\mysql" -ucarboniteuser -pzwcdb ibdata1 -sN -e "SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio, EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus, BackupDetails FROM ZIBCatalog.ZIBreport WHERE Operation like '%ZIB_BACKUP_DIRECT_UPLOAD%' AND BackupStartTime >= DATE(NOW()) + INTERVAL - 1 DAY"
      #$CarboniteJobs = & "C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\Database\bin\mysql" -ucarboniteuser -pzwcdb ibdata1 -sN -e "SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio, EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus FROM ZIBCatalog.ZIBreport WHERE Operation like '%ZIB_BACKUP_DIRECT_UPLOAD%' AND BackupStartTime >= DATE(NOW()) + INTERVAL - 1 DAY \G"
      #$CarboniteJobs = & "C:\Program Files\Carbonite\Carbonite Safe Server Backup(x64)\Database\bin\mysql" -ucarboniteuser -pzwcdb ibdata1 -sN -e "SELECT * FROM information_schema.tables \G"
      
#      $CarboniteJobs = Invoke-Command -ComputerName $comp -scriptblock {
#        PARAM($Param1)
#        & $Param1 -ucarboniteuser -pzwcdb ibdata1 -sN -e "SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio, 
#                                                                 EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus 
#                                                                 FROM ZIBCatalog.ZIBreport 
#                                                                 WHERE Operation like '%ZIB_BACKUP%' ORDER BY BackupType DESC LIMIT 2 \G"} -ArgumentList $FileName

      $CarboniteJob1 = Invoke-Command -ComputerName $comp -scriptblock {
        PARAM($Param1)
        & $Param1 -ucarboniteuser -pzwcdb ibdata1 -sN -e "
        SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio,
               EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus
        FROM ZIBCatalog.ZIBreport
        WHERE BackupStatus like '%ZIB_BACKUP%' AND BackupType = 'Windows File System'
        ORDER BY BackupStartTime DESC LIMIT 1
        \G"} -ArgumentList $FileName

      <#
      $CarboniteJob2 = Invoke-Command -ComputerName $comp -scriptblock {
        PARAM($Param1)
        & $Param1 -ucarboniteuser -pzwcdb ibdata1 -sN -e "
        SELECT BackupHost, ZCBVersion, BackupType, BackupLevel, UploadRate, RetentionPolicy, TotalBackupSize, CompressionRatio,
               EncryptionTechnique, BackupElapsedTime, BackupStartTime, BackupEndTime, FullBackupTimeStamp, BackupStatus
        FROM ZIBCatalog.ZIBreport
        WHERE BackupStatus like '%ZIB_BACKUP%' AND BackupType = 'Windows System State'
        ORDER BY BackupStartTime DESC LIMIT 1
        \G"} -ArgumentList $FileName
      #>

      $CarboniteJob3 = Invoke-Command -ComputerName $comp -scriptblock {
        PARAM($Param1)
        & $Param1 -ucarboniteuser -pzwcdb ibdata1 -sN -e "
        SELECT BackupId, BackupSet, Operation, OperationStartTime, OperationEndTime, Status
        FROM ZIBCatalog.ZIBmonitor
        #WHERE Status = 'ZIB_BACKUP_SUCCESSFUL' OR Status = 'ZIB_UPLOAD_SUCCESSFUL'
        WHERE Status = 'ZIB_BACKUP_DIRECT_UPLOAD_SUCCESSFUL' OR Status = 'ZIB_BACKUP_DIRECT_BACKUP_SUCCESSFUL' OR Status = 'ZIB_BACKUP_SUCCESSFUL' OR Status = 'ZIB_UPLOAD_SUCCESSFUL'
        \G"} -ArgumentList $FileName

        #WHERE BackupStatus like '%ZIB_BACKUP%' of ZIB_BACKUP_SUCCESSFUL of ZIB_BACKUP_WARNING of ZIB_BACKUP_FAILED
        #ORDER BY BackupStartTime

      #GROUP BY BackupType
      #FROM ZIBCatalog.ZIBreport 
      #WHERE Operation like '%ZIB_BACKUP%'
      #GROUP BY BackupType ORDER BY BackupStartTime ASC LIMIT 2 \G"} -ArgumentList $FileName
      #WHERE Operation like '%ZIB_BACKUP_DIRECT_UPLOAD%' AND BackupStartTime >= DATE(NOW()) + INTERVAL - 1 DAY \G"} -ArgumentList $FileName
      #WHERE Operation like '%ZIB_BACKUP%' ORDER BY BackupStartTime DESC LIMIT 4 \G"} -ArgumentList $FileName

      ############################################################################
      #for ($i=0; $i -le $CarboniteJob3.length; $i++) {$CarboniteJob3[$i]}
      ############################################################################

      $ReturnMsg = ""
      $NoJobError=$false
      $LinesPerJobOutput = 0

      if ($CarboniteJob1 -eq $null) {
        $ReturnMsg = "No Jobs Found"
        $ReturnValue += ACreate-TestResult "Carbonite Backup" $ReturnMsg $false
        }
      else {
            $i=0
            $ReturnMsg = "Version " + $CarboniteJob1[($i*$CarboniteJob1.Count)+2] + " installed"
            $ReturnValue += ACreate-TestResult "Carbonite Backup" $ReturnMsg $true            

            $CarboniteCopyMonitorLines = $CarboniteJob3.length

            for ($i=0; $i -le $CarboniteCopyMonitorLines; $i++) {
                   if ($i%7 -eq 2) {
                        $CarboniteJobName = $CarboniteJob3[$i]
                        }
                   if ($i%7 -eq 4) {
                        $CarboniteJobStartTime = $CarboniteJob3[$i]
                        }
                   if ($i%7 -eq 5) {
                        $CarboniteJobEndTime = $CarboniteJob3[$i]
                        }
                   if ($i%7 -eq 6) {
                        $CarboniteJobStatus = $CarboniteJob3[$i]
                        }

                   if ($CarboniteJobStatus -like '*_SUCCESSFUL*') {
                        $NoJobError=$true
                        }
            
                   if ($i -ne 0 -AND ($i % 7) -eq 0) {
                        if ($CarboniteJobStatus -like '*_UPLOAD_SUCCESSFUL*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Cloud Backup Successful"
                            }
                        elseif ($CarboniteJobStatus -like '*_BACKUP_SUCCESSFUL*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Local Backup Successful"
                            }
                        elseif ($CarboniteJobStatus -like '*_UPLOAD_FAILED*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Cloud Backup Failed"
                            }
                        elseif ($CarboniteJobStatus -like '*_BACKUP_FAILED*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Local Backup Failed"
                            }
                        elseif ($CarboniteJobStatus -like '*_UPLOAD_WARNING*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Cloud Backup Warning"
                            }
                        elseif ($CarboniteJobStatus -like '*_BACKUP_WARNING*') {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Local Backup Warning"
                            }
                        else {
                            $ReturnMsg = " + Job: " + $CarboniteJobName + " : " +  $CarboniteJobStartTime + " - " + $CarboniteJobEndTime + " - Backup problems"
                            }
                   
                        $Current=(Get-Date)
                        $diff= New-TimeSpan -Start $CarboniteJobStartTime -End $Current

                        if ( ($diff.days -gt 1 -AND $CarboniteJobName -notlike '*System State*') -OR !$NoJobError) {                                  
                           $ReturnValue += ACreate-TestResult "Carbonite Backup" $ReturnMsg $false
                            }
                        Elseif ( ($diff.days -gt 31 -AND $CarboniteJobName -like '*System State*') -OR !$NoJobError ) {
                            $ReturnValue += ACreate-TestResult "Carbonite Backup" $ReturnMsg $NoJobError
                            }
                        Else {
                           $ReturnValue += ACreate-TestResult "Carbonite Backup" $ReturnMsg $NoJobError
                            }
                        }

                   }

            }
    }
Return ACreate-Test "Carbonite Backup" $ReturnValue
}


#########################################
####### Get Acronis Backup Status #######
#########################################
function Aget-Acronis_Backup($comp) {

  $hklm = 2147483650
  $key = "SOFTWARE\Wow6432Node\Acronis\CLI\"
  $AcroCMD_Key = "path"

  $AcroCMD_Val = ""
  $file = ""
  $filename = ""
  $Acronis_Backup_Version = ""
  $ReturnValue = @()
  
  $processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'arsm.exe%'" -ErrorAction Continue
  if ($processes -eq $null)
      {
      $ReturnValue += ACreate-TestResult "Acronis Backup" "Not Installed" $true
      return ACreate-Test "Acronis Backup" $ReturnValue
      }
  else
      {
      $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
      $AcroCMD_Val = $wmi.GetStringValue($hklm, $Key, $AcroCMD_Key)
      $AcroCMD_Val = $AcroCMD_Val.svalue

      #$filename = "Program Files (x86)\Acronis\CommandLineTool\acrocmd.exe"
      $filename = $AcroCMD_Val.replace("C:\","")
      $filename2 = $AcroCMD_Val

      $obj = New-Object System.Collections.ArrayList
      $filepath = Test-Path "\\$comp\c$\$filename"
      if ($filepath -eq "True") {
          $file = Get-Item "\\$comp\c$\$filename" 
          $Acronis_Backup_Version = ($file.VersionInfo).fileversion.replace(",",".")
          $BuildDate = (($file.LastWriteTime).Day).ToString()
          $BuildDate = $BuildDate + "/" + (($file.LastWriteTime).Month).ToString()
          $BuildDate = $BuildDate + "/" + (($file.LastWriteTime).Year).ToString()
          $BuildDate = $BuildDate + " " + (($file.LastWriteTime).Hour).ToString()
          $BuildDate = $BuildDate + ":" + (($file.LastWriteTime).Minute).ToString()
          }
      $ReturnMsg = "Version " + $Acronis_Backup_Version + " - " + $BuildDate + " installed"
      $ReturnValue += ACreate-TestResult "Acronis Backup" $ReturnMsg $true
      }

      #$scriptblock = {"cmd /c " + $filename2 + " list plans"}
      $scriptblock = {cmd /c "C:\Program Files (x86)\Acronis\CommandLineTool\acrocmd.exe" list plans}
      $ReturnMsg = Invoke-Command -scriptblock $scriptblock -ComputerName $comp

      foreach ($line in $ReturnMsg) { 
        if ($line -like "*GUID*") {
            continue
            }
        if ($line -like "--------------------*") {
            continue
            }
        if ($line -like "The operation completed*") {
            continue
            }
        if ($line -ne "") {
            $line = $line.split(" ")
            $count=0
            $ln2=""
            foreach ($ln in $line) {
                if ($ln -ne "") {
                    if ([int]$count -lt 5) {
                        $ln2 = $ln2 + " " + $ln
                        $count++
                        }
                    }                
                }
            $ReturnMsg = "+ Job: " + $ln2
            if ($ln2 -like "*error*" -or $ln2 -like "*Failed*" ) {
                $ReturnValue += ACreate-TestResult "Acronis Backup" $ReturnMsg $false
                }
            else {
                $ReturnValue += ACreate-TestResult "Acronis Backup" $ReturnMsg $true
                }
            continue
            }
        write-host $line
        }

Return ACreate-Test "Acronis Backup" $ReturnValue
}


################################
####### Get Java Version #######
################################
function Aget-JavaRTE($comp) {

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
            $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x64_Version8 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version8 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true            
            }
        elseif ($JAVA_RTE_x64_Version7 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version7 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true            
            }
        elseif ($JAVA_RTE_x64_Version6 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version6 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true            
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
                        $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true
                        }
                        else {
                            $ReturnValue += ACreate-TestResult "Java RTE 32bit" "Not Installed" $true
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
            $ReturnValue += ACreate-TestResult "Java RTE 64bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x64_Version8 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version8 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 64bit" $ReturnMsg $true            
            }
        elseif ($JAVA_RTE_x64_Version7 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version7 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 64bit" $ReturnMsg $true            
            }
        elseif ($JAVA_RTE_x64_Version6 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x64_Version6 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 64bit" $ReturnMsg $true            
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
                    $ReturnValue += ACreate-TestResult "Java RTE 64bit" $ReturnMsg $true
                    }
                else {
                    $ReturnValue += ACreate-TestResult "Java RTE 64bit" "Not Installed" $true
                    }                
                }
            else {
                $ReturnValue += ACreate-TestResult "Java RTE 64bit" "Not Installed" $true
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
            $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x86_Version8 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x86_Version8 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x86_Version7 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x86_Version7 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true
            }
        elseif ($JAVA_RTE_x86_Version6 -ne $null) {
            $ReturnMsg = "Version " + $JAVA_RTE_x86_Version6 + " installed"
            $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true
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
                    $ReturnValue += ACreate-TestResult "Java RTE 32bit" $ReturnMsg $true
                    }
                else {
                    $ReturnValue += ACreate-TestResult "Java RTE 32bit" "Not Installed" $true
                    }
                }
                else {
                    $ReturnValue += ACreate-TestResult "Java RTE 32bit" "Not Installed" $true
                }
            }
      }
    }
    Catch {
        $ReturnValue += ACreate-TestResult "Java RTE " $ReturnMsg $false
    }

Return ACreate-Test "Java RTE" $ReturnValue
}


################################
###### Get Windows Uptime ######
################################
Function Aget-WindowsUptime($comp){
		function WMIDateStringToDate($Bootup) {
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
            $LastBootUpTime = WMIDateStringToDate($Bootup)
			$now = Get-Date
            $Reporttime = $now - $lastBootUpTime
            $d = "{0,3}" -f $Reporttime.Days
            $h = "{0,2}" -f $Reporttime.Hours
            $m = "{0,2}" -f $Reporttime.Minutes
            $ms= "{0,2}" -f $Reporttime.Milliseconds
            $a = "{0} days, {1} hours, {2:N0} minutes" -f $d,$h,$m
            if($d -gt 125) {$OK = $false} else {$OK = $true}
            $ReturnValue += ACreate-TestResult "Windows Uptime" $a $OK
            return ACreate-Test "Uptime" $ReturnValue
		}
}


#########################################
###### Get Windows Update Settings ######
#########################################
function Aget-WindowsUpdateSetting($server){
    $AutoUpdateDays=@{0="Every Day"; 1="Every Sunday"; 2="Every Monday"; 3="Every Tuesday"; 4="Every Wednesday";5="Every Thursday"; 6="Every Friday"; 7="EverySaturday"}
    $ReturnValue = @()
	
    $wusettings = ([activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.AutoUpdate",$server))).Settings
    
    if ($wusettings.NotificationLevel -eq $null) {
        $ReturnValue += ACreate-TestResult "Windows Update" "De informatie kan niet worden uitgelezen" $false
    }
    elseif ([int]$wusettings.NotificationLevel -eq 4) {
        $ReturnValue += ACreate-TestResult "Windows Update" ("" + $autoupdatedays[$wusettings.ScheduledInstallationDay] + " at " + $wusettings.ScheduledInstallationTime + ":00")  $true
    } 
    else {
        $ReturnValue += ACreate-TestResult "Windows Update" "Geen reboot door updates" $true
    }
	return ACreate-Test "Windows Update" $ReturnValue

}


#####################################
###### Get Windows Time Source ######
#####################################
function Aget-WindowsTimeSource($server){
    $ReturnValue = @()
    $PDCtimeSyncSource = "ntp.belbone.be,0x1"
    $PDC=Get-ADDomain | Select-Object PDCEmulator

    $TimeSource = Invoke-Command -ComputerName $server -ScriptBlock { w32tm /query /source }

    if ($server -eq $PDC.PDCEmulator.split(".")[0] ) {      
        If ( $TimeSource.split(",0x1") -contains "ntp.belbone.be" ) {
            $ReturnValue += ACreate-TestResult "TimeSource" $TimeSource $true
            }
        else {
            $ReturnValue += ACreate-TestResult "TimeSource" $TimeSource $false
            }
        }
    else {
        $ReturnValue += ACreate-TestResult "TimeSource" $TimeSource ($PDC.PDCEmulator -contains $TimeSource.Trim())
        }

    return ACreate-Test "Timesource" $ReturnValue
}


########################################
###### Get Windows Time Source v2 ######
########################################
function Aget-WindowsTimeSource2($server){
    $ReturnValue = @()
    $Found=$false
    $PDCtimeSyncSource = "ntp.belbone.be,0x1"
    $PDC=Get-ADDomain | Select-Object PDCEmulator
    $DCs=Get-ADDomainController -Filter *
    $DCs=$DCs.Name
    $wmi = get-wmiobject -class Win32_OperatingSystem -computername $server
    #$OSCheck = (Get-WmiObject -comp $comp -class Win32_OperatingSystem ).Caption
    
    if ( [int]$wmi.version.split(".")[0] -gt 5 ) {
        #$TimeSource = Invoke-Command -ComputerName $server -ScriptBlock { w32tm /query /source }
        $TimeSource = Invoke-Command -ComputerName $server -ScriptBlock { w32tm /query /peers }
        If ( ($TimeSource -imatch 'Peer:' | unique) -like('*ntp.belbone.be*') ) {
            $TimeSource = (($TimeSource -imatch 'Peer:' | unique).split(":")[1].trim()).split(",")[0]
            }
        Else {
            $TimeSource = ((($TimeSource -imatch 'Peer:' | unique).split(":")[1].trim()).split(",")[0]).split(".")[0]
            }
        }
    Else {
        $TimeSource = Invoke-Command -ComputerName $server -ScriptBlock { net time /querysntp }
        $TimeSource=$TimeSource.split(":")[1].Trim()
        If ( ($TimeSource.split(",0x1") -contains "ntp.belbone.be") -or ($TimeSource.split(",0x1") -contains "time.windows.com") ) {
            $TimeSource=$TimeSource.split(",")[0]
            }
        else {          
            $TimeSource=$TimeSource.split(",")[0]
            }
        }    

    if ($server -eq $PDC.PDCEmulator.split(".")[0] ) {      
        If ( $TimeSource -contains "ntp.belbone.be" ) {
            $Found=$true
            $ReturnValue += ACreate-TestResult "TimeSource" $TimeSource $true
            }
        else {
            $Found=$true
            $ReturnValue += ACreate-TestResult "TimeSource" $TimeSource $false
            }
        }              
    else {
        foreach ($DC in $DCs) {           
                 if ($TimeSource -eq $dc) {
                     $Found=$true
                     $ReturnValue += ACreate-TestResult "TimeSource" $TimeSource $true
                     }        
                }
        if (!$found) {
            if ( ([int]$wmi.version.split(".")[0] -lt "6") -and ($TimeSource -contains "time.windows.com") ) {
                $ReturnValue += ACreate-TestResult "TimeSource" $TimeSource $true
                }
            else {
                $ReturnValue += ACreate-TestResult "TimeSource" $TimeSource $false
                }
            }
        }
    return ACreate-Test "Timesource" $ReturnValue
}


##################################
###### Get Windows Services ######
##################################
Function Aget-WindowsServices($server){
    $ReturnValue = @()
	$Services = Get-wmiobject win32_service -Filter "startmode = 'auto' AND state != 'running' AND Exitcode !=0 " -ComputerName $server
    
    If ($Services -ne $null) {
        
        $Services | foreach{
			#$ReturnValue += ACreate-TestResult $_.name ("" + $_.state + ";" + $_.exitcode) $false
            $ReturnValue += ACreate-TestResult $_.displayname ("" + $_.state + ";" + $_.exitcode) $false
        }
    }
    Else {
        $ReturnValue += ACreate-TestResult "All Services" "running normally" $true
    }
    return ACreate-Test "Services" $ReturnValue 
}


#######################################
###### Get Windows Domain Admins ######
#######################################
Function Aget-DomainAdmins(){
    $MaxDomainAdmins = 3
    $ReturnValue = @()
	try {
        $members = get-ADGroupMember "Domain admins"
        }
    catch {
        try {
            $members = get-ADGroupMember "Domeinadministrators"
            }
        catch {}
        }

    $enabledCount = 0
    $vandaag = get-date

    
    foreach($member in $members | sort){
        echo $member
        if($member.objectclass -eq "user"){
            $user= get-aduser $member -Properties *
            $user.AccountExpirationDate
            if ($user.Enabled){
                if (($user.AccountExpirationDate -eq $null)-or($user.AccountExpirationDate -gt $vandaag)){
                    $enabledcount += 1
                    if($enabledCount -gt $MaxDomainAdmins){
                         $ReturnValue += ACreate-TestResult $member.name "account is enabled" $false
                    }else{
                         $ReturnValue += ACreate-TestResult $member.name "account is enabled" $true
                    }
                }else{
                    $ReturnValue += ACreate-TestResult $member.name "account is expired" $true
                }
                
            }else{
                $ReturnValue += ACreate-TestResult $member.name "account is disabled" $true
            }
        }
    }
    
    if ($enabledCount -gt $MaxDomainAdminsS){
        $ReturnValue += ACreate-TestResult "aantal enabled admins" $enabledCount $false
    }else{
        $ReturnValue += ACreate-TestResult "aantal enabled admins" $enabledCount $true
    }
Return ACreate-Test "Domainadmin" $ReturnValue    
}


###########################################
###### Get Hyper-V Hanging Snapshots ######
###########################################
Function Aget-VM_Snapshots($server){
    $ReturnValue = @()

<# On Error "Hyper-V encountered an error trying to access an object on computer 'xxx-xxx-xx' because the object was not found...."
   Run the following command to rebuild the WMI components for virtualization
   MOFCOMP %SYSTEMROOT%\System32\WindowsVirtualization.V2.mof
#>

    # Get the Hyper-V feature and store it in $hyperv
    $hyperv = Invoke-Command -ComputerName $server -ScriptBlock {Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online} -ErrorAction Continue

    # Check if Hyper-V is already enabled.
    if($hyperv.State -eq "Enabled") {

        $vmsnapshots = Invoke-Command -ComputerName $server -ScriptBlock {
            $vms = Get-VM | select vmName
            foreach ($vm in $vms) {
                Get-Vmsnapshot -VMname $vm.VMName
                }
            }

        if ($vmsnapshots -eq $null) {
            $ReturnMsg = "None "
            $ReturnValue += ACreate-TestResult "Hyper-V Snapshots" $ReturnMsg $true
            }
        else {
            foreach ($vmsnapshot in $vmsnapshots) {
                if ($vmsnapshot.ParentSnapshotName -eq $null) {
                    $ReturnMsg = "Snapshot " + $vmsnapshot.name + " - Type: " + $vmsnapshot.SnapshotType
                    }
                else {
                    $ReturnMsg = "Snapshot " + $vmsnapshot.name + " - Type: " + $vmsnapshot.SnapshotType + " - Parent: " + $vmsnapshot.ParentSnapshotName
                    }
                    $year = $vmsnapshot.CreationTime.Year
                    $month = $vmsnapshot.CreationTime.Month
                    $day = $vmsnapshot.CreationTime.Day
                    $year1 = "{0:D4}" -f $year
                    $month1 = "{0:D2}" -f $month
                    $day1 = "{0:D2}" -f $day
                    $LastModDay=$year1+$month1+$day1
                    $Diff1="{0:D8}" -f (Get-Date -UFormat "%Y%m%d")
                    $Diff2="{0:D8}" -f $LastModDay
                    $Diff0=$Diff1-$Diff2
                    if ($Diff0 -gt 7) {
                        $ReturnValue += ACreate-TestResult "Hyper-V Snapshots" $ReturnMsg $false
                        }
                    else {
                        $ReturnValue += ACreate-TestResult "Hyper-V Snapshots" $ReturnMsg $true
                        }
                }            
            }
        } 
    else {
        $ReturnValue += ACreate-TestResult "Hyper-V Snapshots" "Not Installed" $true
        }    
  
return ACreate-Test "Hyper-V Lingering Snapshots" $ReturnValue
}


#################################################
###### Get Windows Firewall Profile Status ######
#################################################
function Aget-FirewallProfile($server) {
    $OS_Major_Version = (Get-WmiObject win32_operatingsystem -Computer $server).version.split(".")[0]
    $OS_Minor_Version = (Get-WmiObject win32_operatingsystem -Computer $server).version.split(".")[1]
    $OS_Version = $OS_Major_Version+$OS_Minor_Version

    if ( [int]$OS_Version -gt 52 ) {

        $ReturnMsg = ""
        $ReturnValue = @()
        $FW_Profiles_Status = @()

        $ScriptBlock = { (Get-NetFirewallProfile -PolicyStore ActiveStore | select name,enabled) }
        $ScriptBlock = { (Get-NetFirewallProfile | select name,enabled) }
        $FW_Profiles_Status = Invoke-Command -ComputerName $server -ScriptBlock $ScriptBlock -ErrorAction Ignore
        $FW_All_Profiles_Status = ($FW_Profiles_Status | where { $_.Enabled -eq $True } | measure ).Count -eq 3

        if ($FW_All_Profiles_Status) {
            #Write-Host "Windows Firewall is Compliant"
            #write-host $Profile.name"Profile is Enabled"
            $ReturnMsg = "Domain, Private & Public Profiles are enabled"
            $ReturnValue += ACreate-TestResult "Windows Adv. Firewall" $ReturnMsg $true
            }
        else {
            foreach ($Profile in $FW_Profiles_Status) {
                IF (-NOT $Profile.Enabled) {
                    #write-host $Profile.name"Profile is Disabled"
                    $ReturnMsg = $Profile.name+" Profile is Disabled"
                    $ReturnValue += ACreate-TestResult "Windows Adv. Firewall" $ReturnMsg $false
                    }
                ELSE {
                    #write-host $Profile.name"Profile is Enabled"
                    $ReturnMsg = $Profile.name+" Profile is Enabled"
                    $ReturnValue += ACreate-TestResult "Windows Adv. Firewall" $ReturnMsg $true                    
                    }
                }
            }
        }
     else {
            $ReturnMsg = "not available in this OS"
            $ReturnValue += ACreate-TestResult "Windows Adv. Firewall" $ReturnMsg $true
            }       
            
 return ACreate-Test "Windows Adv. Firewall" $ReturnValue
}


#########################################
###### Get Windows Update Settings ######
#########################################
function Aget-WindowsUpdateSettings($server) {

    $hklm = 2147483650
    $key = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\"
    $key1 = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\"
    $key3 = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\"

    $UseWUServer = "UseWUServer"
    $WUServer = "WUServer"
    $NoAutoUpdate = "NoAutoUpdate"
    $AUOptions = "AUOptions"
    $ScheduledInstallDay = "ScheduledInstallDay"
    $ScheduledInstallTime = "ScheduledInstallTime"

    $ReturnValue = @()
    $ReturnMsg = ""
  
    $OS_Version = Aget-OSVersion $server

    # First check if there is an WIndows Update Policy, check the regkey: "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer"
    # If positive, check the regkey: "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer" en "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUStatusServer"
    # If positive, use the WSUS update settings, if negative, use the "internet settings"

    # Check Windows Update Configuration
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $server
  
    $Comp_UseWUServer = $wmi.GetDWORDValue($hklm, $Key1, $UseWUServer)
    $Comp_UseWUServer = $Comp_UseWUServer.UValue
   
    $Comp_NoAutoUpdate = $wmi.GetDWORDValue($hklm, $Key1, $NoAutoUpdate)
    $Comp_NoAutoUpdate = $Comp_NoAutoUpdate.UValue

    if ([int]$OS_Version -gt 60) {
        $Comp_WUServer = $wmi.GetStringValue($hklm, $Key, $WUServer)
        $Comp_WUServer = $Comp_WUServer.sValue
        if ($Comp_WUServer.length -ne "0") {
            $Comp_WUServer = $Comp_WUServer.split("//")[2]
            }
        #else {
            $Comp_AUOptions = $wmi.GetDWORDValue($hklm, $Key1, $AUOptions)
            $Comp_AUOptions = $Comp_AUOptions.UValue

            $Comp_ScheduledInstallDay = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallDay)
            $Comp_ScheduledInstallDay = $Comp_ScheduledInstallDay.UValue

            $Comp_ScheduledInstallTime = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallTime)
            $Comp_ScheduledInstallTime = $Comp_ScheduledInstallTime.UValue
            $Comp_ScheduledInstallTime = "{0,2}" -f $Comp_ScheduledInstallTime  

            if ($Comp_AUOptions -ne $null) {
                Switch ($Comp_AUOptions) 
                    {    
                    "1" {$ReturnMsg = "Automatic updates has been Disabled"}
                    "2" {$ReturnMsg = "Notify  for  Download  &   Installation"}
                    "3" {$ReturnMsg = "Auto Download & Notify for Installation"}
                    "4" {$ReturnMsg = "Auto Download & Scheduled  Installation"}
                    "5" {$ReturnMsg = "Automatic updates enabled but allow local admin to choose settings"}
                    }
                }

            if ($Comp_ScheduledInstallDay -ne $null) {
                Switch ($Comp_ScheduledInstallDay)
                    {
                    "0" {$ReturnMsg = $ReturnMsg + ", Everyday "}
                    "1" {$ReturnMsg = $ReturnMsg + ", Sunday   "}
                    "2" {$ReturnMsg = $ReturnMsg + ", Monday   "}
                    "3" {$ReturnMsg = $ReturnMsg + ", Tuesday  "}
                    "4" {$ReturnMsg = $ReturnMsg + ", Wednesday"}
                    "5" {$ReturnMsg = $ReturnMsg + ", Thursday "}
                    "6" {$ReturnMsg = $ReturnMsg + ", Friday   "}
                    "7" {$ReturnMsg = $ReturnMsg + ", Saturday "}    
                    }
                }

            If ($Comp_ScheduledInstallTime.trim().length -ne 0) {
                $ReturnMsg = $ReturnMsg + " at:" + $Comp_ScheduledInstallTime+"h"
                }
    
            if ($Comp_UseWUServer -ne $null) {
                Switch ($Comp_UseWUServer)
                    {
                    "0" {$ReturnMsg = $ReturnMsg + " (Update from Microsoft)"}
                    "1" {if ($Comp_WUServer -ne $null) {
                            $ReturnMsg = $ReturnMsg + " (Update from WSUS server:"+ $comp_WUServer+")"
                            }
                        }
                    }
                }

            #echo $ReturnMsg
            $ReturnValue += ACreate-TestResult "Windows Update Settings" $ReturnMsg $true
        }
    
    elseIf ($Comp_NoAutoUpdate -eq $null -and $Comp_UseWUServer -eq $null) {
        #$Comp_AUOptions = $wmi.GetDWORDValue($hklm, $Key3, $AUOptions)
        $Comp_AUOptions = $wmi.GetDWORDValue($hklm, $Key1, $AUOptions)
        $Comp_AUOptions = $Comp_AUOptions.UValue

        $Comp_ScheduledInstallDay = $wmi.GetDWORDValue($hklm, $Key3, $ScheduledInstallDay)
        #$Comp_ScheduledInstallDay = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallDay)
        $Comp_ScheduledInstallDay = $Comp_ScheduledInstallDay.UValue

        $Comp_ScheduledInstallTime = $wmi.GetDWORDValue($hklm, $Key3, $ScheduledInstallTime)
        #$Comp_ScheduledInstallTime = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallTime)
        $Comp_ScheduledInstallTime = $Comp_ScheduledInstallTime.UValue
        $Comp_ScheduledInstallTime = "{0,2}" -f $Comp_ScheduledInstallTime  

        if ($Comp_AUOptions -ne $null) {
            Switch ($Comp_AUOptions) 
                {    
                "0" {$ReturnMsg = "Automatic updates enabled and downloaded updates will be installed immediately"}
                "1" {$ReturnMsg = "Automatic updates disabled, however users can manually initiate update"}
                "2" {$ReturnMsg = "Check for updates but do not download them until user says so"}
                "3" {$ReturnMsg = "Download the updates but do not install"}
                "4" {$ReturnMsg = "Automatic updates enabled but allow local admin to choose settings"}
                }
            }

        if ($Comp_ScheduledInstallDay -ne $null) {
            Switch ($Comp_ScheduledInstallDay)
                {
                "0" {$ReturnMsg = $ReturnMsg + ", Everyday "}
                "1" {$ReturnMsg = $ReturnMsg + ", Sunday   "}
                "2" {$ReturnMsg = $ReturnMsg + ", Monday   "}
                "3" {$ReturnMsg = $ReturnMsg + ", Tuesday  "}
                "4" {$ReturnMsg = $ReturnMsg + ", Wednesday"}
                "5" {$ReturnMsg = $ReturnMsg + ", Thursday "}
                "6" {$ReturnMsg = $ReturnMsg + ", Friday   "}
                "7" {$ReturnMsg = $ReturnMsg + ", Saterday "}    
                }
            }

        If ($Comp_ScheduledInstallTime.trim().length -ne 0) {
            $ReturnMsg = $ReturnMsg + " at:" + $Comp_ScheduledInstallTime+"h"
            }
     
        $ReturnValue += ACreate-TestResult "Windows Update Settings" $ReturnMsg $true
        # End of If statement
        }
        else {
            $Comp_WUServer = $wmi.GetStringValue($hklm, $Key, $WUServer)
            $Comp_WUServer = $Comp_WUServer.sValue
            if ($Comp_WUServer.length -ne "0") {
                $Comp_WUServer = $Comp_WUServer.split("//")[2]
                }
            #else {
            $Comp_AUOptions = $wmi.GetDWORDValue($hklm, $Key1, $AUOptions)
            $Comp_AUOptions = $Comp_AUOptions.UValue

            $Comp_ScheduledInstallDay = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallDay)
            $Comp_ScheduledInstallDay = $Comp_ScheduledInstallDay.UValue

            $Comp_ScheduledInstallTime = $wmi.GetDWORDValue($hklm, $Key1, $ScheduledInstallTime)
            $Comp_ScheduledInstallTime = $Comp_ScheduledInstallTime.UValue
            $Comp_ScheduledInstallTime = "{0,2}" -f $Comp_ScheduledInstallTime  

            If ($Comp_NoAutoUpdate -ne $null) {
                Switch ($Comp_NoAutoUpdate)
                    {
                    "0" {$WU_Ok=$true; $ReturnMsg =  "Auto Update"}
                    "1" {$WU_Ok=$false; $ReturnMsg = "No Auto Update"}
                    }
                }
    
            if ($Comp_UseWUServer -ne $null) {
                Switch ($Comp_UseWUServer)
                    {
                    "0" {$ReturnMsg = $ReturnMsg + " from Microsoft"}
                    "1" {$ReturnMsg = $ReturnMsg + " from WSUS server"}
                    }
                }

            if ($Comp_WUServer -ne $null) {
                $ReturnMsg = $ReturnMsg + ":" + $comp_WUServer
                }

            if ($Comp_AUOptions -ne $null) {
                Switch ($Comp_AUOptions) 
                    {    
                    "1" {$ReturnMsg = $ReturnMsg + ", Automatic updates has been Disabled"}
                    "2" {$ReturnMsg = $ReturnMsg + ", Notify for Download & Installation"}
                    "3" {$ReturnMsg = $ReturnMsg + ", Auto Download & Notify for Installation"}
                    "4" {$ReturnMsg = $ReturnMsg + ", Auto Download & Scheduled Installation"}
                    "5" {$ReturnMsg = $ReturnMsg + ", Automatic updates enabled but allow local admin to choose settings"}
                    }
                }

            if ($Comp_ScheduledInstallDay -ne $null) {
                Switch ($Comp_ScheduledInstallDay)
                    {
                    "0" {$ReturnMsg = $ReturnMsg + ", Everyday "}
                    "1" {$ReturnMsg = $ReturnMsg + ", Sunday   "}
                    "2" {$ReturnMsg = $ReturnMsg + ", Monday   "}
                    "3" {$ReturnMsg = $ReturnMsg + ", Tuesday  "}
                    "4" {$ReturnMsg = $ReturnMsg + ", Wednesday"}
                    "5" {$ReturnMsg = $ReturnMsg + ", Thursday "}
                    "6" {$ReturnMsg = $ReturnMsg + ", Friday   "}
                    "7" {$ReturnMsg = $ReturnMsg + ", Saterday "}    
                    }
                }

            If ($Comp_ScheduledInstallTime.trim().length -ne 0) {
                $ReturnMsg = $ReturnMsg + " at:" + $Comp_ScheduledInstallTime+"h"
                }
            echo $ReturnMsg
            $ReturnValue += ACreate-TestResult "Windows Update Settings" $ReturnMsg $true
            #}
        }

    return ACreate-Test "Windows Update Settings" $ReturnValue
    }


########################################
###### Get Windows Updates Status ######
########################################
function Aget-CheckWindowsUpdateStatus($server, $CheckFailedUpdates) {
    $FailedUpdates = @()
    $UniqueFailedUpdates = @()
    $SucceededUpdates = @()

   <#
    $QueuedUpdates=Invoke-Command -ComputerName $server -ScriptBlock {
            $updateObject = New-Object -ComObject Microsoft.Update.Session
            #$updateObject.ClientApplicationID = "Windows Queued Updates Script"
            $updateSearcher = $updateObject.CreateUpdateSearcher();
            try {$searchResults = $updateSearcher.Search("IsInstalled=0");
            $searchResults.Updates.Count }
            catch {Return $error}
            }
    #>

    $QueuedUpdates = Invoke-Command -ComputerName $server -ScriptBlock {
        $updateObject = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateObject.CreateUpdateSearcher();
        try {$searchResults = $updateSearcher.Search("IsInstalled=0");}
        catch {
            $exceptionExit = echo $_.tostring()
            Return $exceptionExit
            }
        $searchResults.Updates.Count            
        }

    if ($QueuedUpdates -match 'Exception from HRESULT:') {
        $QueuedUpdates = " Exception: "+($QueuedUpdates.split(":")[1]).Trim()
        }

    if ($CheckFailedUpdates) {

        $updates=Invoke-Command -ComputerName $server -ScriptBlock {
            $UpdateSession = New-Object -ComObject "Microsoft.Update.Session"
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            $historyCount = $UpdateSearcher.GetTotalHistoryCount()
            $UpdateSearcher.QueryHistory(0, $historyCount) | Select-Object Date, @{name="Operation"; expression={switch($_.operation){1 {"Installation"}; 2 {"Uninstallation"}; 3 {"Other"}}}}, @{name="Status"; expression={switch($_.resultcode){1 {"In Progress"}; 2 {"Succeeded"}; 3 {"Succeeded With Errors"};4 {"Failed"}; 5 {"Aborted"} } } }, Title
            }
            #$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
            #$SearchResult = $Searcher.Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0")    

        foreach ($item in ($updates |sort)) {
            if ($item.status -eq "Failed") {
                if ($item.title.indexof("(") -gt 0) {
                    $FailedItem = $item.title.split("(")[1].split(")")[0]
                    $FailedUpdates += $FailedItem
                    }
                }
            elseif ($item.status -eq "Succeeded") {
                if ($item.title.indexof("(") -gt 0) {
                    $SucceededItem = $item.title.split("(")[1].split(")")[0]
                    $SucceededUpdates += $SucceededItem
                    }
                }
            }

        $FailedCnt = 0
        $Prev_FailedItem=""
        foreach ($FailedItem in ($FailedUpdates |sort)) {
            if ($FailedItem.trim() -ne $Prev_FailedItem.trim()) {
                $FailedCnt++
                $UniqueFailedUpdates += $faileditem.trim()
                #echo "$faileditem $Prev_FailedItem"
                }
            elseif ($FailedItem.trim() -eq $Prev_FailedItem.trim()) {
                echo "$faileditem $Prev_FailedItem"            
                }
            $Prev_FailedItem = $FailedItem
            }

        $FailedCnt=0
        foreach ($Item in $UniqueFailedUpdates) {
            if (!$SucceededUpdates.Contains($item)) {
                $FailedCnt++
                echo "Persistant Failed update"
                }
            }

        $FailedUpdatesCnt = "{0,3}" -f $FailedCnt
        $SucceededUpdatesCnt = "{0,4}" -f $SucceededUpdates.Count
        $QueuedUpdates = "{0,3}" -f $QueuedUpdates
    
        $ReturnMsg = "Updates Queued:"+$QueuedUpdates+" Failed:"+$FailedUpdatesCnt+" Succeeded:"+$SucceededUpdatesCnt

        } # end if ($CheckFailedUpdates)
    else {
        $QueuedUpdates = "{0,3}" -f $QueuedUpdates
        $ReturnMsg = "Updates Queued:"+$QueuedUpdates
        }

    if ([int]$FailedCnt -gt 15 -OR ($QueuedUpdates -match 'Exception: ') ) {
        $ReturnValue += ACreate-TestResult "Windows Update Status" $ReturnMsg $false
        }
    else {
        $ReturnValue += ACreate-TestResult "Windows Update Status" $ReturnMsg $true
        }

return ACreate-Test "Windows Update Status" $ReturnValue
}


########################################
###### Get Windows Updates Status ######
########################################
function Aget-CheckWindowsUpdateStatus2($server) {
    $ReturnValue = @()
    $ReturnMsg = ""

    $WUstatus = Invoke-Command -ComputerName $server -ScriptBlock {(New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search(“IsHidden=0 and IsInstalled=0”).Updates | Select-Object Title} -ErrorAction Continue    
    foreach ($item in $WUstatus) {
        $ReturnMsg = $item.title
        $ReturnValue += ACreate-TestResult "Windows Updates" $ReturnMsg $false
        }
Return ACreate-Test "Windows Updates" $ReturnValue
}


####################################
###### Get Windows UAC Status ######
####################################
function Aget-UACLevel($server) {
 
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
        $ReturnValue += ACreate-TestResult "Windows UAC" $ReturnMsg $false
        }
    elseIf($ConsentPromptBehaviorAdmin_Value -Eq 0 -And $PromptOnSecureDesktop_Value -Eq 0){ 
        $ReturnMsg = "Enabled with Never Notify"
        $ReturnMsg = "Enabled"
        $ReturnValue += ACreate-TestResult "Windows UAC" $ReturnMsg $false
    } 
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 0){ 
        $ReturnMsg = "Enabled with Notify Me only when apps try to make changes to My Computer(do not Dim Desktop)"
        $ReturnMsg = "Enabled"
        $ReturnValue += ACreate-TestResult "Windows UAC" $ReturnMsg $false
    }
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 1){ 
        $ReturnMsg = "Enabled with Notify Me only when apps try to make changes to My Computer(default)"
        $ReturnMsg = "Enabled"
        $ReturnValue += ACreate-TestResult "Windows UAC" $ReturnMsg $true
    } 
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 2 -And $PromptOnSecureDesktop_Value -Eq 1){ 
        $ReturnMsg = "Enabled with Always notify"
        $ReturnMsg = "Enabled"
        $ReturnValue += ACreate-TestResult "Windows UAC" $ReturnMsg $true
    } 
    Else{ 
        $ReturnMsg = "Unknown state"
        $ReturnValue += ACreate-TestResult "Windows UAC" $ReturnMsg $false
    }
return ACreate-Test "Windows UAC" $ReturnValue
}


######################################
###### Get DNS Settings per NIC ######
######################################
function Aget-CheckWindowsDNSSettingsPerNIC($server, $WINS_Servers) {

    $server=$server.ToLower()
    $ReturnValue = @()
    $ReturnMsg = ""
    $ReturnMsg1 = @()    

    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0
    $ips = @()
    $dcs = @()
    $No_Reverse_DNS_IP = @()

    $nstemp = $ns    
    $No_Reverse_DNS_Zone = ""
    #$No_Reverse_DNS_IP = ""
    $ServerIPs = ""

    do  {        
        $pos = $nstemp.IndexOf(":")
        if ($pos -gt -1) {
            $nstemp = $nstemp.Substring($pos+1)
            }
        } while ($pos -gt -1)
    $nstemp = $nstemp.Trim()

    do  {
       if ($nstemp.split(" ")[$i].trim() -ne "") {
            $ips += $nstemp.split(" ")[$i].trim()
            }
       $i = $i +1
        } while ($i -ne ($nstemp.split(" ").count))

    foreach ($item in $domain.DomainControllers.name) {
        #echo $item.toupper()
        $dcs += $item.toupper()
        }

    foreach ($item in $ips) {
        try {
            $temp_dc = [System.Net.Dns]::GetHostbyAddress($item)
            #write-host $temp_dc.HostName+"  <-> "$item
            #$dcs += $temp_dc.HostName
            }
        catch {
            #echo "No reverse IP Zone for ip $item"
            #$No_Reverse_DNS_Zone = "No Reverse IP Zone/PTR Record for ip "
            $No_Reverse_DNS_IP += $item
            }
        }

    $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $server -ErrorAction Stop

    $DNS_Servers_Ok=$true
    $WINS_Servers_Ok=$true
    $DNS_Server=""
    $ReturnMsg2 = @()
    $ReturnMsg3 =""

    foreach($Network in $Networks) {
        $pos=1
        if ($Network.DNSServerSearchOrder.length -gt 0) {
            $DNSServers = $DNSServers + $Network.DNSServerSearchOrder
            }

        foreach ($DNSServer in $DNSServers) {
            $ServerIsDC = $False
            foreach ($item in $domain.DomainControllers.name.toupper()) {
                if ( ($domain.DomainControllers.name.toupper()).Contains($server.ToUpper()+"."+$domain.name.toupper()) ) {
                    $ServerIsDC = $True
                    }
                }

            if ( ( ($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -eq $pos) -and ($pos -ne 1) ) -and ($ServerIsDC) ) {
                    #echo "127.0.0.1 is the last DNS server in the list on a DC = OK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $true)
                    }
            elseif ( ( ($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -eq $pos) -and ($pos -eq 1) ) -and ($ServerIsDC) ) {
                    #echo "127.0.0.1 is the first and only DNS server in the list on a DC = NOK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }
            elseif (($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -ne $pos)) {
                    #echo "127.0.0.1 is not the last DNS server in the list = NOK"
                    $ReturnMsg2 += $DNSServer
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }
            elseif ($ips.Contains($DNSServer)) {
                    #echo $DNSServer" is a known AD DNS server = OK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $true)
                    }
            elseif (-not($ips.Contains($DNSServer))) {
                    #echo $DNSServer" is not a known AD DNS server = NOK"
                    $ReturnMsg2 += $DNSServer
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }

            #foreach ($DNSServer in $DNSServers) 
            $pos=$pos+1
            }

        $NetworkName = $Network.Description
        if ($NetworkName -contains "iDRAC Virtual NIC*") {
            echo "iDRAC NIC"
            }
        $WINSPrimaryserver = $Network.WINSPrimaryServer 
        $WINSSecondaryserver = $Network.WINSSecondaryserver 

        if ($WINS_Servers.Count -gt 0 -and $WINSPrimaryserver.length -eq 0 -and $WINSSecondaryserver.length -eq 0) {
            #echo "Wrong Config, WINS Servers exist but no WINS configured on NIC Settings"
            $WINS_Servers_Ok=($WINS_Servers_Ok -band $false)
            }
        elseif ($WINS_Servers.Count -gt 0 -and ($WINSPrimaryserver.length -ne 0 -or $WINSSecondaryserver.length -ne 0) ) {
                #echo "2 WINS Servers configured on NIC Settings"
                $WINS_Servers_Ok=($WINS_Servers_Ok -band $true)    
                #}
                if ($WINSPrimaryserver.length -ne 0) {
                    if ($WINS_Servers.Contains($WINSPrimaryserver)) {
                        #echo "NIC Primary WINS Server setting is a valid WINS Server"
                        $WINS_Servers_Ok=($WINS_Servers_Ok -band $true)
                        }
                    else {
                        #echo "NIC Primary WINS Server setting is not a valid WINS Server"
                        $WINS_Servers_Ok=($WINS_Servers_Ok -band $false)
                        }
                    }

                if ($WINSSecondaryserver.length -ne 0) {
                    if ($WINS_Servers.Contains($WINSSecondaryserver)) {
                        #echo "NIC Secondary WINS Server setting is a valid WINS Server"
                        $WINS_Servers_Ok=($WINS_Servers_Ok -band $true)
                        }
                    else {
                        #echo "NIC Secondary WINS Server setting is not a valid WINS Server"
                        $WINS_Servers_Ok=($WINS_Servers_Ok -band $false)
                        }
                    }
                }
        elseif ($WINS_Servers.Count -eq 0 -and ($WINSPrimaryserver.length -ne 0 -or $WINSSecondaryserver.length -ne 0) ) {
                #echo "No WINS Servers, but NIC has at least one WINS Server configured"
                $WINS_Servers_Ok=($WINS_Servers_Ok -band $false)
                }

        If(!$DNSServers) {
            $PrimaryDNSServer = "Notset"
            $SecondaryDNSServer = "Notset"
            }
        elseif($DNSServers.count -eq 1) {
            $PrimaryDNSServer = $DNSServers[0]
            $SecondaryDNSServer = "Notset"
            }
            else
                {
                $PrimaryDNSServer = $DNSServers[0]
                $SecondaryDNSServer = $DNSServers[1]
                }
        # ENd of the foreach($Network in $Networks)
        }

    $ReturnMsg = $DNSServers
    $ReturnMsg1 += $WINSPrimaryserver
    $ReturnMsg1 += $WINSSecondaryserver

    if ($DNS_Servers_Ok) {
        #write-host "DNS and WINS Config Ok"
        #echo $DNSServers + $WINSPrimaryserver + $WINSSecondaryserver
        $ReturnValue += ACreate-TestResult "DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        }
    else {
        #write-host "DNS Or WINS Config Not Ok"
        #echo $DNSServers + $WINSPrimaryserver + $WINSSecondaryserver
        $ReturnMsg3 = " -> Invalid DNS Server(s): " + $ReturnMsg2
        $ReturnValue += ACreate-TestResult "DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        $ReturnValue += ACreate-TestResult "DNS Settings per NIC" $ReturnMsg3 $DNS_Servers_Ok
        }    

    if ($WINS_Servers.Count -gt 0) {
        if ( ($WINSPrimaryserver -eq $null) -and ($WINSSecondaryserver -eq $null) ) {
            #write-host "No Primary or Secondary WINS Configured"
            $ReturnValue += ACreate-TestResult "WINS Settings per NIC" "No Primary or Secondary WINS Configured" $false
            }
        elseif( ($WINSPrimaryserver -ne $null) -or ($WINSSecondaryserver -ne $null) ) {
            #write-host "Primary or Secondary WINS Configured"
            $ReturnValue += ACreate-TestResult "WINS Settings per NIC" $ReturnMsg1 $true
            }
        }
    else {
        #write-host "There are NO WINS Servers"
        if ( ($WINSPrimaryserver.length -ne 0) -or ($WINSSecondaryserver.length -ne 0) ) {
            #write-host "No WINS Servers, but NIC has at least one WINS Server configured"
            $ReturnMsg3 = " -> No WINS Servers, but NIC has a WINS Server(s): " + $ReturnMsg1
            $ReturnValue += ACreate-TestResult "WINS Settings per NIC" $ReturnMsg3 $false
            }

        }

    #}

    #$ServerIP = (Resolve-DnsName $server).ipaddress
    $ServerIP = Aget-Resolve-DnsName $server
    #if ($No_Reverse_DNS_IP -eq $ServerIP) {
    if ( $No_Reverse_DNS_IP.Contains($ServerIP) ) {
        $No_Reverse_DNS_Zone = "No PTR Record for ip "
        #$No_Reverse_DNS_IP = $ServerIP
        $DNS_Servers_Ok=$false
        $ReturnMsg = $No_Reverse_DNS_Zone+$No_Reverse_DNS_IP
        $ReturnValue += ACreate-TestResult "DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        }

return ACreate-Test "DNS and WINS Settings per NIC" $ReturnValue
}


#########################################
###### Get DNS Settings per NIC V2 ######
#########################################
function Aget-CheckWindowsDNSSettingsPerNIC2($server) {
    $server=$server.ToLower()
    $ReturnValue = @()
    $ReturnMsg = ""

    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0
    $ips = @()
    $dcs = @()
    $nstemp = $ns    
    $No_Reverse_DNS_Zone = ""
    $No_Reverse_DNS_IP = ""
    $ServerIPs = ""

    do  {        
        $pos = $nstemp.IndexOf(":")
        if ($pos -gt -1) {
            $nstemp = $nstemp.Substring($pos+1)
            }
        } while ($pos -gt -1)
    $nstemp = $nstemp.Trim()

    do  {
       if ($nstemp.split(" ")[$i].trim() -ne "") {
            $ips += $nstemp.split(" ")[$i].trim()
            }
       $i = $i +1
        } while ($i -ne ($nstemp.split(" ").count))

    foreach ($item in $ips) {
        try {
            $temp_dc = [System.Net.Dns]::GetHostbyAddress($item)
            #write-host $temp_dc.HostName+"  <-> "$item
            $dcs += $temp_dc.HostName
            }
        catch {
            #echo "No reverse IP Zone for ip $item"
            $No_Reverse_DNS_Zone = "No Reverse IP Zone/PTR Record for ip $item"
            $No_Reverse_DNS_IP = $item
            }
        }
    
    $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $server -ErrorAction Stop

    foreach($Network in $Networks) {
        $pos=1
        $DNS_Servers_Ok=$true
        $DNSServers = $Network.DNSServerSearchOrder

        foreach ($DNSServer in $DNSServers) {
            if ( ( ($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -eq $pos) ) -and ($domain.DomainControllers.name.Contains($server) ) ) {                 
                    #echo "127.0.0.1 is the last DNS server in the list on a DC = OK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $true)
                    }
            elseif (($DNSServer -eq "127.0.0.1") -and ([int]$DNSServers.count -ne $pos)) {
                    #echo "127.0.0.1 is not the last DNS server in the list = NOK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }
            elseif ($ips.Contains($DNSServer)) {
                    #echo $DNSServer" is a known AD DNS server = OK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $true)
                    }
            elseif (-not($ips.Contains($DNSServer))) {
                    #echo $DNSServer" is not a known AD DNS server = NOK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }

            if ($IPs.Contains($No_Reverse_DNS_IP)) {
                if ( ( ([System.Net.Dns]::GetHostAddresses($server)).ipaddresstostring -eq $No_Reverse_DNS_IP) -and ( ([System.Net.Dns]::GetHostAddresses($server)).addressfamily -eq "InterNetwork") ) {
                    #echo $No_Reverse_DNS_Zone + " = NOK"
                    $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
                    }
                }

            $pos=$pos+1
            }

        if ( ($No_Reverse_DNS_Zone.length -eq 0) ) {
            $ReturnMsg = $DNSServers
            }
        elseif ( ($No_Reverse_DNS_Zone.length -ne 0) -and ( ($domain.DomainControllers.ipaddress).Contains( ([System.Net.Dns]::GetHostAddresses($server)).ipaddresstostring ) -and ( ([System.Net.Dns]::GetHostAddresses($server)).addressfamily -eq "InterNetwork") ) ) {
            $DNS_Servers_Ok=($DNS_Servers_Ok -band $false)
            $ReturnMsg = $DNSServers + $No_Reverse_DNS_Zone
            }

        $NetworkName = $Network.Description
        $WINSPrimaryserver = $Network.WINSPrimaryServer 
        $WINSSecondaryserver = $Network.WINSSecondaryserver 
        If(!$DNSServers) {
            $PrimaryDNSServer = "Notset"
            $SecondaryDNSServer = "Notset"
            }
        elseif($DNSServers.count -eq 1) {
            $PrimaryDNSServer = $DNSServers[0]
            $SecondaryDNSServer = "Notset"
            }
            else
                {
                $PrimaryDNSServer = $DNSServers[0]
                $SecondaryDNSServer = $DNSServers[1]
                }        
        }

    if ($DNS_Servers_Ok) {
        write-host "DNS Config Ok"        
        $ReturnValue += ACreate-TestResult "Server DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        }
    else {
        write-host "DNS Config Not Ok"
        $ReturnValue += ACreate-TestResult "Server DNS Settings per NIC" $ReturnMsg $DNS_Servers_Ok
        }

return ACreate-Test "Server DNS Settings per NIC" $ReturnValue
}


################################################
###### Get Windows DFS Replication Status ######
################################################
function Aget-DFSR_Replication_Status2() {
$RGroups = Get-WmiObject  -Namespace "root\MicrosoftDFS" -Query "SELECT * FROM DfsrReplicationGroupConfig"
#If  replication groups specified, use only those.
        
#$ComputerName=$env:ComputerName
$ComputerName="EVO-FP-51"
$Succ=0
$Warn=0
$Err=0
 
foreach ($Group in $RGroups)
{
    $RGFoldersWMIQ = "SELECT * FROM DfsrReplicatedFolderConfig WHERE ReplicationGroupGUID='" + $Group.ReplicationGroupGUID + "'"
    $RGFolders = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query  $RGFoldersWMIQ
    $RGConnectionsWMIQ = "SELECT * FROM DfsrConnectionConfig WHERE ReplicationGroupGUID='"+ $Group.ReplicationGroupGUID + "'"
    $RGConnections = Get-WmiObject -Namespace "root\MicrosoftDFS" -Query  $RGConnectionsWMIQ
    foreach ($Connection in $RGConnections)
    {
        $ConnectionName = $Connection.PartnerName#.Trim()
        if ($Connection.Enabled -eq $True)
        {
            #if (((New-Object System.Net.NetworkInformation.ping).send("$ConnectionName")).Status -eq "Success")
            #{
                foreach ($Folder in $RGFolders)
                {
                    $RGName = $Group.ReplicationGroupName
                    $RFName = $Folder.ReplicatedFolderName
 
                    if ($Connection.Inbound -eq $True)
                    {
                        $SendingMember = $ConnectionName
                        $ReceivingMember = $ComputerName
                        $Direction="inbound"
                    }
                    else
                    {
                        $SendingMember = $ComputerName
                        $ReceivingMember = $ConnectionName
                        $Direction="outbound"
                    }
 
                    $BLCommand = "dfsrdiag Backlog /RGName:'" + $RGName + "' /RFName:'" + $RFName + "' /SendingMember:" + $SendingMember + " /ReceivingMember:" + $ReceivingMember
                    $Backlog = Invoke-Expression -Command $BLCommand
 
                    $BackLogFilecount = 0
                    foreach ($item in $Backlog)
                    {
                        if ($item -ilike "*Backlog File count*")
                        {
                            $BacklogFileCount = [int]$Item.Split(":")[1].Trim()
                        }
                    }
 
                    if ($BacklogFileCount -eq 0)
                    {
                        $Color="white"
                        $Succ=$Succ+1
                    }
                    elseif ($BacklogFilecount -lt 10)
                    {
                        $Color="yellow"
                        $Warn=$Warn+1
                    }
                    else
                    {
                        $Color="red"
                        $Err=$Err+1
                    }
                    #$BacklogFileCount = "{0:N0}" -f $BacklogFileCount
                    $BacklogFileCount = "{0,7}" -f $BacklogFileCount
                    Write-Host "$BacklogFileCount files in backlog $SendingMember->$ReceivingMember for $RGName" -fore $Color
 
                } # Closing iterate through all folders
            #} # Closing  If replies to ping
        } # Closing  If Connection enabled
    } # Closing iteration through all connections
} # Closing iteration through all groups
Write-Host "$Succ successful, $Warn warnings and $Err errors from $($Succ+$Warn+$Err) replications."
      
Return $ReturnMsg
}


#################################################
###### Get Windows Forest Functional Level ######
#################################################
Function Aget-WindowsForestFunctionalLevel() {
#
#DGO: Only test on Accessable DC's (Stihl)
#
#$AD_Forest_Func_Level = Get-ADForest
#$AD_Forest_Func_Level.Forestmode
#Get-ADForest | select forestmode | ft -Wrap –Auto
$SearchBase="CN=Partitions,CN=CONFIGURATION,"+$LdapDomain
#$AD_Forest_Func_Level=dsquery * $SearchBase -scope base -attr msDS-Behavior-Version
#$DCs=(Get-ADForest).Domains | % { Get-ADDomainController -Discover -DomainName  $_ } | % { Get-ADDomainController -server $_.Name -filter * } | Select Name
#$Server=$DCs[0].name

$FFLevels = @()
$Compare_Value = ""
$FFLevel_Status_Ok = $true

foreach ($DC in $domain.DomainControllers | sort) {
    if ($Servers.servername.contains(($DC.Name.replace("."+$domain.name,"")).toupper())) { 
        $Server=$DC.name.ToUpper()
        $AD_Forest_Func_Level = Invoke-Command -ComputerName $server -ScriptBlock {dsquery * $SearchBase -scope base -attr msDS-Behavior-Version}
        $AD_Forest_Func_Level=$AD_Forest_Func_Level[1]

        if ($Compare_Value -eq "") {
            $Compare_Value = $AD_Forest_Func_Level
            $FFLevels += $server+"|"+$AD_Forest_Func_Level.trim()
            }
        elseif ($Compare_Value -ne $AD_Forest_Func_Level) {
                $FFLevel_Status_Ok = $false
                $FFLevels += $server+"|"+$AD_Forest_Func_Level.Trim()
                }
            else {
                $FFLevels += $server+"|"+$AD_Forest_Func_Level.Trim()
                }
        }
    }

        if ($FFLevel_Status_Ok) {
            switch ($AD_Forest_Func_Level.trim()) {
                0 {echo "Windows Forest Functional Level: Windows 2000"}
                1 {echo "Windows Forest Functional Level: Windows 2003 interim"}
                2 {echo "Windows Forest Functional Level: Windows 2003"}
                3 {echo "Windows Forest Functional Level: Windows 2008"}
                4 {echo "Windows Forest Functional Level: Windows 2008 R2"}
                5 {echo "Windows Forest Functional Level: Windows 2012"}
                6 {echo "Windows Forest Functional Level: Windows 2012 R2"}
                7 {echo "Windows Forest Functional Level: Windows 2016"}
                8 {echo "Windows Forest Functional Level: Windows 2019"}
                }                
            }
        else {
            foreach ($item in $FFLevels) {
                $Server = $item.split("|")[0]
                $FFLevel = $item.split("|")[1]
                switch ($FFLevel) {            
                    0 {echo "Windows Forest Functional Level: Windows 2000 ($Server)"}
                    1 {echo "Windows Forest Functional Level: Windows 2003 interim ($Server)"}
                    2 {echo "Windows Forest Functional Level: Windows 2003 ($Server)"}
                    3 {echo "Windows Forest Functional Level: Windows 2008 ($Server)"}
                    4 {echo "Windows Forest Functional Level: Windows 2008 R2 ($Server)"}
                    5 {echo "Windows Forest Functional Level: Windows 2012 ($Server)"}
                    6 {echo "Windows Forest Functional Level: Windows 2012 R2 ($Server)"}
                    7 {echo "Windows Forest Functional Level: Windows 2016 ($Server)"}
                    8 {echo "Windows Forest Functional Level: Windows 2019 ($Server)"}
                    }
                }
            }
}


#################################################
###### Get Windows Domain Functional Level ######
#################################################
function Aget-WindowsDomainFunctionalLevel() {
#
$DFLevels = @()
$Compare_Value = ""
$DFLevel_Status_Ok = $true

$SearchBase=$LdapDomain

#DGO: Only test on Accessable DC's
#
foreach ($DC in $domain.DomainControllers | sort) {
    if ($Servers.servername.contains(($DC.Name.replace("."+$domain.name,"")).toupper())) { 
        $Server=$DC.name.toupper()
        $AD_Domain_Func_Level1 = Invoke-Command -ComputerName $server -ScriptBlock {dsquery * $SearchBase -scope base -attr msDS-Behavior-Version}
        $AD_Domain_Func_Level2 = Invoke-Command -ComputerName $server -ScriptBlock {dsquery * $SearchBase -scope base -attr ntMixedDomain}

        $AD_Domain_Func_Level=$AD_Domain_Func_Level1[1].trim()+$AD_Domain_Func_Level2[1].trim()

        if ($Compare_Value -eq "") {
            $Compare_Value = $AD_Domain_Func_Level
            $DFLevels += $server+"|"+$AD_Domain_Func_Level.trim()
            }
        elseif ($Compare_Value -ne $AD_Domain_Func_Level) {
                $DFLevel_Status_Ok = $false
                $DFLevels += $server+"|"+$AD_Domain_Func_Level.Trim()
                }
            else {
                $DFLevels += $server+"|"+$AD_Domain_Func_Level.Trim()
                }
        }
    }

    if ($DFLevel_Status_Ok) {
    switch ($AD_Domain_Func_Level.trim()) {
        00 {echo "Windows Domain Functional Level: Windows 2000 Native"}
        01 {echo "Windows Domain Functional Level: Windows 2000 Mixed"}
        20 {echo "Windows Domain Functional Level: Windows 2003"}
        30 {echo "Windows Domain Functional Level: Windows 2008"}
        40 {echo "Windows Domain Functional Level: Windows 2008 R2"}
        50 {echo "Windows Domain Functional Level: Windows 2012"}
        60 {echo "Windows Domain Functional Level: Windows 2012 R2"}
        70 {echo "Windows Domain Functional Level: Windows 2016"}
        80 {echo "Windows Domain Functional Level: Windows 2019"}
            }                
        }
    else {
        foreach ($item in $DFLevels) {
            $Server = $item.split("|")[0]
            $DFLevel = $item.split("|")[1]
            switch ($DFLevel) {            
                00 {echo "Windows Domain Functional Level: Windows 2000 Native ($Server)"}
                01 {echo "Windows Domain Functional Level: Windows 2000 Mixed ($Server)"}
                20 {echo "Windows Domain Functional Level: Windows 2003 ($Server)"}
                30 {echo "Windows Domain Functional Level: Windows 2008 ($Server)"}
                40 {echo "Windows Domain Functional Level: Windows 2008 R2 ($Server)"}
                50 {echo "Windows Domain Functional Level: Windows 2012 ($Server)"}
                60 {echo "Windows Domain Functional Level: Windows 2012 R2 ($Server)"}
                70 {echo "Windows Domain Functional Level: Windows 2016 ($Server)"}
                80 {echo "Windows Domain Functional Level: Windows 2019 ($Server)"}
                }
            }
        }
}


########################################################
###### Get Windows DFSR SYSVOL Replication Status ######
########################################################
function Aget-DFSR_SYSVOL_Replication_Migration_State() {

#$DCs=(Get-ADForest).Domains | % { Get-ADDomainController -Discover -DomainName  $_ } | % { Get-ADDomainController -server $_.Name -filter * } | Select Name
#$Server=$DCs[0].name
$DFSR_Migration_States = @()
$DFSR_Global_States = @()
$Compare_Value = ""
$DFSR_Global_State = $true

#DGO: Only test on Accessable DC's
#
foreach ($DC in $domain.DomainControllers | sort) {
    if ($Servers.servername.contains(($DC.Name.replace("."+$domain.name,"")).toupper())) {
        $Server=$DC.name.toupper()
        $Status1 = Invoke-Command -ComputerName $server -ScriptBlock {dfsrmig /getmigrationstate}
        $Status2 = Invoke-Command -ComputerName $server -ScriptBlock {dfsrmig /getglobalstate}
        $ResultMsg = $status1[0]
        $ResultMsg2 = $Status2[0]
    
        if ($Compare_Value -eq "") {
            $Compare_Value = $ResultMsg2
            $DFSR_Global_States += $server+"|"+$ResultMsg2.trim()
            $DFSR_Migration_States += $server+"|"+$ResultMsg.trim()
            }
        elseif ($Compare_Value -ne $ResultMsg2) {
                $DFSR_Global_State = $false
                $DFSR_Global_States += $server+"|"+$ResultMsg2.trim()
                $DFSR_Migration_States += $server+"|"+$ResultMsg.Trim()            
                }
            else {
                $DFSR_Global_States += $server+"|"+$ResultMsg2.trim()
                $DFSR_Migration_States += $server+"|"+$ResultMsg.Trim()            
                }
        }
    }

    if ($DFSR_Global_State) {
        if ($ResultMsg2 -eq $ResultMsg) {
            echo "$ResultMsg2"
            }
        else {
            echo "$ResultMsg2, $ResultMsg"
            }
        }
    else {
        $i = 0
        foreach ($item in $DFSR_Global_States) {
            #$ReturnMsg = $item.split("|")[1]+" ("+$item.split("|")[0]+")"
            if ($item.split("|")[1] -eq $DFSR_Migration_States[$i].split("|")[1]) {
                $ReturnMsg2 = $item.split("|")[1]+" ("+$item.split("|")[0]+")"
                $i = $i +1
                echo $ReturnMsg2
                }
            else {
                $ReturnMsg2 = $item.split("|")[1]+", "+$DFSR_Migration_States[$i].split("|")[1]+" ("+$item.split("|")[0]+")"
                $i = $i +1
                echo $ReturnMsg2
                }
            }
        }
}


##########################################
###### Get Azure AD Connect Version ######
##########################################
function Aget-AAD_Connect_Version($comp) {
# "C:\Program Files\Microsoft Azure Active Directory Connect\AzureADConnect.exe"
# "C:\Program Files\Microsoft Azure AD Sync\UIShell\miisclient.exe"
# "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync\Microsoft.Azure.ActiveDirectory.Synchronization.Framework.dll"
# "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe"  SYNCHRONISATION PROCESS

$filename = ""
$ReturnValue = @()
$ReturnMessage = ""

# https://www.microsoft.com/en-us/download/details.aspx?id=47594

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'miiserver.exe'" -ErrorAction Continue
if ($processes -eq $null) 
    {
    #echo "Microsoft Azure AD Sync Not Installed"
    $ReturnValue += ACreate-TestResult "Microsoft Azure AD Sync/Connect" "Not Installed" $true
    return ACreate-Test "Microsoft Azure AD Sync/Connect" $ReturnValue
    }
else {
    $Filename = $Processes.ExecutablePath
    #$FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Filename).FileVersion
    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename
    #echo "Microsoft Azure AD Sync/Connect Installed Version: $FileVersion Installed"
    
    $AAD_Sync = Invoke-Command -ComputerName $comp -ScriptBlock {Get-ADSyncScheduler}
    $AAD_NextSyncCycle = $AAD_Sync.NextSyncCycleSTartTimeInUTC
    $AAD_SyncCycleEnabled =  $AAD_Sync.SyncCycleEnabled
    $AAD_StagingModeEnabled = $AAD_Sync.StagingModeEnabled
    $AAD_SchedulerSuspended = $AAD_Sync.SchedulerSuspended
    $AAD_NextSyncCyclePolicyType = $AAD_Sync.NextSyncCyclePolicyType

    $NextSyncCycleUTCTime = Get-Date $AAD_NextSyncCycle
    $strCurrentTimeZone = (Get-WmiObject win32_timezone -computername $comp).StandardName
    $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
    $NextSyncCycleLocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($NextSyncCycleUTCTime, $TZ)

    $ReturnMessage = " + SyncEnabled:"+$AAD_SyncCycleEnabled+" - StagingEnabled:"+$AAD_StagingModeEnabled+" - SchedulerSuspended:"+$AAD_SchedulerSuspended+" - PolicyType:"+$AAD_NextSyncCyclePolicyType+" - NextSync:"+$NextSyncCycleLocalTime
    
    $ReturnValue += ACreate-TestResult "Microsoft Azure AD Sync/Connect" "Version: $FileVersion Installed" $true    
    
    if ($AAD_SyncCycleEnabled -AND (-NOT($AAD_SchedulerSuspended)) -AND (-NOT($AAD_StagingModeEnabled)) ) {
        $ReturnValue += ACreate-TestResult "Microsoft Azure AD Sync/Connect" $ReturnMessage $true    
        }
    Else {
        $ReturnValue += ACreate-TestResult "Microsoft Azure AD Sync/Connect" $ReturnMessage $false
        }
    
    return ACreate-Test "Microsoft Azure AD Sync/Connect" $ReturnValue
    }
}


################################################
### Get Windows Server Best Practices Status ###
### Windows Server BPA                       ###
################################################
function Aget-WindowsBPA($comp) {
#
#$COMP="SFC-DC-01"
$OS_Version = Aget-OSVersion $comp
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
                            $LineDetails = Get-BpaResult –BestPracticesModelID $Line.ModelID
                            if ($Line.ModelID -ne "Microsoft/Windows/Hyper-V") {
                                foreach ($item in $LineDetails) {
                                    #$item | Where-Object { ( ($item.Severity –eq 'Error') -OR ($item.Severity –eq 'Warning') ) -AND ($item.Excluded –eq $false) } | Select Title, Problem, Resolution, Help | FL Title, Problem, Resolution, Help
                                    $item | Where-Object { ( ($item.Severity –eq 'Error') -OR ($item.Severity –eq 'Warning') ) -AND ($item.Excluded –eq $false) } | Select-Object -Property @{Name="Title"; Expression={ $_.Title.ToString().Trim()}}, @{Name="Problem"; Expression={ $_.Problem.ToString().Trim()}}, @{Name="Resolution"; Expression={ $_.Resolution.ToString().Trim()}}, @{Name="Help"; Expression={ $_.Help.ToString().Trim()}} | FL Title, Problem, Resolution, Help
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


###########################################
#### Get SQL Server Instances Versions ####
function Aget-SQL_Server_Instances($comp) {
###########################################
$ReturnValue = @()

$Instances = Invoke-Command -ComputerName $comp -ScriptBlock {(get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances} -ErrorAction SilentlyContinue
if ($Instances -eq $null) {
    $ReturnValue += ACreate-TestResult "SQL Server" "Not Installed" $true
    }
else {
    foreach ($Instance in $Instances) {
        $SQL_INSTANCE_KEY="HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
        $SQL_Instance_Detail = Invoke-Command -ComputerName $comp -ScriptBlock {(get-itemproperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL")} -ErrorAction SilentlyContinue
        $SQL_Instance_Properties = Invoke-Command -ComputerName $comp -ScriptBlock {PARAM($param1) (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$param1\Setup")} -ArgumentList $SQL_Instance_Detail.$Instance -ErrorAction SilentlyContinue

        #$SQL_Instance_Properties.PatchLevel.split(".")[0]
        Switch ($SQL_Instance_Properties.PatchLevel.split(".")[0]) {
            "15" {$ReturnMsg = "Version: 2019 - "+$SQL_Instance_Properties.Edition+" installed"}
            "14" {$ReturnMsg = "Version: 2017 - "+$SQL_Instance_Properties.Edition+" installed"}
            "13" {$ReturnMsg = "Version: 2016 - "+$SQL_Instance_Properties.Edition+" installed"}
            "12" {$ReturnMsg = "Version: 2014 - "+$SQL_Instance_Properties.Edition+" installed"}
            "11" {$ReturnMsg = "Version: 2012 - "+$SQL_Instance_Properties.Edition+" installed"}
            "10" {
                  if ($SQL_Instance_Properties.PatchLevel.split(".")[0] -eq "50") {
                      $ReturnMsg = "Version: 2008R2 - "+$SQL_Instance_Properties.Edition+" installed"}
                  else {
                      $ReturnMsg = "Version: 2008 - "+$SQL_Instance_Properties.Edition+" installed"}
                  }
            "9" {$ReturnMsg = "Version: 2005 - "+$SQL_Instance_Properties.Edition+" installed"}
            "8" {$ReturnMsg = "Version: 2000 - "+$SQL_Instance_Properties.Edition+" installed"}
            "7" {$ReturnMsg = "Version: 7.0 - "+$SQL_Instance_Properties.Edition+" installed"}
            }
        $ReturnValue += ACreate-TestResult "SQL Server" $ReturnMsg $true    
        }
    }
    
Return ACreate-Test "SQL Server" $ReturnValue
}


##########################################
###### Check for Windows RDS Server ######
##########################################
function Aget-RDS_Server($comp) {
$ReturnValue = @()

$RDS_Server = Invoke-command -ComputerName $comp {Get-WmiObject -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" | select -ExpandProperty TerminalServerMode}

if ($RDS_Server) {
    $ReturnMsg = "Role installed"
    }
else {
    $ReturnMsg = "Role not installed"    
    }
$ReturnValue += ACreate-TestResult "RDS Server" $ReturnMsg $true

Return ACreate-Test "RDS Server" $ReturnValue
}


#########################################
#### Check for Secure LDAP AD Access ####
#########################################
function Aget-DC_LDAPSSL() {
# https://www.youtube.com/watch?v=xC3ujXGkh_c
# http://vcloud-lab.com/entries/windows-2016-server-r2/configuring-secure-ldaps-on-domain-controller
$ReturnValue = @()

[int] $GCPortLDAP = 3268
[int] $GCPortLDAPSSL = 3269
[int] $PortLDAP = 389
[int] $PortLDAPSSL = 636
        
#Get all DC's
$DCs = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().DomainControllers

foreach ($DC in $DCs) {
    $GC_LDAP = [ADSI]"LDAP://$($dc.name):$GCPortLDAP"
    $GC_LDAPSSL = [ADSI]"LDAP://$($dc.name):$GCPortLDAPSSL"
    $LDAP = [ADSI]"LDAP://$($dc.name):$PortLDAP"
    $LDAPSSL = [ADSI]"LDAP://$($dc.name):$PortLDAPSSL"

    try {$Connection_GC_LDAP = [adsi]($GC_LDAP)} Catch {}
    If ($Connection_GC_LDAP.Path) {
        $ReturnMsg = "Global Catalog Unsecure Connection to LDAP://$($dc.name):$GCPortLDAP"
        $ReturnValue += ACreate-TestResult "Domain Controller Secure LDAP" $ReturnMsg $true
        }
    Else {
        $ReturnMsg = "Global Catalog Unsecure Connection to LDAP://$($dc.name):$GCPortLDAP"
        $ReturnValue += ACreate-TestResult "Domain Controller Secure LDAP" $ReturnMsg $false
        }

    try {$Connection_GC_LDAPSSL = [adsi]($GC_LDAPSSL)} Catch {}
    If ($Connection_GC_LDAPSSL.Path) {
        $ReturnMsg = "Global Catalog Secure   Connection to LDAP://$($dc.name):$GCPortLDAPSSL"
        $ReturnValue += ACreate-TestResult "Domain Controller Secure LDAP" $ReturnMsg $true
        }
    Else {
        $ReturnMsg = "Global Catalog Secure   Connection to LDAP://$($dc.name):$GCPortLDAPSSL"
        $ReturnValue += ACreate-TestResult "Domain Controller Secure LDAP" $ReturnMsg $false
        }

    try {$Connection_LDAP = [adsi]($LDAP)} Catch {}
    If ($Connection_LDAP.Path) {
        $ReturnMsg = "Standard Unsecure       Connection to LDAP://$($dc.name):$PortLDAP"
        $ReturnValue += ACreate-TestResult "Domain Controller Secure LDAP" $ReturnMsg $true
        } 
    Else {
        $ReturnMsg = "Standard Unsecure       Connection to LDAP://$($dc.name):$PortLDAP"
        $ReturnValue += ACreate-TestResult "Domain Controller Secure LDAP" $ReturnMsg $false
        }

    try {$Connection_LDAPSSL = [adsi]($LDAPSSL)} Catch {}
    If ($Connection_LDAPSSL.Path) {
        $ReturnMsg = "Standard Secure         Connection to LDAP://$($dc.name):$PortLDAPSSL"
        $ReturnValue += ACreate-TestResult "Domain Controller Secure LDAP" $ReturnMsg $true
        } 
    Else {
        $ReturnMsg = "Standard Secure         Connection to LDAP://$($dc.name):$PortLDAPSSL"
        $ReturnValue += ACreate-TestResult "Domain Controller Secure LDAP" $ReturnMsg $false
        }
    }

Return ACreate-Test "Domain Controller Secure LDAP" $ReturnValue
}


###################################################
#### Get RDP Network Location Awareness Status ####
###################################################
function Aget-RDP_NLA($comp) {

    $ReturnValue = @()
    
    $RDP_NLA = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $comp -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
    
    if ($RDP_NLA) {
        $ReturnMsg = "Enabled"
        $ReturnValue += ACreate-TestResult "RDP NLA" $ReturnMsg $true
        }
    else {
        $ReturnMsg = "Disabled"
        $ReturnValue += ACreate-TestResult "RDP NLA" $ReturnMsg $false
        }
    
    Return ACreate-Test "RDP Network Level Authentication" $ReturnValue
}


############################################
### Check if AD Recycle bin is activated ###
############################################
function Aget-ADRecycleBin(){

$ReturnValue = @()
$Result = ""

    $enabledScopes = (Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes
    if ($enabledScopes)
        {
        foreach ($line in $enabledScopes){
            if ($Result.Length -eq 0) {
                $Result = $line.split(",")[1]
                }
            else {
                $Result = $Result + " | " + $line.split(",")[1]
                }
            }
        $ReturnValue += ACreate-TestResult "AD Recycle Bin Enabled" $Result $true
        }
    else
        {
        $ReturnMsg = "Disabled"
        $ReturnValue += ACreate-TestResult "AD Recycle Bin Enabled" $Result $false
        }
return ACreate-Test "AD Recycle Bin" $ReturnValue
}

###########################################################################
### Check Signed & secure Channel communication (Default Domain Policy) ###
###########################################################################
function Aget-SignedOrSecure_Channel_Communication($comp){

    #Domain member: Digitally encrypt or sign secure channel data (always)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal:REG_DWORD:0x00000001

    #Domain member: Digitally encrypt secure channel data (when possible)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel:REG_DWORD:0x00000001

    #Domain member: Digitally sign secure channel data (when possible)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel:REG_DWORD:0x00000001

    #Microsoft network client: Digitally sign communications (always)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature:REG_DWORD:0x00000001

    #Microsoft network client: Digitally sign communications (if server agrees)
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature:REG_DWORD:0x00000001

    #Microsoft network server: Digitally sign communications (always)"
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature:REG_DWORD:0x00000001

    #Microsoft network server: Digitally sign communications (if client agrees)"
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature:REG_DWORD:0x00000001

    $hklm = 2147483650
    $key1 = "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
    $key2 = "SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
    $item_RequireSignOrSeal = "RequireSignOrSeal"
    $item_SealSecureChannel = "SealSecureChannel"
    $item_SignSecureChannel = "SignSecureChannel"

    $item_RequireSecuritySignature = "RequireSecuritySignature"
    $item_EnableSecuritySignature = "EnableSecuritySignature"

    $ReturnValue = @()
    $ReturnMsg = ""
  
    $DCs = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().DomainControllers.Name
    $Comp_FQDN = $comp + "." +$domain.name

    # Check Windows Update Configuration
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
    #if ($DCs -contains $Comp_FQDN) {
    #    echo "Deze computer is een DC"
        $RequireSignOrSeal = $wmi.GetDWORDValue($hklm, $Key1, $item_RequireSignOrSeal)
        $RequireSignOrSeal = $RequireSignOrSeal.UValue
        $ReturnMsg = "Domain member: Digitally encrypt or sign secure channel data (always)"
        if ($RequireSignOrSeal) {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        $SealSecureChannel = $wmi.GetDWORDValue($hklm, $Key1, $item_SealSecureChannel)
        $SealSecureChannel = $SealSecureChannel.UValue
        $ReturnMsg = "Domain member: Digitally encrypt secure channel data (when possible)"
        if ($SealSecureChannel) {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        $SignSecureChannel = $wmi.GetDWORDValue($hklm, $Key1, $item_SignSecureChannel)
        $SignSecureChannel = $SignSecureChannel.UValue
        $ReturnMsg = "Domain member: Digitally sign secure channel data (when possible)"
        if ($SignSecureChannel) {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        #}
    #else {
        echo "Deze Computer is ne member server"
        $RequireSecuritySignature = $wmi.GetDWORDValue($hklm, $Key2, $item_RequireSecuritySignature)
        $RequireSecuritySignature = $RequireSecuritySignature.UValue
        $ReturnMsg = "Microsoft network server: Digitally sign communications (always)"
        if ($RequireSecuritySignature) {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        $EnableSecuritySignature = $wmi.GetDWORDValue($hklm, $Key2, $item_EnableSecuritySignature)
        $EnableSecuritySignature = $EnableSecuritySignature.UValue
        $ReturnMsg = "Microsoft network server: Digitally sign communications (if client agrees)"
            if ($EnableSecuritySignature) {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $true
            }
        else
            {
            $ReturnValue += ACreate-TestResult "Encrypt or Sign AD Communication" $ReturnMsg $false
            }

        #}
   
return ACreate-Test "Encrypt or Sign AD Communication" $ReturnValue
}


#######################################
### Check for Enabled SMB1 Protocol ###
#######################################
function Aget-Check_SMBv1($comp){

# 2008R2  Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}
#   FIX:  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 –Force
# 2012    Get-SmbServerConfiguration | Select EnableSMB1Protocol
#   Fix:  Set-SmbServerConfiguration -EnableSMB1Protocol $false -force
# 2012R2  (Get-WindowsFeature FS-SMB1).Installed
#         Get-SmbServerConfiguration | Select EnableSMB1Protocol
#   FIX:  Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
#         Set-SmbServerConfiguration -EnableSMB1Protocol $false
#
# Windows 7/2008/2008R2 via registry key 
# Windows 8/8.1/10/2012/206/2019 via powershell Get-SmbServerConfiguration | Select EnableSMB1Protocol

$OS_Version = Aget-OSVersion $comp

    $hklm = 2147483650
    $key1 = "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
    $item_Name = "SMB1"

    $ReturnValue = @()
    $ReturnMsg = ""

if ( [int]$OS_Version -gt 61 ) {
    # WIndows 2012 or greater
    $SMB_Configuration = Invoke-Command -ComputerName $comp -scriptblock {Get-SmbServerConfiguration} -ErrorAction SilentlyContinue
    $SMBv1 = $SMB_Configuration.EnableSMB1Protocol
    if ($SMBv1) {
        $ReturnValue += ACreate-TestResult "SMBv1 Protocol" "Enabled" $false
        }
    elseif (-Not $SMBv1) {
        $ReturnValue += ACreate-TestResult "SMBv1 Protocol" "Disabled" $true
        }
    }
Else {
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
    $SMB = $wmi.GetDWORDValue($hklm, $Key1, $item_Name)
        $SMBv1 = $SMB.UValue
        $ReturnMsg = "Disabled"
        if ($SMBv1 -eq $null -OR $SMBv1 -eq 1) {
            $ReturnValue += ACreate-TestResult "SMBv1 Protocol" "Enabled" $false
            }
        elseif ($SMBv1 -eq 0) {
            $ReturnValue += ACreate-TestResult "SMBv1 Protocol" "Disabled" $true
            }
        }
   
return ACreate-Test "SMBv1 Protocol" $ReturnValue
}


################################################
### Check for DFSR SYSVOL Replication Health ###
################################################
function Aget-DFSR_SYSVOL_Replication_Health($comp){

<#
$LogName="FRS Replication"
$Source="FRS"
$Eventid=13568
$Message="*The DFS Replication service stopped replication*"
#>

$LogName="DFS Replication"
$Source="DFSR"
$Eventid=2213
$Message="*The DFS Replication service stopped replication*"

$ReturnValue = @()
$ReturnMsg = ""

$StartTime = (Get-date).AddDays(-7)

if ($domain.DomainControllers.name -Contains ($comp+"."+$domain.name).ToUpper()) {
    # If error: Get-WinEvent : The RPC server is unavailable => Select Inbound Rules and in the list, right-click Remote Event Log Management (RPC) and select Enable Rule.
    #$Events = Get-EventLog -ComputerName $comp -LogName $LogName -Source $Source -After (Get-Date).AddDays(-60) | Where-Object {$_.EventID -eq $EventId} | sort TimeGenerated | select -last 1
    $Events = Get-WinEvent -FilterHashtable @{LogName=$LogName;ID=$EventId;StartTime=$StartTime} -MaxEvents 1 -ComputerName $comp -ErrorAction SilentlyContinue

    if ($Events -ne $null) {
        $ReturnMsg = "Eventid:"+$EventId+" Unhealthy"
        $ReturnValue += ACreate-TestResult "DFSR SYSVOL Replication" $ReturnMsg $false
        }
    else {
        $ReturnMsg = "Eventid:"+$EventId+" Healthy"
        $ReturnValue += ACreate-TestResult "DFSR SYSVOL Replication" $ReturnMsg $true
        }
    }
else {
    $ReturnValue += ACreate-TestResult "DFSR SYSVOL Replication" "Not Installed" $true
    }

$LogName="DFS Replication"
$Source="DFSR"
$EventId=4012
$Message="*DFS*"

if ($domain.DomainControllers.name -Contains ($comp+"."+$domain.name).ToUpper()) {
    # If error: Get-WinEvent : The RPC server is unavailable => Select Inbound Rules and in the list, right-click Remote Event Log Management (RPC) and select Enable Rule.
    #$Events = Get-EventLog -ComputerName $comp -LogName $LogName -Source $Source -After (Get-Date).AddDays(-60) | Where-Object {$_.EventID -eq $EventId} | sort TimeGenerated | select -last 1
    $Events = Get-WinEvent -FilterHashtable @{LogName=$LogName;ID=$EventId;StartTime=$StartTime} -MaxEvents 1 -ComputerName $comp -ErrorAction SilentlyContinue

    if ($Events -ne $null) {
        $ReturnMsg = "Eventid:"+$EventId+" Unhealthy"
        $ReturnValue += ACreate-TestResult "DFSR SYSVOL Replication" $ReturnMsg $false
        }
    else {
        $ReturnMsg = "Eventid:"+$EventId+" Healthy"
        $ReturnValue += ACreate-TestResult "DFSR SYSVOL Replication" $ReturnMsg $true
        }
    }
else {
    $ReturnValue += ACreate-TestResult "DFSR SYSVOL Replication" "Not Installed" $true
    }


return ACreate-Test "DFSR SYSVOL Replication Health" $ReturnValue
}


##################################
### Check for UEFI Secureboot ####
##################################
function Aget-Check_UEFISecureboot($comp){
$ReturnValue = @()
$hklm = 2147483650

$SecureBootRegKey = "SYSTEM\CurrentControlSet\Control\SecureBoot\State\"
$SecureBootKey = "UEFISecureBootEnabled"
$SecureBootValue = ""

$wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp

$SecureBootValue = ($wmi.GetDWORDValue($hklm, $SecureBootRegKey, $SecureBootKey)).uvalue
#$SecureBootValue = Invoke-command -ComputerName $comp -ScriptBlock {Confirm-SecureBootUEFI}

if ($SecureBootValue) {
    $ReturnValue += ACreate-TestResult "UEFI Secureboot" "Enabled" $true
    }
else {
    $ReturnValue += ACreate-TestResult "UEFI Secureboot" "Disabled" $false
    }

return ACreate-Test "UEFI Secureboot" $ReturnValue
}


############################
### Check for TPM Ready ####
############################
function Aget-Check_4_TPM($comp){
Invoke-command -ComputerName $comp -ScriptBlock {
        $TPM = Get-TPM
        [PSCustomObject]@{
            ComputerName = $TPM.PSComputerName
            TpmPresent = $TPM.TpmPresent
            TpmReady = $TPM.TpmReady
            TpmEnabled = $TPM.TpmEnabled
            TpmActivated = $TPM.TpmActivated
        }
    }
}


#################################################
### Check for Caché Database Running Version ####
#################################################
function Aget-Check_Cache_DB($comp){
$ReturnValue = @()

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'cservice.exe'" -ErrorAction Continue
if ($processes -eq $null) 
    {
    #echo "Caché Database Not Installed"
    $ReturnValue += ACreate-TestResult "Caché Database" "Not Installed" $true
    return ACreate-Test "Caché Database" $ReturnValue
    }
else {
    $Filename = $Processes.ExecutablePath
    #$FileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Filename).FileVersion
    $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename
    
    $ReturnValue += ACreate-TestResult "Caché Database" "Version: $FileVersion Installed" $true    
    }
return ACreate-Test "Caché Database" $ReturnValue
}


##############################################
#### Check Version Remote Desktop Manager ####
##############################################
function Aget-Check_Remote_Desktop_Connection_Manager($comp){
$ReturnValue = @()
$Latest_Version = ""

# Info van MVK
# (Get-Process rdcman).productversion[0] -replace '^(\d+\.\d+).*','$1'
# [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try {
    $Latest_Version = (Invoke-WebRequest https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman).content -replace '(?ms).*Remote Desktop Connection Manager v(\d+\.\d+).*','$1'
    }
Catch
    {
    $Latest_Version = ""
    Write-Host "Invoke-Webrequest is not available in this OS/Powershell Version - Module 'Check_Remote_Desktop_Connection_Manager'." -ForegroundColor Red | Out-Default
    }

#$Latest_Version = (Invoke-WebRequest https://docs.microsoft.com/en-us/sysinternals/downloads/rdcman).content -replace '(?ms).*Remote Desktop Connection Manager v(\d+\.\d+).*','$1'

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'rdcman.exe'" -ErrorAction Continue
if ($processes -eq $null) 
    {
    $Filename = "\Program Files (x86)\Microsoft\Remote Desktop Connection Manager\RDCMan.exe"    
    if ( Test-Path \\$comp\c$\$Filename ) {
        #echo "Is Installed C:\Program Files\Microsoft"        
        $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) (Get-Item $Param1).VersionInfo} -ArgumentList $Filename -ErrorAction SilentlyContinue
        if (($FileVersion.ProductVersion.Split(".")[0]+"."+$FileVersion.ProductVersion.Split(".")[1]) -lt $Latest_Version) {
            $FileVer= "Version: "+($FileVersion.ProductVersion.Split(".")[0]+"."+$FileVersion.ProductVersion.Split(".")[1])+" installed, "+$Latest_Version+" available"
            $ReturnValue += ACreate-TestResult "RD Connection Manager" $FileVer $false
            }
        else {
            $FileVer= "Version: "+$FileVersion.ProductVersion+" installed"
            $ReturnValue += ACreate-TestResult "RD Connection Manager" $FileVer $true
            }
        }
    else {
        $Filename = "\Program Files\Microsoft\Remote Desktop Connection Manager\RDCMan.exe"
        if ( Test-Path \\$comp\c$\$Filename ) {
            #echo "Is Installed in C:\Program Files (x86)\Microsoft"
            $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) (Get-Item $Param1).VersionInfo} -ArgumentList $Filename -ErrorAction SilentlyContinue
            if (($FileVersion.ProductVersion.Split(".")[0]+"."+$FileVersion.ProductVersion.Split(".")[1]) -lt $Latest_Version) {
                $FileVer= "Version: "+($FileVersion.ProductVersion.Split(".")[0]+"."+$FileVersion.ProductVersion.Split(".")[1])+" installed, "+$Latest_Version+" available"
                $ReturnValue += ACreate-TestResult "RD Connection Manager" $FileVer $false
                }
            else {
                $FileVer= "Version: "+$FileVersion.ProductVersion+" installed"
                $ReturnValue += ACreate-TestResult "RD Connection Manager" $FileVer $true
                }
            }
        else {
            $ReturnValue += ACreate-TestResult "RD Connection Manager" "Not Installed" $true
            }
        }
        
    return ACreate-Test "Remote Desktop Connection Manager" $ReturnValue
    }
   else {
        $Filename = $Processes.ExecutablePath
        $FileVersion = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename
        if (($FileVersion.Split(".")[0]+"."+$FileVersion.Split(".")[1]) -lt $Latest_Version) {
            $FileVer= "Version: "+($FileVersion.Split(".")[0]+"."+$FileVersion.Split(".")[1])+" installed, "+$Latest_Version+" available"
            $ReturnValue += ACreate-TestResult "RD Connection Manager" $FileVer $false
            }
        else {
            $FileVer= "Version: "+($FileVersion.Split(".")[0]+"."+$FileVersion.Split(".")[1])+" installed"
            $ReturnValue += ACreate-TestResult "RD Connection Manager" $FileVer $true
            }

    }        

return ACreate-Test "Remote Desktop Connection Manager" $ReturnValue
}


#########################################################################
### Check Version Eaton IPP                                           ###
### HPE Power Protector nog verder af te werken, is een Eaton variant ###
#########################################################################
function Aget-Check_Eaton_IntelligentPowerProtector($comp){
$ReturnValue = @()

# RegKey: HKLM\SOFTWARE\Wow6432Node\Eaton\IntelligentPowerProtector\InstallPath:REG_SZ:C:\Program Files (x86)\Eaton\IntelligentPowerProtector
# Process mc2.exe
# File: C:\Program Files (x86)\Eaton\IntelligentPowerProtector\mc2.exe
# DBfile: C:\Program Files (x86)\Eaton\IntelligentPowerProtector\db\mc2.db

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'mc2.exe'" -ErrorAction Continue

if ($processes -ne $null) {
    if ($processes.ExecutablePath -eq "C:\Program Files (x86)\HPE\PowerProtector\mc2.exe") {
       $Installed_SW = Invoke-Command -ComputerName $comp -ScriptBlock { (get-itemproperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') } -ErrorAction SilentlyContinue

        foreach ($item in $Installed_SW) {
            if ($item.DisplayName -ilike "*HPE Power Protector*") {
                $Eaton_Version = ($item.DisplayVersion).split(" ")[0]
                }
            }

        $Eaton_Version = $Eaton_Version -replace '(?ms).(\d.\d+.\d+).*','$1'
        $FileVer= "Version: "+$Eaton_Version+" installed"
        $ReturnValue += ACreate-TestResult "Eaton IPP" $FileVer $true
        }
    else {
        $Installed_SW = Invoke-Command -ComputerName $comp -ScriptBlock { (get-itemproperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') } -ErrorAction SilentlyContinue

        foreach ($item in $Installed_SW) {
            if ($item.DisplayName -ilike "*Eaton*") {
                $Eaton_Version = ($item.DisplayVersion).split(" ")[0]
                }
            }
        $Eaton_Version = $Eaton_Version -replace '(?ms).(\d.\d+.\d+).*','$1'
        $FileVer= "Version: "+$Eaton_Version+" installed"
        $ReturnValue += ACreate-TestResult "Eaton IPP" $FileVer $true
        }
    }
else {
    $ReturnValue += ACreate-TestResult "Eaton IPP" "Not Installed" $true    
    }
    
return ACreate-Test "Eaton Intelligent PowerProtector" $ReturnValue
}


######################################
#### Check Version APC PowerChute ####
######################################
function Aget-Check_APC_POWERCHUTE_NETWORK_SHUTDOWN($comp){

<#
# https://www.apc.com/shop/be/en/categories/power/uninterruptible-power-supply-ups-/ups-management/powerchute-network-shutdown/N-auzzn7
Try {
    $Latest_Version = ( (Invoke-WebRequest "https://www.apc.com/shop/be/en/categories/power/uninterruptible-power-supply-ups-/ups-management/powerchute-network-shutdown/N-auzzn7").content -replace '(?ms).*v(/d./d./d)*Windows, Linux, Windows Virtualization Installer for Nutanix/Hyper-V/SCVMM.*','$1')
    }
Catch {
       Write-Host "Invoke-Webrequest is not available in this OS/Powershell Version - Module 'Check_Eaton_IntelligentPowerProtector'." -ForegroundColor Red | Out-Default
    }
#>

$ReturnValue = @()
$hklm = 2147483650

$APC_PC_key1 = "SOFTWARE\APC\PowerChuteNetworkShutdown\"
$APC_PC_PATH_Key = "Version"
$APC_PC_PATH = ""

$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'PCNS.exe'" -ErrorAction Continue
if ($processes -ne $null) {
    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp
    $APC_PC_PATH_Key = $wmi.GetStringValue($hklm, $APC_PC_key1, $APC_PC_PATH_Key)
    $APC_PC_PATH_Key = $APC_PC_PATH_Key.sValue
    $ReturnValue += ACreate-TestResult "APC PCNS" "Version: $APC_PC_PATH_Key Installed" $true
    }
else {
    $ReturnValue += ACreate-TestResult "APC PCNS" "Not Installed" $true    
    }
    
return ACreate-Test "APC PowerChute Network Shutdown" $ReturnValue
}


######################################################
#### Check for Optimized SMB Filesharing settings ####
######################################################
function Aget-Check_SMB_OPTIMIZED_SETTINGS($comp){
#
# get-smbserverconfiguration & set-smbserverconfiguration
#
$ReturnValue = @()
$SMB_SETTINGS = ""
$SMB_SETTINGS2 = ""
$Status = $true
$Status2 = $true

$OS_Version = Aget-OSVersion $comp

if ( [int]$OS_Version -gt 63 -AND [INT](Get-WmiObject win32_operatingsystem -computername $comp).version.split(".")[2] -gt 17762) {
    # Windows 2019 or greater
    Echo Windows 2019/2022
    $AsynchronousCredits = 512
    $AutoDisconnectTimeout = 15
    $CachedOpenLimit = 10
    $DurableHandleV2TimeoutInSeconds = 180
    $MaxThreadsPerQueue = 20
    $Smb2CreditsMax = 8192
    $Smb2CreditsMin = 512
    }
else {
    # Windows 2003/2003R2/2008/2008R2/2016
    Echo Windows 7/8/2008/2008R2/2012/2012R2/2016
    $AsynchronousCredits = 64
    $AutoDisconnectTimeout = 0
    $CachedOpenLimit = 5
    $DurableHandleV2TimeoutInSeconds = 30
    $MaxThreadsPerQueue = 20
    $Smb2CreditsMax = 2048
    $Smb2CreditsMin = 128
    }

$SMB_FILESERVER = Invoke-Command -ComputerName $comp -ScriptBlock {get-smbserverconfiguration}

if ($SMB_FILESERVER) {
    if ($SMB_FILESERVER.AsynchronousCredits -eq $AsynchronousCredits)  {
        $SMB_SETTINGS = "AsynchronousCredits: "+$SMB_FILESERVER.AsynchronousCredits+"(ok), "
        }
    else {
        $SMB_SETTINGS = "AsynchronousCredits: "+$SMB_FILESERVER.AsynchronousCredits+"("+$AsynchronousCredits+"), "
        $Status = $false
        }
    if ($SMB_FILESERVER.MaxThreadsPerQueue -eq $MaxThreadsPerQueue)  {
        $SMB_SETTINGS = $SMB_SETTINGS + "MaxThreadsPerQueue: "+$SMB_FILESERVER.MaxThreadsPerQueue+"(ok), "
        }
    else {
        $SMB_SETTINGS = $SMB_SETTINGS + "MaxThreadsPerQueue: "+$SMB_FILESERVER.MaxThreadsPerQueue+"("+$MaxThreadsPerQueue+"), "
        $Status = $false
        }
    if ($SMB_FILESERVER.Smb2CreditsMax -eq $Smb2CreditsMax)  {
        $SMB_SETTINGS = $SMB_SETTINGS + "Smb2CreditsMax: "+$SMB_FILESERVER.Smb2CreditsMax+"(ok), "
        }
    else {
        $SMB_SETTINGS = $SMB_SETTINGS + "Smb2CreditsMax: "+$SMB_FILESERVER.Smb2CreditsMax+"("+$Smb2CreditsMax+"), "
        $Status = $false
        }
    if ($SMB_FILESERVER.Smb2CreditsMin -eq $Smb2CreditsMin)  {
        $SMB_SETTINGS = $SMB_SETTINGS + "Smb2CreditsMin: "+$SMB_FILESERVER.Smb2CreditsMin+"(ok), "
        }
    else {
        $SMB_SETTINGS = $SMB_SETTINGS + "Smb2CreditsMin: "+$SMB_FILESERVER.Smb2CreditsMin+"("+$Smb2CreditsMin+"), "
        $Status = $false
        }
    if ($SMB_FILESERVER.DurableHandleV2TimeoutInSeconds -eq $DurableHandleV2TimeoutInSeconds)  {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + " -> DurableHandleV2TimeoutInSeconds: "+$SMB_FILESERVER.DurableHandleV2TimeoutInSeconds+"(ok), "
        }
    else {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + " -> DurableHandleV2TimeoutInSeconds: "+$SMB_FILESERVER.DurableHandleV2TimeoutInSeconds+"("+$DurableHandleV2TimeoutInSeconds+"), "
        $Status2 = $false
        }
    if ($SMB_FILESERVER.AutoDisconnectTimeout -eq $AutoDisconnectTimeout)  {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + "AutoDisconnectTimeout: "+$SMB_FILESERVER.AutoDisconnectTimeout+"(ok), "
        }
    else {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + "AutoDisconnectTimeout: "+$SMB_FILESERVER.AutoDisconnectTimeout+"("+$AutoDisconnectTimeout+"), "
        $Status2 = $false
        }    
    if ($SMB_FILESERVER.CachedOpenLimit -eq $CachedOpenLimit)  {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + "CachedOpenLimit: "+$SMB_FILESERVER.CachedOpenLimit+"(ok)"
        }
    else {
        $SMB_SETTINGS2 = $SMB_SETTINGS2 + "CachedOpenLimit: "+$SMB_FILESERVER.CachedOpenLimit+"("+$CachedOpenLimit+")"
        $Status2 = $false
        }

    if ($Status) {
        $ReturnValue += ACreate-TestResult "SMB Fileserver Settings" $SMB_SETTINGS $true
        }
    else {
        $ReturnValue += ACreate-TestResult "SMB Fileserver Settings" $SMB_SETTINGS $false
        }
    if ($Status2) {
        $ReturnValue += ACreate-TestResult "SMB Fileserver Settings" $SMB_SETTINGS2 $true
        }
    else {
        $ReturnValue += ACreate-TestResult "SMB Fileserver Settings" $SMB_SETTINGS2 $false
        }
    }
else {
    $ReturnValue += ACreate-TestResult "SMB Fileserver Settings" "No SMB Fileserver" $false
    }

return ACreate-Test "SMB Fileserver Settings" $ReturnValue
}


######################################
#### Check for Enabled NIC Queing ####
######################################
function Aget-Check_NIC_VM_QUEUING($comp){
$ReturnValue = @()

$VMQueuing = Invoke-Command -ComputerName $comp -ScriptBlock {Get-NetAdapterVmq -Name "*" | Where-Object -FilterScript { $_.Enabled }}

if ($VMQueuing) {
    $ReturnValue += ACreate-TestResult "VM Queuing (1gb NIC?)" "Enabled" $false  
    }
else {
    $ReturnValue += ACreate-TestResult "VM Queuing (1gb NIC?)" "Disabled" $true
    }

return ACreate-Test "VM Queuing" $ReturnValue
}


############################################################
#### Check for Enabled NIC Receive Side Scaling setting ####
############################################################
function Aget-Check_RSS_NIC_SETTING($comp){
#
# Enable-NetAdapterRss –Name *
#
# This setting is found on the Advanced tab of the device’s Device Manager property sheet or in the Adapter Settings panel in Intel PROSet ACU.
# To change this setting in Windows PowerShell, use the Set-IntelNetAdapterSetting cmdlet.
# Set-IntelNetAdapterSetting -Name "<adapter_name>" -DisplayName "Receive Side Scaling" -DisplayValue "Enabled"
# 
$ReturnValue = @()
$RSS_ENABLED = $false

$RSS_STATE = Invoke-Command -ComputerName $comp -ScriptBlock {netsh interface tcp show global}

foreach ($item in $RSS_STATE) {
    if ($item -match 'Receive-Side Scaling.*') {
       #echo $item.Contains(": enabled")
       $RSS_ENABLED = $true
       }
    }

if ($RSS_ENABLED) {
    $ReturnValue += ACreate-TestResult "Receive-Side Scaling" "Enabled" $true
        }
else {
    $ReturnValue += ACreate-TestResult "Receive-Side Scaling" "Disabled" $false
    }

return ACreate-Test "Receive-Side Scaling" $ReturnValue
}


#####################################################
#### Check for Enabled NIC IPsec Offload setting ####
#####################################################
function Aget-Check_IPsecoffload($comp){
#
# Enable IPsec TOv2 with PowerShell cmdlet: Enable-NetAdapterIPsecOffload, or in the network adapter Advanced Properties.
#
$ReturnValue = @()
$IPsecoffload = ""

$IPsecoffload = Invoke-Command -ComputerName $comp -ScriptBlock {(Get-NetAdapterIPsecOffload).Enabled}

if ($IPsecoffload) {
    $ReturnValue += ACreate-TestResult "IPsecoffload (if supported)" "Enabled" $true
        }
else {
    $ReturnValue += ACreate-TestResult "IPsecoffload (if supported)" "Disabled" $false
    }

return ACreate-Test "IPsecoffload" $ReturnValue
}


#######################################################
#### Check for High Performance Windows Power Plan ####
#######################################################
function Aget-Check_Power_Plan($comp){
#
# COntrol Panel -> Power Options -> High Performance
#
$ReturnValue = @()
$High_Perf_Plan_Active=$false

$Power_Plans = get-wmiobject -class "win32_PowerPlan" -namespace "root\cimv2\power" -computername $comp -ErrorAction Continue

foreach ($Power_Plan in $Power_Plans) {
    if ($Power_Plan.IsActive) {
        #Write-host $comp" Power Plan:"($Power_Plan.ElementName)
        if ($Power_Plan.ElementName -eq "High Performance") {
            $High_Perf_Plan_Active = $true
            }
        }
    }

    if ($High_Perf_Plan_Active) {
        $ReturnValue += ACreate-TestResult "High Performance Power Plan" "Enabled" $High_Perf_Plan_Active
        }
    else {
        $ReturnValue += ACreate-TestResult "High Performance Power Plan" "Disabled" $High_Perf_Plan_Active
        }


return ACreate-Test "High Performance Power Plan" $ReturnValue
}


##################################################
### Check for TLS 1.2 default WinHTTP protocol ###
##################################################
function Aget-Check_TLS_1.2_Protocol($comp){
# https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client
# https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-tls-enforcement#powershell-script-to-check-tls-12
# TLS 1.2 was first introduced into .Net Framework 4.5.1 and 4.5.2 with the following hotfix rollups:


$ReturnValue = @()
$hklm = 2147483650

$WinHttp_RegKey64 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\"
$WinHttp_RegKey32 = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\"
$DefaultSecureProtocols_Key = "DefaultSecureProtocols"

#$TLS_1_0_Client_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\"
#$TLS_1_1_Client_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\"
$TLS_1_2_Client_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\"
#$TLS_1_2_Client_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client\"
#$TLS_1_0_Server_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\"
#$TLS_1_1_Server_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\"
$TLS_1_2_Server_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\"
#$TLS_1_2_Server_RegKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server\"

$dotNetv4_32bit_Framework_Key = "SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
$dotNetv4_64bit_Framework_Key = "SOFTWARE\Microsoft\.NETFramework\v4.0.30319"

$SystemDefaultTlsVersions_Key = "SystemDefaultTlsVersions"
$SchUseStrongCrypto_Key = "SchUseStrongCrypto"

$TLS_DisabledByDefault_Key = "DisabledByDefault"
$TLS_Enabled_Key = "Enabled"

$WinHttp_TLS_Value64 = ""
$WinHttp_TLS_Value32 = ""
$TLS_1_0_DisabledByDefault_Value = ""
$TLS_1_0_Enabled_Value = ""
$TLS_1_1_DisabledByDefault_Value = ""
$TLS_1_1_Enabled_Value = ""
$TLS_1_2_DisabledByDefault_Value = ""
$TLS_1_2_Enabled_Value = ""

$wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp

$WinHttp_TLS_Value64 = ($wmi.GetDWORDValue($hklm, $WinHttp_RegKey64, $DefaultSecureProtocols_Key)).uvalue
$WinHttp_TLS_Value32 = ($wmi.GetDWORDValue($hklm, $WinHttp_RegKey32, $DefaultSecureProtocols_Key)).uvalue

$dNETv4_32bit_Default_TLS_Version = ($wmi.GetDWORDValue($hklm, $dotNetv4_32bit_Framework_Key, $SystemDefaultTlsVersions_Key)).uvalue
$dNETv4_32bit_StrongCrypto = ($wmi.GetDWORDValue($hklm, $dotNetv4_32bit_Framework_Key, $SchUseStrongCrypto_Key)).uvalue

$dNETv4_64bit_Default_TLS_Version = ($wmi.GetDWORDValue($hklm, $dotNetv4_64bit_Framework_Key, $SystemDefaultTlsVersions_Key)).uvalue
$dNETv4_64bit_StrongCrypto = ($wmi.GetDWORDValue($hklm, $dotNetv4_64bit_Framework_Key, $SchUseStrongCrypto_Key)).uvalue

$TLS_1_2_Client_Enabled_Value = ($wmi.GetDWORDValue($hklm, $TLS_1_2_Client_RegKey, $TLS_Enabled_Key)).uvalue
$TLS_1_2_Client_DisabledByDefault_Value = ($wmi.GetDWORDValue($hklm, $TLS_1_2_Client_RegKey, $TLS_DisabledByDefault_Key)).uvalue

$TLS_1_2_Server_Enabled_Value = ($wmi.GetDWORDValue($hklm, $TLS_1_2_Server_RegKey, $TLS_Enabled_Key)).uvalue
$TLS_1_2_Server_DisabledByDefault_Value = ($wmi.GetDWORDValue($hklm, $TLS_1_2_Server_RegKey, $TLS_DisabledByDefault_Key)).uvalue

<#
$dNETv4_32bit_Default_TLS_Version
$dNETv4_32bit_StrongCrypto
$dNETv4_64bit_Default_TLS_Version
$dNETv4_64bit_StrongCrypto
$TLS_1_2_Server_Enabled_Value
$TLS_1_2_Server_DisabledByDefault_Value
$TLS_1_2_Client_Enabled_Value
$TLS_1_2_Client_DisabledByDefault_Value
#>

if ( ($dNETv4_32bit_Default_TLS_Version -eq 1) -AND ($dNETv4_32bit_StrongCrypto -eq 1) -AND ($dNETv4_64bit_Default_TLS_Version -eq 1) -AND ($dNETv4_64bit_StrongCrypto -eq 1) -AND ($TLS_1_2_Server_Enabled_Value -eq 1) -AND ($TLS_1_2_Server_DisabledByDefault_Value -eq 0) -AND ($TLS_1_2_Client_Enabled_Value -eq 1) -AND ($TLS_1_2_Client_DisabledByDefault_Value -eq 0) ) {
    $TLS_Value = "$dNETv4_32bit_Default_TLS_Version "+"$dNETv4_32bit_StrongCrypto "+"$dNETv4_64bit_Default_TLS_Version "+"$dNETv4_64bit_StrongCrypto "+"$TLS_1_2_Server_Enabled_Value "+"$TLS_1_2_Server_DisabledByDefault_Value "+"$TLS_1_2_Client_Enabled_Value "+"$TLS_1_2_Client_DisabledByDefault_Value"
    $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
    }
else {

    if ( $dNETv4_32bit_Default_TLS_Version -ne $null ) {
        $TLS_Value = "32bit SystemDefaultTlsVersions = "+$dNETv4_32bit_Default_TLS_Version
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "32bit SystemDefaultTlsVersions"+" not found"
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $Value $false
        }


    if ( $dNETv4_32bit_StrongCrypto -ne $null ) {
        $TLS_Value = "32bit SchUseStrongCrypto = "+$dNETv4_32bit_StrongCrypto
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "32bit SchUseStrongCrypto"+" not found"
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $Value $false
        }


    if ( $dNETv4_64bit_Default_TLS_Version -ne $null ) {
        $TLS_Value = "64bit SystemDefaultTlsVersions = "+$dNETv4_64bit_Default_TLS_Version
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "64bit SystemDefaultTlsVersions"+" not found"
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $Value $false
        }

    if ( $dNETv4_64bit_StrongCrypto -ne $null ) {
        $TLS_Value = "64bit SchUseStrongCrypto = "+$dNETv4_64bit_StrongCrypto
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "64bit SchUseStrongCrypto"+" not found"
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $Value $false
        }



    if ( $TLS_1_2_Server_Enabled_Value -ne $null ) {
        $TLS_Value = "TLS 1.2 Server Enabled = "+$TLS_1_2_Server_Enabled_Value
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "TLS 1.2 Server Enabled"+" not found"
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $Value $false
        }

    if ( $TLS_1_2_Server_DisabledByDefault_Value -ne $null ) {
        $TLS_Value = "TLS 1.2 Server DisabledByDefault = "+$TLS_1_2_Server_DisabledByDefault_Value
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "TLS 1.2 Server DisabledByDefault"+" not found"
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $Value $false
        }

    if ( $TLS_1_2_Client_Enabled_Value -ne $null ) {
        $TLS_Value = "TLS 1.2 Client Enabled = "+$TLS_1_2_Client_Enabled_Value
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "TLS 1.2 Client Enabled"+" not found"
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $Value $false
        }

    if ( $TLS_1_2_Client_DisabledByDefault_Value -ne $null ) {
        $TLS_Value = "TLS 1.2 Client DisabledByDefault = "+$TLS_1_2_Client_DisabledByDefault_Value
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $TLS_Value $true
        }
    else {
        $Value = "TLS 1.2 Client DisabledByDefault"+" not found"
        $ReturnValue += ACreate-TestResult "WinHTTP and TLS 1.2 support" $Value $false
        }
    }
return ACreate-Test "WinHTTP and TLS 1.2 support" $ReturnValue
}


function Aget-Check_FSLogix($comp){
#
# Check FSlogix version
# https://learn.microsoft.com/en-us/fslogix/how-to-install-fslogix#download-fslogix
#
$ReturnValue = @()
$hklm = 2147483650

$FSLogixAppsVersion_key = "SOFTWARE\FSLogix\Apps\"
$FSLogixAppsEnabled_key = "SOFTWARE\FSLogix\Profiles\"
$FSLogixAppsVersion_item = "InstallVersion"
$FSLogixAppsEnabled_item = "Enabled"
$FSLogixAppsVersion_Value = ""
$FSLogixAppsEnabled_Value = ""


$process = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'frxsvc.exe'" -ErrorAction Continue
if ($process -ne $null) {
    Try {
        $FSLogix_Apps_Latest_Version = ( (Invoke-WebRequest "https://community.chocolatey.org/packages/fslogix").content )
        $VersionIndex = $FSLogix_Apps_Latest_Version.indexof("FSLogix Apps Agent ")
        #$FSLogixLatestVersion = $FSLogix_Apps_Latest_Version.substring($VersionIndex,100)
        $FSLogix_Apps_Latest_Version = ($FSLogix_Apps_Latest_Version.substring($VersionIndex,100)).split(" ")[3].split("<")[0]
        }
    Catch {
        $FSLogix_Apps_Latest_Version = ""
        Write-Host "Invoke-Webrequest is not available in this OS/Powershell Version - Module 'Check_FSLogix'." -ForegroundColor Red | Out-Default
        }

    $Filename = $process.ExecutablePath
    $FSLogixAppsVersion_Value = Invoke-Command -ComputerName $comp -scriptblock {PARAM($Param1) [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Param1).FileVersion} -ArgumentList $Filename

    $wmi = get-wmiobject -list "StdRegProv" -namespace root\default -computername $comp

    $FSLogixAppsEnabled_Value = $wmi.GetDWORDValue($hklm, $FSLogixAppsEnabled_key, $FSLogixAppsEnabled_item)
    $FSLogixAppsEnabled_Value = $FSLogixAppsEnabled_Value.uValue

    IF ($FSLogix_Apps_Latest_Version.trim() -gt $FSLogixAppsVersion_Value.trim()) {
        IF ($FSLogixAppsEnabled_Value -eq "1") {
            $FSLogix_Result = "Enabled, version: $FSLogixAppsVersion_Value installed, $FSLogix_Apps_Latest_Version available"
            $ReturnValue += ACreate-TestResult "FSLogix Apps" $FSLogix_Result $false
            }
        ELSE {
            $FSLogix_Result = "Disabled, version: $FSLogixAppsVersion_Value installed, $FSLogix_Apps_Latest_Version available"
            $ReturnValue += ACreate-TestResult "FSLogix Apps" $FSLogix_Result $false
            }
        }
    ELSE {
       IF ($FSLogixAppsEnabled_Value -eq "1") {
            $FSLogix_Result = "Enabled, version: $FSLogixAppsVersion_Value installed"
            $ReturnValue += ACreate-TestResult "FSLogix Apps" $FSLogix_Result $true
            }
        ELSE {
            $FSLogix_Result = "Disabled, version: $FSLogixAppsVersion_Value installed"
            $ReturnValue += ACreate-TestResult "FSLogix Apps" $FSLogix_Result $false
            }
         }

    }
else {
    $ReturnValue += ACreate-TestResult "FSLogix Apps" "Not Installed" $true    
    }
    
return ACreate-Test "FSLogix Apps" $ReturnValue
}


function Aget-All_DNS_Servers_IPv6_Address {
#
# Get Configured IPv6 DNS servers
#
    $ReturnValue = @()
    $DNS_Servers = @()
    $DNS_Server_Name = ""
    $DNS_Server_Names = @()

    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0 
    $ips = @()
    $nstemp = $ns
    
    do  {        
        $pos = $nstemp.IndexOf(":")
        if ($pos -gt -1) {
            $nstemp = $nstemp.Substring($pos+1)
            }
        } while ($pos -gt -1)
    $nstemp = $nstemp.Trim()

    do  {
       if ($nstemp.split(" ")[$i].trim() -ne "") {
            $ips += $nstemp.split(" ")[$i].trim()
            }
       $i = $i +1
        } while ($i -ne ($nstemp.split(" ").count))

    foreach ($ip in $ipaddr) { 
        if ($ip.InterfaceAlias -notlike "Loopbac*") {
            $ip.ipaddress
            }
        }

    $DC_names = ($domain.DomainControllers.name).toupper() | sort
    foreach ($DNS_Server in $IPS) {
        $DNS_Server_Name = nslookup $DNS_Server
        foreach ($line in $DNS_Server_Name) {
            if ($Line -like "Name:*") {
                $DNS_Server_Names += (($Line.split(":")[1].trim()).split(".")[0]).toupper()
                }
            }
        }

            $NIC_DNS_Servers = @()
            $NIC_IPv4_Address = @()
            $NIC_Link_local_IPv6_Address = @()
            $DNS_IPv6 = @()
                    
        foreach ($DNS_Server_Name in $DNS_Server_Names ) {
            $Continue_DNS = $false
            $Continue_LLIPv6 = $false
            $Continue_IPv4 = $false

            #$ipv6_DNS = Invoke-Command -Computer $comp -ScriptBlock { netsh int ipv6 show dnsservers }
            $ipconfigall = Invoke-Command -Computer $DNS_Server_Name -ScriptBlock {ipconfig /all}
       
            #Link-local IPv6 Address . . . . . : fe80::5c99:e044:e7c9:9242%12(Preferred)
            #IPv4 Address. . . . . . . . . . . : 192.168.254.27(Preferred)
            #DNS Servers . . . . . . . . . . . : fe80::7cb1:8180:bce2:fbda%8
       
            foreach ($line in $ipconfigall) {
                if ($line.Trim() -like 'Connection-specific DNS Suffix*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'Description*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'Physical Address*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'DHCP Enabled*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'Autoconfiguration Enabled*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'Link-local IPv6 Address*') {
                    $Continue_DNS = $false ; $Continue_IPv4 = $false
                    If ($line.Trim() -like 'Link-local IPv6 Address*' -OR $Continue_LLIPv6) {
                        $NIC_Link_local_IPv6_Address += (($line.substring(39)).Trim()).split("(")[0]
                        }
                    ELSE {
                        $NIC_Link_local_IPv6_Address += ($line.Trim()).split("(")[0]
                        }
                    $Continue_LLIPv6 = $true                
                    }
                if ($line.Trim() -like 'IPv4 Address*') {
                    $Continue_DNS = $false ; $Continue_LLIPv6 = $false
                    If ($line.Trim() -like 'IPv4 Address*' -OR $Continue_IPv4) {
                        $NIC_IPv4_Address += (($line.substring(39)).Trim()).split("(")[0]
                        }
                    ELSE {
                        $NIC_IPv4_Address += ($line.Trim()).split("(")[0]
                        }
                    $Continue_IPv4 = $true                
                    }
                if ($line.Trim() -like 'Subnet Mask*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'Default Gateway*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'DHCPv6 IAID*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'DHCPv6 Client DUID*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ($line.Trim() -like 'NetBIOS over Tcpip*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
                if ( ($line.Trim() -like 'DNS Servers*') -OR $Continue_DNS) {
                    $Continue_LLIPv6 = $false ; $Continue_IPv4 = $false
                    If ($line.Trim() -like 'DNS Servers*') {
                        $NIC_DNS_Servers += ($line.substring(39)).Trim()
                        }
                    ELSE {
                        $NIC_DNS_Servers += $line.Trim()
                        }
                    $Continue_DNS = $true                
                    }
                }        
        }
    
return $NIC_Link_local_IPv6_Address
}


function Aget-IPv6_NIC_Settings($comp,$DNS_Servers_IPv6_Address) {
#
# Get IPv6 NIC DNS settings
#
    $ReturnValue = @()
    $DNS_Servers = @()
    $DNS_Server_Name = ""
    $DNS_Server_Names = @()

    $ns = nslookup $domain
    $ns = "" + $ns
    $i= 0 
    $ips = @()
    $nstemp = $ns
    
    do  {        
        $pos = $nstemp.IndexOf(":")
        if ($pos -gt -1) {
            $nstemp = $nstemp.Substring($pos+1)
            }
        } while ($pos -gt -1)
    $nstemp = $nstemp.Trim()

    do  {
       if ($nstemp.split(" ")[$i].trim() -ne "") {
            $ips += $nstemp.split(" ")[$i].trim()
            }
       $i = $i +1
        } while ($i -ne ($nstemp.split(" ").count))

    foreach ($ip in $ipaddr) { 
        if ($ip.InterfaceAlias -notlike "Loopbac*") {
            $ip.ipaddress
            }
        }

    $DC_names = ($domain.DomainControllers.name).toupper() | sort
    if ($DC_Names -Contains ($comp).toupper()+"."+($domain.name).toupper() ) {
        $Continue_DNS = $false
        $Continue_LLIPv6 = $false
        $Continue_IPv4 = $false
        $NIC_DNS_Servers = @()
        $NIC_IPv4_Address = @()
        $NIC_Link_local_IPv6_Address = @()
        $DNS_IPv6 = @()

        #$ipv6_DNS = Invoke-Command -Computer $comp -ScriptBlock { netsh int ipv6 show dnsservers }
        $ipconfigall = Invoke-Command -Computer $comp -ScriptBlock {ipconfig /all}
       
        #Link-local IPv6 Address . . . . . : fe80::5c99:e044:e7c9:9242%12(Preferred)
        #IPv4 Address. . . . . . . . . . . : 192.168.254.27(Preferred)
        #DNS Servers . . . . . . . . . . . : fe80::7cb1:8180:bce2:fbda%8
       
        foreach ($line in $ipconfigall) {
            if ($line.Trim() -like 'Connection-specific DNS Suffix*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Description*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Physical Address*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'DHCP Enabled*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Autoconfiguration Enabled*') { $Continue_DNS = $false ; $Continue_IPv4 = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Link-local IPv6 Address*') {
                $Continue_DNS = $false ; $Continue_IPv4 = $false
                If ($line.Trim() -like 'Link-local IPv6 Address*' -OR $Continue_LLIPv6) { $NIC_Link_local_IPv6_Address += (($line.substring(39)).Trim()).split("(")[0] }
                ELSE { $NIC_Link_local_IPv6_Address += ($line.Trim()).split("(")[0] }
                $Continue_LLIPv6 = $true                
                }
            if ($line.Trim() -like 'IPv4 Address*') {
                $Continue_DNS = $false ; $Continue_LLIPv6 = $false
                If ($line.Trim() -like 'IPv4 Address*' -OR $Continue_IPv4) { $NIC_IPv4_Address += (($line.substring(39)).Trim()).split("(")[0] }
                ELSE { $NIC_IPv4_Address += ($line.Trim()).split("(")[0] }
                $Continue_IPv4 = $true                
                }
            if ($line.Trim() -like 'Subnet Mask*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'Default Gateway*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'DHCPv6 IAID*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'DHCPv6 Client DUID*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ($line.Trim() -like 'NetBIOS over Tcpip*') { $Continue_DNS = $false ; $Continue_LLIPv6 = $false }
            if ( ($line.Trim() -like 'DNS Servers*') -OR $Continue_DNS) {
                $Continue_LLIPv6 = $false ; $Continue_IPv4 = $false
                If ($line.Trim() -like 'DNS Servers*') { $NIC_DNS_Servers += ($line.substring(39)).Trim() }
                ELSE { $NIC_DNS_Servers += $line.Trim() }
                $Continue_DNS = $true                
                }
            }
        
        foreach ($item in $NIC_DNS_Servers) {
                IF ( ($item -ne "127.0.0.1") -AND ($item -ne "::1") -AND ($IPS -NotContains $item) ) { $DNS_IPv6 += $item }
                }

        if ( ($NIC_Link_local_IPv6_Address.length -gt 0) -AND ($DNS_IPv6.length -gt 0) ) {
            foreach ($item in $NIC_Link_local_IPv6_Address) {
                if ($DNS_IPv6 -Contains $item) {
                    $ReturnMsg = "Link-local IPv6 Address '" + $item+ "' is in the IPv6 NIC DNS Settings: '"+$DNS_IPv6+"'"
                    $ReturnValue += ACreate-TestResult "IPv6 NIC DNS Settings" $ReturnMsg $true
                    }
                else {
                    $ReturnMsg = "Link-local IPv6 Address '" + $item+ "' is NOT in the IPv6 NIC DNS Settings: '"+$DNS_IPv6+"'"
                    $ReturnValue += ACreate-TestResult "IPv6 NIC DNS Settings" $ReturnMsg $false
                    }
                }
            }
        elseif ($NIC_Link_local_IPv6_Address.length -eq 0) {
            $ReturnMsg = "IPv6 disabled"
            $ReturnValue += ACreate-TestResult "IPv6 NIC DNS Settings" $ReturnMsg $true
            }
        else {
            $ReturnMsg = "No IPv6 address set on NIC"
            $ReturnValue += ACreate-TestResult "IPv6 NIC DNS Settings" $ReturnMsg $false
            }

        }
return ACreate-Test "IPv6 NIC DNS Settings on DC's" $ReturnValue
}


function Aget-RDS_SG_Members($comp) {
#
# Get the 'Remote Desktop Users' Security Group members
#
    $ReturnValue = @()
    $ReturnMsg = ""

    $RDS_SG_MEMBERS_SCRIPT= {
        $count = 0
        $Member_Server_RDS_Users = net localgroup "Remote Desktop Users"
        foreach ($item in $Member_Server_RDS_Users) {    
            if ($item -notlike "Alias*") {
                if ($item -notlike "Comment*") {
                    if ($item -notlike "") {
                        if ($item -notlike "Members*") {
                            if ($item -notlike "") {
                                if ($item -notlike "-------*") {
                                    if ($item -notlike "The command*") {
                                        #echo $item
                                        $count++
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        return $count
        }

    $count = Invoke-Command -ComputerName $comp -ScriptBlock $RDS_SG_MEMBERS_SCRIPT
    $RDS_SRV = Invoke-command -ComputerName $comp {Get-WmiObject -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" | select -ExpandProperty TerminalServerMode}

    if ($RDS_SRV -eq 0) {
        if ( $count -ge 1 ) {
            $ReturnMsg = "$count"
            $ReturnStatus = $false
            }
        else {
             $ReturnMsg = "$count"
            $ReturnStatus = $true
            }
        }
    elseif ($RDS_SRV -eq 1) {
        if ( $count -ge 0 ) {
            $ReturnMsg = "$count (RDS Server)"
            $ReturnStatus = $true
            }
        }

    $ReturnValue += ACreate-TestResult "'Remote Desktop Users' Security Group members (needs manual review)" $ReturnMsg $ReturnStatus

return ACreate-Test "'Remote Desktop Users' Security Group members" $ReturnValue
}


function Aget-Computer_SID($comp) {
#
# Get SID of a DOmain Joined Computer
#
    $ReturnValue = @()

    $ReturnSID = get-adcomputer $comp -prop sid
    $ReturnMsg = $ReturnSID.SID

    #if ($vergelijker -contains $newsid) {Out-Default "gevonden"} else {$vergelijker += $newsid}

    $ReturnValue += ACreate-TestResult "Computer SID" $ReturnMsg $true

return ACreate-Test "Computer Unique SID" $ReturnValue
}


function Aget-Computer_SID2($comp) {

    #if ($vergelijker -contains $newsid) {Out-Default "gevonden"} else {$vergelijker += $newsid}

    $ReturnSID = (get-adcomputer $comp -prop sid).SID.value
       
return $ReturnSID
}


function Aget-NTFS_Volume_Health($comp){
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
                $ReturnValue += ACreate-TestResult "NTFS Volume Health" $ReturnMsg $false
                }
            }
        }

return ACreate-Test "NTFS Volume Health" $ReturnValue
}


function Aget-NPSextension_For_MFA($comp){
#
#$comp="hci-fs-01"
#
$NPSextensionPresent = $false
 
$processes = get-wmiobject -class "Win32_Process" -namespace "root\cimV2" -computername $comp -filter "Name like 'svchost.exe'" -ErrorAction Continue
foreach ($process in $processes) {
    if ( $process.commandline -like "*C:\WINDOWS\System32\svchost.exe -k netsvcs -p -s IAS" ) {        

        # Get MFA NPSextension installed version
        $NPSextensionInstalledVersion = Invoke-command -ComputerName $comp {Get-WmiObject Win32_Product -Filter "Name like 'NPS Extension For Azure MFA'" | Select-Object -ExpandProperty Version}

        if ($NPSextensionInstalledVersion) {
            $NPSextensionPresent = $true

            # Get the latest version of MFA NPS Extension

            $web = New-Object Net.WebClient
            $NPSextensionLatestVersionRawText = (Invoke-WebRequest "https://www.microsoft.com/en-us/download/details.aspx?id=54688").content

            # Compare if the current version match the latest version

            $VersionIndex = $NPSextensionLatestVersionRawText.indexof("NpsExtnForAzureMfaInstaller.exe")
            $NPSextensionLatestVersion = $NPSextensionLatestVersionRawText.substring($VersionIndex,500)
            $VersionIndex = $NPSextensionLatestVersion.indexof("version")
            $NPSextensionLatestVersion = [regex]::Match( ($NPSextensionLatestVersion.Substring($VersionIndex,100)).split(":")[1].split(",")[0] , '[^"]+(?=")').Value
            $NPSextensionLatestVer = $NPSextensionLatestVersion.Replace(".","")
            $NPSextensionInstalledVer = $NPSextensionInstalledVersion.replace(".","")
 
            if ( $NPSextensionLatestVer -gt $NPSextensionInstalledVer ) {
                #echo "NPSextension for Azure MFA version $NPSextensionInstalledVersion is installed, nieuwe versie $NPSextensionLatestVersion beschikbaar"
                $ReturnMsg = "version: $NPSextensionInstalledVersion installed version: $NPSextensionLatestVersion available"
                $ReturnValue += ACreate-TestResult "NPSextension for Azure MFA" $ReturnMsg $false
                }
            else {
                $ReturnMsg = "version: $NPSextensionInstalledVersion installed"
                $ReturnValue += ACreate-TestResult "NPSextension for Azure MFA" $ReturnMsg $true
                }
            }            
        }
    }
    if ( -NOT $NPSextensionPresent ) {
        $ReturnValue += ACreate-TestResult "NPSextension for Azure MFA" "Not Installed" $true
        }

return ACreate-Test "NPSextension for Azure MFA" $ReturnValue
}


####################################
######### Output Resultaat #########
####################################
function aPrint-toScreenByTestOf($testToDisplay, $server){
	$resultaat = @()
	
        $server.tests | foreach{
            if($_.TestName -eq $testToDisplay){
                $_.testResult | foreach{
                    $lijn = New-Object psObject 
	                $lijn | Add-Member -Type noteProperty -Name "Server" -Value $server.servername
	                $lijn | Add-Member -type NoteProperty -Name "Onderdeel" -Value $_.TestItem
	                $lijn | Add-Member -type NoteProperty -Name "Waarde" -Value $_.TestValue
	                if($_.TestResultaat) {
	                    $ok = "OK"
	                }
	                else {
	                    $ok = "NOK"
	                }

	                $lijn | Add-Member -type NoteProperty -Name "Resultaat" -Value $ok
                    if ( (($_.testValue -notlike "*Not Installed") -AND ($_.testvalue -notlike "*Not Available")) -OR ($_.TestResultaat -like "NOK") ) {
	                    $resultaat += $lijn
                        }
                }
            }
        }
	$testToDisplay
    "-" * $testToDisplay.Length
    $resultaat | ft -AutoSize	
}


function Aprint-ToScreenByTest($testToDisplay){

    $ValidResult = $false
    $servers | foreach{
        $hostname = $_.servername
        $_.tests | foreach{
            if($_.TestName -eq $testToDisplay){
                $_.testResult | foreach{
                    $lijn = New-Object psObject 
	                $lijn | Add-Member -Type noteProperty -Name "Server" -Value $hostname
	                $lijn | Add-Member -type NoteProperty -Name "Onderdeel" -Value $_.TestItem
	                $lijn | Add-Member -type NoteProperty -Name "Waarde" -Value $_.TestValue
	                if($_.TestResultaat) {
	                    $ok = "OK"
	                }
	                else {
	                    $ok = "NOK"
	                }

	                $lijn | Add-Member -type NoteProperty -Name "Resultaat" -Value $ok
                    if ( ($_.TestValue -notlike "*Not Installed") ) {
	                    $resultaat += $lijn
                        }
	                #$resultaat += $lijn
                    #if (($_.testValue -notlike "*Not Installed") -AND ($_.testValue -notlike "*No Hyper-V Server")) {
                    if ( (($_.testValue -notlike "*Not Installed") -AND ($_.testvalue -notlike "*Not Available")) -OR ($_.TestResultaat -like "NOK") ) {
                        $ValidResult = $True
                        }
                }
            }
        }
    }

    if ($ValidResult) {
        $Servers.tests[-1].testName
        "-" * $Servers.tests[-1].testName.Length    
        $resultaat | ft -AutoSize
        }
}


function Aprint-ToScreenLastTest(){
    $resultaat = @()
    $ValidResult = $false

    $servers | foreach{
        $hostname = $_.servername
        $_.tests[-1] | foreach{
            $_.testResult | foreach{
                $lijn = New-Object psObject 
                $lijn | Add-Member -Type noteProperty -Name "Server" -Value $hostname
                $lijn | Add-Member -type NoteProperty -Name "Onderdeel" -Value $_.TestItem
                $lijn | Add-Member -type NoteProperty -Name "Waarde" -Value $_.TestValue
                if($_.TestResultaat) {
                    $ok = "OK"
                }
                else {
                    $ok = "NOK"
                }

                $lijn | Add-Member -type NoteProperty -Name "Resultaat" -Value $ok
                if ( ($_.TestValue -notlike "*Not Installed") ) {
	                $resultaat += $lijn
                    }                
                #$resultaat += $lijn
                #if ( ($_.testValue -notlike "*Not Installed") ) {
                if ( (($_.testValue -notlike "*Not Installed") -AND ($_.testvalue -notlike "*Not Available")) -OR ($_.TestResultaat -like "NOK") ) {
                    $ValidResult = $True
                    }
                }

        }
    }

    if ($ValidResult) {
        $Servers.tests[-1].testName
        "-" * $Servers.tests[-1].testName.Length   
        $resultaat | ft -AutoSize
        }
}


function Aprint-ToScreenByServer($serverToDisplay){
    echo $serverToDisplay
    echo "---------------"
    #echo ""
    $servers | foreach{
        if($_.servername -eq $serverToDisplay){
            $hostname = $_.servername
            $_.tests | foreach{
                $testName = $_.testName
                $_.testResult | foreach{
                    #if ( ($_.testValue -notlike "*Not Installed") ) {
                    if ( ($_.testValue -notlike "*Not Installed") -AND ($_.testvalue -notlike "*Not Available") ) {
                        if($_.TestResultaat) {
                            $ok = "OK"
                            }
                        else {
                            $ok = "NOK"
                            }
                        echo ($testname + ": " + $_.testItem + " " + $_.testValue + " -> " + $ok)
                        }
                }
                
            }
        }
    }
    echo ""
}


############################################ OPHALEN SERVERS ############################################
"Testing server Connections ..." | Out-Default

#$ServersSearchBase = "OU=\+BN,DC=emea,DC=dir"

try {
    if ($ServersSearchbase -eq "") {
        #echo "Searchbase is $ServersSearchbase"
        $AD_Servers = Get-ADComputer -Filter {(OperatingSystem -like "*server*") -AND (enabled -eq $true)} | Sort-Object Name
        }
    else {
        #echo "Searchbase is $ServersSearchbase"
        $AD_Servers = Get-ADComputer -Filter {(OperatingSystem -like "*server*") -AND (enabled -eq $true)} -SearchBase $ServersSearchbase | Sort-Object Name
        }
        
    $AD_Servers | Foreach { 
        Awrite-Verbose("Testing connection for " + $_.Name)
        $Excluded_Servers = "VLV-NAS-01","DRUNKIE","GRP","SCNC05","SCNC01","HERACLES2","EASYPAYSERV","PLUTON","HERACLES3","NEPTUNE","PRINTSERVER","DOCSHARENEW","HERACLES-2012","SRV-P-GRPL-S01","POSSEIDON"
        
        If ( ((Test-Connection -ComputerName $_.Name -Count 1 -Quiet) -eq $false) -OR ($Excluded_Servers -contains $_.Name) )
            {
            $BadServers += $_
            }
        Else
            {		
	        $Servers += acreate-server($_.name)
            }

        }
        "" | Out-Default
    } 
catch {
    Write-Host "Get-ADComputer is not available in this Windows AD Domain version (AD 2012 is necessary)"
    ############################################################################################################################################################
    #HARIBO not domain joined computers
    #$AD_Servers = "HAR-CRM-02","HAR-BCK-02","HAR-TS-02","SERVER01","SERVER02","SERVER03","SERVER04"
    #AHEAD not domain joined computer
    $AD_Servers = $env:COMPUTERNAME
    ############################################################################################################################################################

    $AD_Servers | Foreach { 
        Awrite-Verbose("Testing connection for " + $_)
        #If ( ((Test-Connection -ComputerName $_.Name -Count 1 -Quiet) -eq $false) -OR ($_.Name -eq "GRP") -OR ($_.Name -eq "SCNC05") -OR ($_.Name -eq "SCNC01") -OR ($_.Name -eq "HERACLES2") -OR ($_.Name -eq "EASYPAYSERV") -OR ($_.Name -eq "TRAD") -OR ($_.Name -eq "SERV-FABA") -OR ($_.Name -eq "PLUTON") -OR ($_.Name -eq "HERACLES3") -OR ($_.Name -eq "NEPTUNE") -OR ($_.Name -eq "PRINTSERVER") -OR ($_.Name -eq "SRV-NCB-MGMT01") -OR ($_.Name -eq "DOCSHARENEW") -OR ($_.Name -eq "SRV-NCB-ADFS") -OR ($_.Name -eq "HERACLES-2012") -OR ($_.Name -eq "SRV-NCB-BACKUP") -OR ($_.Name -eq "PCCBUC") -OR ($_.Name -eq "SRV-NCB-TEM") -OR ($_.Name -eq "SRV-P-GRPL-S01") -OR ($_.Name -eq "FABA-FEGC") -OR ($_.Name -eq "POSSEIDON"))
        If ((Test-Connection -ComputerName $_ -Count 1 -Quiet) -eq $false)
            {
                $BadServers += $_
            }
        Else
            {		
		    $Servers += acreate-server($_)
            }
        }
        "" | Out-Default
    }            

#### Bad Computers ####

if( $Badservers.count -gt 0) {
    "Volgende servers kunnen niet worden bereikt:"
    "--------------------------------------------"
    $BadServers | Sort Name | ft Name -HideTableHeaders
}
""

"PSRemoting is not enabled on the following server"
"-------------------------------------------------"
$servers | foreach {
   if (!$_.PSRemoting){
        echo $_.servername
   }
}
echo ""

############################################ Aanmaken Algemente testen ############################################

$network = ACreate-Server("Network")

############################################ BEGIN ServIT TESTEN ###########################################

#### Aanmaken GPO indien nodig ####
if ($CreateRemotingGPO){
	Aimport-PSRemotingGPO
}


#### Get WINS Servers ####
$WINS_Servers = Aget-Get_WINS_Servers $WINS_Servers   


#### Get DNS  Servers IPv6 Address ####
if ( -NOT($ad_Servers.Equals($env:COMPUTERNAME)) ) {
    $DNS_Servers_IPv6_Address = Aget-All_DNS_Servers_IPv6_Address
}

<#
#### Computer SID ####
$SERVER_SIDs = @()
$COMPARED_SERVER_SIDs = @()

$Servers | Foreach {
    Awrite-Verbose("Checking Computer SID on " + $_.servername)

    $SERVER_OBJ = Aget-Computer_SID2 $_.servername
    $SRV_SID = New-Object -TypeName psobject
    $SRV_SID | Add-Member -MemberType NoteProperty -Name SERVER -Value $_.servername
    $SRV_SID | Add-Member -MemberType NoteProperty -Name SID -Value $SERVER_OBJ
    $SERVER_SIDs += $SRV_SID
    }
    <#
    $SRV_SID = New-Object -TypeName psobject
    $SRV_SID | Add-Member -MemberType NoteProperty -Name SERVER -Value BCR-DC-02
    $SRV_SID | Add-Member -MemberType NoteProperty -Name SID -Value S-1-5-21-1204098803-2282756101-3952931304-6982
    $SERVER_SIDs += $SRV_SID
    #>
#>

foreach ($Item in $SERVER_SIDs) {
    #Write-host $Item.SERVER, "SID:",$Item.SID
    }
    # https://jdhitsolutions.com/blog/powershell/8465/filtering-powershell-unique-objects/
    #$COMPARED_SERVER_SIDs = $SERVER_SIDs | get-unique -AsString | sort SERVER
    #$NotUniqueSIDs = compare-object ($SERVER_SIDs)($COMPARED_SERVER_SIDs) -IncludeEqual

#if(!$OutputByServer){ Aprint-ToScreenLastTest } 


#### Uptime ####
$Servers | Foreach {
    Awrite-Verbose("Checking Uptime on " + $_.servername)
	$_.tests += Aget-WindowsUptime $_.servername
}
if(!$OutputByServer){ Aprint-ToScreenLastTest } 


#### Computer SID ####
$Servers | Foreach {
    Awrite-Verbose("Checking Computer SID on " + $_.servername)
	$_.tests += Aget-Computer_SID $_.servername
}
if(!$OutputByServer){ Aprint-ToScreenLastTest } 


#### APC PowerChute ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking for APC PowerChute Network Shutdown " + $_.servername)        
        $_.tests += Aget-Check_APC_POWERCHUTE_NETWORK_SHUTDOWN $_.servername
    } else {
        Awrite-Verbose ("Skipping APC PowerChute Network Shutdown check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "APC PowerChute Network Shutdown" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Eaton Intelligent PowerProtector ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking for Eaton Intelligent PowerProtector " + $_.servername)        
        $_.tests += Aget-Check_Eaton_IntelligentPowerProtector $_.servername
    } else {
        Awrite-Verbose ("Skipping Eaton Intelligent PowerProtector check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Eaton Intelligent PowerProtector" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Antivirus ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Antivirus Product on " + $_.servername)
        $_.tests += Aget-Antivirus $_.servername "antivirusEnabled"
    } else {
        Awrite-Verbose ("Skipping Antivirus Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Antivirus Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### GFI AntiSpam ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking GFI Anti Spam Product on " + $_.servername)
        $_.tests += Aget-AntiSPAM $_.servername
    } else {
        Awrite-Verbose ("Skipping GFI Anti Spam Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Anti Spam Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### MozyPro Backup ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking MozyPro Backup Product on " + $_.servername)
        $_.tests += Aget-MozyBackup $_.servername
    } else {
        Awrite-Verbose ("Skipping MozyPro Backup Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "MozyPro Backup Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Carbonite Safe Server Backup ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Carbonite Safe Server Backup Product on " + $_.servername)
        $_.tests += Aget-CarboniteBackup $_.servername
    } else {
        Awrite-Verbose ("Skipping Carbonite Safe Server Backup Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Carbonite Safe Server Backup Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Veeam Endpoint (Agent) Backup ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Veeam Endpoint (Agent) Backup on " + $_.servername)
        $_.tests += Aget-VeeamEndpointBackup $_.servername
    } else {
        Awrite-Verbose ("Skipping Veeam Endpoint Backup on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Veeam Endpoint Backup" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Veeam Backup ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Veeam Backup Product on " + $_.servername)
        $_.tests += Aget-VeeamBackup2 $_.servername
    } else {
        Awrite-Verbose ("Skipping Veeam Backup Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Veeam Backup Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Symantec BackupExec ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Symantec BackupExec Product on " + $_.servername)
        $_.tests += Aget-BackupExec $_.servername
    } else {
        Awrite-Verbose ("Skipping Symantec BackupExec Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Symantec BackupExec Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Arcserv Backup ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Arcserv Backup Product on " + $_.servername)
        $_.tests += Aget-ArcservUDP_Backup $_.servername
    } else {
        Awrite-Verbose ("Skipping Arcserv Backup Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Arcserv Backup Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### OODrive AdBE Backup ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking OODrive AdBE Backup Product on " + $_.servername)
        $_.tests += Aget-OODrive_AdBE_Backup $_.servername
    } else {
        Awrite-Verbose ("Skipping OODrive AdBE Backup Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "OODrive AdBE Backup Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Acronis Backup ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Acronis Backup Product on " + $_.servername)
        $_.tests += Aget-Acronis_Backup $_.servername
    } else {
        Awrite-Verbose ("Skipping Acronis Backup Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Acronis Backup Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Caché Database ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Caché Database Product on " + $_.servername)
        $_.tests += Aget-Check_Cache_DB $_.servername "antivirusEnabled"
    } else {
        Awrite-Verbose ("Skipping Caché Database Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Caché Database Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Java RTE ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Java RTE Product on " + $_.servername)
        $_.tests += Aget-JavaRTE $_.servername
    } else {
        Awrite-Verbose ("Skipping Java RTE Product on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Java RTE Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Services ####
$Servers | Foreach {
    Awrite-Verbose("Checking Services on " + $_.servername)
	$_.tests += Aget-WindowsServices $_.servername
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### DiskSpace ####
$Servers | Foreach {
    Awrite-Verbose("Checking Diskspace on " + $_.servername)
    $_.tests += Aget-Diskspace $_.servername
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Scheduled tasks ####
$Servers | Foreach {
    Awrite-Verbose("Checking Scheduled tasks on " + $_.servername)
	$_.tests += Aget-ScheduledTasks $_.servername
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Windows Time Source ####
if ( -NOT($ad_Servers.Equals($env:COMPUTERNAME)) ) {
    $Servers | Foreach {
        if($_.PSRemoting) {
            Awrite-Verbose ("Checking Timesource on " + $_.servername)
            $_.tests += Aget-WindowsTimeSource2 $_.ServerName
            }
        else {
            Awrite-Verbose ("Skipping Timesource on " + $_.servername + ". No PS Remoting")
            $_.tests += ACreate-Test "Timesource" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
            }
        }
    if(!$OutputByServer) { Aprint-ToScreenLastTest }
}


#### Lingering Snapshots ####
$Servers | Foreach {
    if($_.PSRemoting) {
        Awrite-Verbose ("Checking Hyper-V Lingering Snapshots on " + $_.servername)
        $_.tests += Aget-VM_Snapshots $_.ServerName
    } else {
        Awrite-Verbose ("Skipping Hyper-V Lingering Snapshots on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Hyper-V Lingering Snapshots" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer) { Aprint-ToScreenLastTest }


#### DiskDefrag ####
if ($CheckDefrag){
    $servers | foreach {
        Awrite-Verbose("Running Disk Fragmentation Analysis on " +$_.servername)
        $_.tests += Aget-DefragAnalysis $_.servername
    }
    if(!$OutputByServer){ Aprint-ToScreenLastTest }
}


if($OutputByServer){
    $servers | foreach{
    Aprint-ToScreenByServer $_.servername
    }
}


#### DHCP Authorized Servers check ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    Awrite-Verbose("Checking DHCP Authorized Servers")
	$network.tests += Aget-Authorised_DHCP_Servers
	
	Aprint-ToScreenByTestOf "DHCP Authorized Servers" $Network
    }


#### DHCP Config Check ####
if ($Blauwdruk){
    Awrite-Verbose("Checking DHCP Server Config")
	$network.tests += Aget-DHCP_Servers_Config
	
	Aprint-ToScreenByTestOf "DHCP Server Config" $Network
}


#### DNS check2 ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    Awrite-Verbose("Checking DNS Config")
	$network.tests += Aget-DNS_Servers2
	
	Aprint-ToScreenByTestOf "DNS Servers" $Network
    }


#### DNS Forwarders check ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    Awrite-Verbose("Checking DNS Forwarders")
	$network.tests += Aget-DNS_Forwarders
	
	Aprint-ToScreenByTestOf "DNS Forwarders" $Network
    }


#### WINS Server Running ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    $servers | foreach {
        if($_.PSRemoting) {
            Awrite-Verbose("Checking WINS Server on " + $_.servername)
            $_.tests += Aget-WINS_Servers_Check $_.servername "antivirusEnabled"
            }
        else {
            Awrite-Verbose ("Skipping WINS Server on " + $_.servername + ". No PS Remoting")
            $_.tests += ACreate-Test "WINS Server" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
            }
        }
    if(!$OutputByServer){ Aprint-ToScreenLastTest }
    }


#### Windows Server DNS and WINS Settings per NIC ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    $Servers | Foreach {
        if($_.PSRemoting) {
            Awrite-Verbose ("Checking DNS and WINS Settings per NIC on " + $_.servername)
            $_.tests += Aget-CheckWindowsDNSSettingsPerNIC $_.ServerName $WINS_Servers
            }
        else {
            Awrite-Verbose ("Skipping DNS and WINS Settings per NIC on " + $_.servername + ". No PS Remoting")
            $_.tests += ACreate-Test "DNS and WINS Settings per NIC" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
            }
        }
    if(!$OutputByServer) { Aprint-ToScreenLastTest }
    }


#### IPv6 NIC DNS Settings ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    $servers | foreach {
        if($_.PSRemoting) {
            Awrite-Verbose("Checking IPv6 NIC DNS Settings on DC's " + $_.servername)        
            $_.tests += Aget-IPv6_NIC_Settings $_.servername $DNS_Servers_IPv6_Address
            }
        else {
            Awrite-Verbose ("Skipping IPv6 NIC DNS Settings on DC's check " + $_.servername + ". No PS Remoting")
            $_.tests += ACreate-Test "IPv6 NIC DNS Settings on DC's" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
            }
        }
    if(!$OutputByServer){ Aprint-ToScreenLastTest }
    }


#### PDC ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    Awrite-Verbose("Checking for PDC")
	$network.tests += Aget-PDC
	
	Aprint-ToScreenByTestOf "Primary Domain Controller" $Network
    }


####  Domain Controller LDAP Access ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    Awrite-Verbose("Checking for Domain Controller Secure LDAP Access")
	$network.tests += Aget-DC_LDAPSSL	
	Aprint-ToScreenByTestOf "Domain Controller Secure LDAP" $Network
    }


#### FSMO Roles ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    Awrite-Verbose("Checking for FSMO Roles")
	$network.tests += Aget-FSMO
	
	Aprint-ToScreenByTestOf "FSMO Roles" $Network
    }


#### Windows Advanced Firewall ####
$Servers | Foreach {
    if($_.PSRemoting) {
        Awrite-Verbose ("Checking Windows Advanced Firewall on " + $_.servername)
        $_.tests += Aget-FirewallProfile $_.ServerName
    } else {
        Awrite-Verbose ("Skipping Windows Advanced Firewall on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Windows Advanced Firewall" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer) { Aprint-ToScreenLastTest }


#### Windows Updates Settings ####
$Servers | Foreach {
    if($_.PSRemoting) {
        Awrite-Verbose ("Checking Windows Update Settings on " + $_.servername)
        $_.tests += Aget-WindowsUpdateSettings $_.ServerName
    } else {
        Awrite-Verbose ("Skipping Windows Update Settings on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Windows Update Settings" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer) { Aprint-ToScreenLastTest }


#### Windows Updates Status ####
if ($CheckQueuedUpdates) {
    $Servers | Foreach {
        if($_.PSRemoting) {
            Awrite-Verbose ("Checking Windows Update Status on " + $_.servername)
            $_.tests += Aget-CheckWindowsUpdateStatus2 $_.ServerName $CheckFailedUpdates
            }
        else {
            Awrite-Verbose ("Skipping Windows Update Status on " + $_.servername + ". No PS Remoting")
            $_.tests += ACreate-Test "Windows Update Status" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
            }
        }
    if(!$OutputByServer) { Aprint-ToScreenLastTest }
    }


#### Windows UAC ####
$Servers | Foreach {
    if($_.PSRemoting) {
        Awrite-Verbose ("Checking Windows UAC on " + $_.servername)
        $_.tests += Aget-UACLevel $_.ServerName
    } else {
        Awrite-Verbose ("Skipping Windows UAC on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Windows UAC" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer) { Aprint-ToScreenLastTest }


#### AAD Sync/Connect Installed ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking Microsoft Azure AD Sync/Connect on " + $_.servername)
        $_.tests += Aget-AAD_Connect_Version $_.servername
    } else {
        Awrite-Verbose ("Skipping Microsoft Azure AD Sync/Connect on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Microsoft Azure AD Sync/Connect" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### SQL Server Installed ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking SQL Server on " + $_.servername)
        $_.tests += Aget-SQL_Server_Instances $_.servername
    } else {
        Awrite-Verbose ("Skipping SQL Server Installation on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "SQL Server" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### RDP Network Level Authentication ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking RDP Network Level Authentication on " + $_.servername)
        $_.tests += Aget-RDP_NLA $_.servername
    } else {
        Awrite-Verbose ("Skipping RDP Network Level Authentication on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "RDP Network Level Authentication" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### AD Recycle Bin Enabled ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    Awrite-Verbose("Checking AD Recycle Bin Enabled")
	$network.tests += Aget-ADRecycleBin
    Aprint-ToScreenByTestOf "AD Recycle Bin" $Network
    }


#
### SignedOrSecure_Channel_Communication ####
#$servers | foreach {
#    if($_.PSRemoting) {
#        Awrite-Verbose("Checking Encrypt or Sign AD Communication on " + $_.servername)
#        $_.tests += Aget-SignedOrSecure_Channel_Communication $_.servername "Encrypt or Sign AD Communication"
#    } else {
#        Awrite-Verbose ("Skipping Encrypt or Sign AD Communication on " + $_.servername + ". No PS Remoting")
#        $_.tests += ACreate-Test "Encrypt or Sign AD Communication" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
#    }
#}
#if(!$OutputByServer){ Aprint-ToScreenLastTest }
#


#### Check for SMBv1 protocol ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking SMBv1 Protocol Disabled on " + $_.servername)
        $_.tests += Aget-Check_SMBv1 $_.servername "SMBv1 Protocol"
    } else {
        Awrite-Verbose ("Skipping SMB Protocol Disabled on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "SMB Protocol" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Healthy DFSR SYSVOL Replication ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    $servers | foreach {
        if($_.PSRemoting) {
            Awrite-Verbose("Checking Healthy DFSR SYSVOL Replication Check on " + $_.servername)
            $_.tests += Aget-DFSR_SYSVOL_Replication_Health $_.servername "antivirusEnabled"
            }
        else {
            Awrite-Verbose ("Skipping Healthy DFSR SYSVOL Replication Product Check on " + $_.servername + ". No PS Remoting")
            $_.tests += ACreate-Test "Healthy DFSR SYSVOL Replication Product" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
            }
        }
    if(!$OutputByServer){ Aprint-ToScreenLastTest }
    }


#### FSLogix Apps ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking FSLogix Apps " + $_.servername)        
        $_.tests += Aget-Check_FSLogix $_.servername
    } else {
        Awrite-Verbose ("Skipping FSLogix Apps check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "FSLogix Apps" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### UEFI Secureboot ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking UEFI Secureboot on " + $_.servername)
        $_.tests += Aget-Check_UEFISecureboot $_.servername "UEFI Secureboot"
    } else {
        Awrite-Verbose ("Skipping UEFI Secureboot on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "UEFI Secureboot" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Remote desktop Connection Manager Version ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking for Remote Desktop Connection Manager " + $_.servername)        
        $_.tests += Aget-Check_Remote_Desktop_Connection_Manager $_.servername
    } else {
        Awrite-Verbose ("Skipping Remote Desktop Connection Manager check on " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Remote Desktop Connection Manager" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### SMB Fileserver Settings ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking for SMB Fileserver Settings " + $_.servername)        
        $_.tests += Aget-Check_SMB_OPTIMIZED_SETTINGS $_.servername
    } else {
        Awrite-Verbose ("Skipping SMB Fileserver Settings check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "SMB Fileserver Settings" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Receive-Side Scaling State ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking for Receive-Side Scaling " + $_.servername)        
        $_.tests += Aget-Check_RSS_NIC_SETTING $_.servername
    } else {
        Awrite-Verbose ("Skipping Receive-Side Scaling check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Receive-Side Scaling" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### IPsecoffload State ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking for IPsecoffload State " + $_.servername)        
        $_.tests += Aget-Check_IPsecoffload $_.servername
    } else {
        Awrite-Verbose ("Skipping IPsecoffload State check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "IPsecoffload State" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### NIC VM Queuing State State ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking for NIC VM Queuing State " + $_.servername)        
        $_.tests += Aget-Check_NIC_VM_QUEUING $_.servername
    } else {
        Awrite-Verbose ("Skipping NIC VM Queuing State check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "NIC VM Queuing State" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### High Performance Power Plan ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking for High Performance Power Plan " + $_.servername)        
        $_.tests += Aget-Check_Power_Plan $_.servername
    } else {
        Awrite-Verbose ("Skipping High Performance Power Plan check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "High Performance Power Plan" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### Get 'Remote Desktop Users' Security Group Members ####
$Servers | Foreach {
    Awrite-Verbose("Checking 'Remote Desktop Users' Security Group Members on " + $_.servername)
	$_.tests += Aget-RDS_SG_Members $_.servername
}
if(!$OutputByServer){ Aprint-ToScreenLastTest }


#### WinHTTP and TLS 1.2 Support ####
$servers | foreach {
    if($_.PSRemoting) {
        Awrite-Verbose("Checking if WinHTTP and TLS 1.2 is activated " + $_.servername)        
        $_.tests += Aget-Check_TLS_1.2_Protocol $_.servername
    } else {
        Awrite-Verbose ("Skipping WinHTTP and TLS 1.2 Support check " + $_.servername + ". No PS Remoting")
        $_.tests += ACreate-Test "Is WinHTTP and TLS 1.2 Activated" (ACreate-TestResult "Powershell Remoting" "Not Available" $false)
    }
}
if(!$OutputByServer){ Aprint-ToScreenLastTest } 


#### NPSextension for Azure AD MFA ####
$Servers | Foreach {
    Awrite-Verbose("Checking Computer SID on " + $_.servername)
	$_.tests += Aget-NPSextension_For_MFA $_.servername
}
if(!$OutputByServer){ Aprint-ToScreenLastTest } 


#### NTFS Volume Health ####
$Servers | Foreach {
    Awrite-Verbose("Checking NTFS Volume Health " + $_.servername)
	$_.tests += Aget-NTFS_Volume_Health $_.servername
}
if(!$OutputByServer){ Aprint-ToScreenLastTest } 


#### Domain admin ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    Awrite-Verbose("Checking Domain Admins")
	$network.tests += Aget-DomainAdmins
	
	Aprint-ToScreenByTestOf "Domainadmin" $Network
    }


#### Exchange Log ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    ""
    "Mailbox Database Size"
    "----------------------"
    Awrite-Verbose("Checking Mailbox Database Size")
    foreach($exch in Aget-exchangeserver){
	    Echo $exch
	    echo "-----------------------------"
        $exhcServerObj = AFindServerByName $exch
        #    Aget-MailboxDBSize($exch)
        if ($exhcServerObj.PSRemoting){
		    fl | Aget-MailboxDBSize($exch)
	        }
        else {
		    Awrite-Verbose("" + $Exch + " is niet breikbaar")
	        }
        }
    }


if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    ""
    ""
    "Mailbox Database FullBackup"
    "-----------------------------"
    Awrite-Verbose("Checking Mailbox Database FullBackup")
    foreach($exch in Aget-exchangeserver){
	    Echo $exch
	    echo "-----------------------------"
        $exhcServerObj = AFindServerByName $exch
        #Aget-MailboxDBBackup($exch)
        if ($exhcServerObj.PSRemoting){
		    fl | Aget-MailboxDBBackup($exch)
	        }
        else {
		    Awrite-Verbose("" + $Exch + " is niet breikbaar")
	        }
    }
}


if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    ""
    ""
    "Mailbox Usage"
    "-----------------------------"
    Awrite-Verbose("Checking Mailbox Usage")
    foreach($exch in Aget-exchangeserver) {
	    Echo $exch
	    echo "-----------------------------"
        $exhcServerObj = AFindServerByName $exch
        if ($exhcServerObj.PSRemoting){
		    Aget-ExchangeMailboxSizes($exch)
            }
        else {
	        Awrite-Verbose("" + $Exch + " is niet breikbaar")
	        }
        }
    }


#### Windows Forest Functional Level ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    ""
    ""
    "Windows Forest Functional Level"
    "-------------------------------"
    Awrite-Verbose("Checking Windows Forest Functional Level")
    Aget-WindowsForestFunctionalLevel
    }


#### Windows Domain Functional Level ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    ""
    ""
    "Windows Domain Functional Level"
    "-------------------------------"
    Awrite-Verbose("Checking Windows Domain Functional Level")
    Aget-WindowsDomainFunctionalLevel
    }


#### DFSR SYSVOL Replication Migration State ####
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    ""
    ""
    "DFSR SYSVOL Replication Migration State"
    "---------------------------------------"
    Awrite-Verbose("Checking DFSR SYSVOL Replication Migration State")
    Aget-DFSR_SYSVOL_Replication_Migration_State
    }


""
""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "Windows XP Enabled Computers"
    "----------------------------"
    #
    Get-ADComputer -Filter {enabled -eq $true} -Properties Name,OperatingSystem,LastLogonDate | WHERE {($_.OperatingSystem -match “Windows XP Professional” -AND ($_.Enabled -eq $True)) } | SELECT Name, OperatingSystem, LastLogonDate | SORT LastLogonDate –unique | FORMAT-TABLE -Wrap –Auto
    }


""
""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "Windows 7 Enabled Computers"
    "----------------------------"
    #
    Get-ADComputer -Filter {enabled -eq $true} -Properties Name,OperatingSystem,LastLogonDate | WHERE {($_.OperatingSystem -match 'Windows ([7])\D+' -AND ($_.Enabled -eq $True)) } | SELECT Name, OperatingSystem, LastLogonDate | SORT LastLogonDate –unique | FORMAT-TABLE -Wrap –Auto
    }


""
""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "Windows 8 Enabled Computers"
    "----------------------------"
    #    
    Get-ADComputer -Filter {enabled -eq $true} -Properties Name,OperatingSystem,LastLogonDate | WHERE {($_.OperatingSystem -match 'Windows ([8][ ])\D+' -AND ($_.Enabled -eq $True)) } | SELECT Name, OperatingSystem, LastLogonDate | SORT LastLogonDate –unique | FORMAT-TABLE -Wrap –Auto
    }


""
""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "Windows 8.1 Enabled Computers"
    "----------------------------"
    #    
    Get-ADComputer -Filter {enabled -eq $true} -Properties Name,OperatingSystem,LastLogonDate | WHERE {($_.OperatingSystem -match 'Windows ([8].[1])\D+' -AND ($_.Enabled -eq $True)) } | SELECT Name, OperatingSystem, LastLogonDate | SORT LastLogonDate –unique | FORMAT-TABLE -Wrap –Auto
    }


""
""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "90days Inactive Enabled Computers"
    "---------------------------------"
    # Gets time stamps for all computers in the domain that have NOT logged in since after specified date 
        
    $DaysInactive = 90  
    $time = (Get-Date).Adddays(-($DaysInactive)) 

    # Get all AD computers with lastLogonTimestamp less than our $DaysInactive time 
    Get-ADComputer -Filter {LastLogonTimeStamp -lt $time -AND enabled -eq $true} -Properties LastLogonTimeStamp | SELECT-OBJECT Name,@{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp)}} | SORT Stamp | FORMAT-TABLE -Wrap –Auto
    }


""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "90days Inactive Enabled Users"
    "-----------------------------"
    # Gets time stamps for all User in the domain that have NOT logged in since after specified date 
  
    $DaysInactive = 90  
    $time = (Get-Date).Adddays(-($DaysInactive)) 

    # Get all AD User with lastLogonTimestamp less than our $DaysInactive time and set to enable 
    Get-ADUser -Filter {LastLogonTimeStamp -lt $time -AND enabled -eq $true} -Properties LastLogonTimeStamp | SELECT-OBJECT Name,@{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('yyyy-MM-dd_hh:mm:ss')}} | SORT Stamp | FORMAT-TABLE -Wrap –Auto
    }


""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "Users with password stored with reversible encryption"
    "-----------------------------------------------------"
    # get a list of AD users where Password is stored with reversible Encryption

    Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl | SELECT-OBJECT Name, DistinguishedName,@{Label = "ReversibleEncryptionEnabled";Expression = {echo "Yes"}}
    }


""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "Get list of all user accounts that do not require a password and are Enabled"
    "----------------------------------------------------------------------------"
    # Get a list of all user accounts that do not require a password and are Enabled
    # https://learn.microsoft.com/en-us/answers/questions/42973/password-not-required-attribute-is-true-does-this
    # to fix it: Get-ADUser -Identity User2 | Set-ADUser -PasswordNotRequired $false

    Get-ADUser -Filter {PasswordNotRequired -eq $true -AND enabled -eq $true} -properties Name, PasswordNotRequired, Enabled | SORT Name | FORMAT-TABLE Name, PasswordNotRequired, Enabled -Wrap –Auto
    }


""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "All OS'es on all Enabled Domain Joined Computers"
    "------------------------------------------------"
    # Gets time stamps for all User in the domain that have NOT logged in since after specified date 
  
    Get-ADComputer -Filter {enabled -eq $true} -Property * | SORT OperatingsystemVersion | FORMAT-TABLE Name,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion -Wrap –Auto
    }
 

""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "Users with non-blanc Description field"
    "--------------------------------------"
    # Gets time stamps for all User in the domain that have NOT logged in since after specified date 
    
    Get-ADUser -filter * -properties * | WHERE-OBJECT{$_.Description -ne $null} | SORT Name | FORMAT-TABLE Name, Description -Wrap –Auto
    }


""
if ( -NOT($AD_Servers.Equals($env:COMPUTERNAME)) ) {
    "All enabled AD users' PasswordLastSet and PasswordNeverExpires propeties"
    "------------------------------------------------------------------------"
    # Get a list of AD users' PasswordLastSet and PasswordNeverExpires propeties

    Get-ADUser -filter {enabled -eq $true} -properties passwordlastset, passwordneverexpires | SORT name | FORMAT-TABLE Name, passwordlastset, Passwordneverexpires -Wrap –Auto
    }


#### Windows Server Best Practices ####
#$CheckWindowsBPA=$true
if ($CheckWindowsBPA) {
#
"Windows Server BPA"
"------------------"
    $Servers | Foreach {    
        if($_.PSRemoting) {
            Awrite-Verbose("Checking Windows Server BPA on " + $_.servername)
            $Message = "Server: "+$_.servername
            echo ""
            echo $Message
            echo ------------------------
            Aget-WindowsBPA $_.servername
            }
        }
    }

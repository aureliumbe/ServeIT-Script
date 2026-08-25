Function  Import-SVPSRemotingGPO(){
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

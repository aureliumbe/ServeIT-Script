function Get-SVVeeamPSSnapin() {
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

function Get-SVCheck4Tpm($comp){
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

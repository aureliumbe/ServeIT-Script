function Invoke-SVTracert {
    param([string]$RemoteHost)

    tracert -d -h 1 $RemoteHost |ForEach-Object{
        if ($_.Trim() -match "^\d{1,2}\s+") {
            $n,$a1,$a2,$a3,$target,$null = $_.Trim()-split"\s{2,}"
            $target
            }
        }
}

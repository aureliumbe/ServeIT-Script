# ServeIT

ServeIT is a modular PowerShell health-check runner. The master script writes a JSON report and prints each result as its check completes.

## Run

```powershell
.\ServeIT.ps1 -ConfigPath .\config\ServeIT.json -JsonPath .\reports\ServeIT-report.json
```

Add `-Verbose` to show progress while Active Directory, ICMP, WMI/RPC, PowerShell remoting, and Exchange connectivity are being checked.

Override the configured targets for one run:

```powershell
.\ServeIT.ps1 -ComputerName SERVER01,SERVER02 -JsonPath .\reports\run.json
```

By default, matching timestamped `ServeIT-report_yyyyMMdd_HHmmss.json` and `.html` files are written to the working directory. Separate report paths can be produced by passing `-JsonPath` and `-HtmlPath`.

Each check result is also printed to the console as soon as it completes.

Generate an HTML report alongside the JSON report:

```powershell
.\ServeIT.ps1 -JsonPath .\reports\run.json -HtmlPath .\reports\run.html
```

Group the HTML results by server instead of check:

```powershell
.\ServeIT.ps1 -JsonPath .\reports\run.json -HtmlPath .\reports\run.html -GroupByServer
```

Generate HTML from an existing JSON report without running checks:

```powershell
.\ServeIT.ps1 -ImportJsonResult .\reports\run.json -HtmlPath .\reports\run.html
```

HTML headings use the configured check `name` from `config\ServeIT.json`. Scalar results use `Server`, `Item`, `Value`, and `Status` columns. Structured object results use a column for each object property instead of putting the complete object in one value column.

## Add a check
1. Add one file under `checks\`.
2. Define one function whose name exactly matches the file base name.
3. Accept `$Context` and `$ComputerName`.
4. Return one or more `New-SVResult` objects.
5. Add the check id, human-readable name, and enabled flag to `config\ServeIT.json`. Add the id to `priorityChecks` only when that check must run before the other enabled checks.

Unregistered scripts under `checks\` are skipped and produce a warning when the runner starts. Enabled configuration entries without a matching script also produce a warning and are skipped.

Example result:

```powershell
New-SVResult 'Check-Example' $ComputerName $value $passed 'Optional message'
```

`Results` is deliberately an array in a single run-level document. This keeps the report atomic, preserves execution order, and makes cross-check summaries straightforward.

## Layout

- `ServeIT.ps1`: master entry point; no check logic.
- `src\ServeIT.Core.psm1`: result objects, registry loading, execution, and report persistence helpers.
- `checks\`: one check per file.
- `config\ServeIT.json`: AD discovery settings, fallback computers, enabled checks, domain-level checks, and the optional priority check list. By default, enabled AD computer objects whose operating system is a server are discovered, tested for reachability and WMI/RPC connectivity, and only servers passing both checks receive server checks. `UnreachableServers` and `RpcUnreachableServers` are preserved in the JSON report; RPC exclusions are also shown as a warning at the top of the HTML report. Priority checks run first in listed order; all other checks run afterward in configuration order.

Set `defragCheckEnabled` to `true` in `config\ServeIT.json` to run the potentially slow disk defragmentation analysis. When it is `false`, the check is skipped and the report contains a warning stating that defrag analysis was not executed. When enabled, the report warning states that the analysis will be executed.

All server checks run when PowerShell remoting is unavailable. The report includes `PSRemotingStatus` and a `PSRemotingUnavailable` warning for each affected server; check execution results remain separate from the capability warning.

Veeam is grouped like the original script: only `Get-SVVeeamBackup2` and `Get-SVVeeamEndpointBackup` are configured as checks. The other Veeam files contain support functions and are loaded for use by the Veeam Backup check, but are not executed independently.

Backup Exec follows the same original boundary: only `Get-SVBackupExec` is a standalone check. `Get-SVBackupExec2` and `Get-SVBackupExec4` are helper functions used by the main check and are listed in `helperFunctions`.

Antivirus follows the original dispatcher boundary as well: only `Get-SVAntiVirus` is a standalone check. It detects the running product and invokes the matching product-specific helper; the product helpers are listed in `helperFunctions` and are not run independently.

Functions that are intentionally not standalone checks are listed in `helperFunctions` in `config\ServeIT.json`. They do not trigger the unregistered-script warning. A configured check with `enabled: false` still reports a separate disabled-check warning.

Exchange checks are listed in `exchangeChecks`. The runner discovers Exchange servers from the AD Exchange configuration container, intersects them with reachable servers, and runs those checks only against the resulting Exchange server list. The selected servers are recorded as `ExchangeServers` in the JSON report.
- `reports\`: generated JSON output; keep generated files out of Git.

## Legacy migration

The legacy checks have been split into individual files under `checks\`. `config\LegacyChecks.json` is the migration inventory and currently contains 98 executable legacy checks. The original source listed `Get-SVCheck_PrintNightmare` only as a comment, so it is not registered as an executable check.

Legacy functions retain their original implementation and are adapted at runtime into the JSON result schema. This makes the migration behavior-preserving while allowing each check to be modernized independently later.


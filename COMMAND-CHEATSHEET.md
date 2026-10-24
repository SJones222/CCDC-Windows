# CCDC-Windows Command Cheatsheet

Run these commands from the repository root in Windows PowerShell 5.1. The five inventory/audit scripts are read-only and write unique timestamped report directories. The installer also provides their short root names: `network.ps1`, `system.ps1`, `users.ps1`, `persistence.ps1`, and `events.ps1`. The separately attributed team administration scripts below retain their original outputs and change system/domain configuration when applied.

## Inventory

```powershell
.\Inventory\Get-SystemInventory.ps1
.\Inventory\Get-NetworkInventory.ps1
```

Default reports:

- System: `summary.txt`, `inventory.json`
- Network: `summary.txt`, `network.json`, `listeners.csv`, `running-services.csv`

## Audits

```powershell
.\Audit\Get-UserAudit.ps1
.\Audit\Get-PersistenceAudit.ps1
.\Audit\Get-SecurityEventTriage.ps1
```

Security event triage options:

```powershell
.\Audit\Get-SecurityEventTriage.ps1 -Hours 24
.\Audit\Get-SecurityEventTriage.ps1 -Deep -Hours 72
```

Audit reports:

- User audit: `summary.txt`, `users.json`, `accounts.csv`, `privileged-members.csv`
- Persistence audit: `summary.txt`, `persistence.json`, `entries.csv`
- Security event triage: `summary.txt`, `events.json`, `events.csv`

## Override the output root

Use `-OutputDir` with any script when reports should be rooted somewhere other than the repository-level `Output/` directory:

```powershell
.\Inventory\Get-SystemInventory.ps1 -OutputDir (Join-Path $env:TEMP 'CCDC-Reports')
.\Audit\Get-SecurityEventTriage.ps1 -Hours 24 -OutputDir (Join-Path $env:TEMP 'CCDC-Reports')
```

The script creates the host and timestamped subdirectories below the selected root. It reports collection failures, output failures, and the actual report directory in the terminal summary. A nonzero exit status indicates that reports could not be saved successfully.

## Notes

- The inventory/audit scripts do not perform network scans or change system configuration.
- Inventory and audit results may be partial or unavailable under limited privileges; read the terminal warnings and `summary.txt`.
- On domain controllers, `Get-UserAudit.ps1` reports Active Directory limitations when the optional built-in ActiveDirectory module is unavailable.

## Windows Team Scripts (manual operation)

The installer deploys all five files below to the installation root and preserves their source directories. None is run automatically. Start an elevated Windows PowerShell 5.1 session and use `cd C:\CCDC` (or the chosen installation root). See the [README team section](README.md#windows-team-scripts) for contributor attribution, complete prerequisites, operational limits, verified hashes, and the scope of maintainer-confirmed redistribution permission.

### Domain-controller firewall

From [Enhan540/CCDCTesting](https://github.com/Enhan540/CCDCTesting), [original barebones v3.0 source](https://github.com/Enhan540/CCDCTesting/blob/main/scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v3.0.ps1). Preserved source: `Firewall/dc-firewalls-barebones-v3.0.ps1`; approved SHA256: `9b373c5811eb7215ba2b767c172c762828cab0d548d1da4471b3c28b953b16ef`. Requires Windows PowerShell 5.1, administrator privileges, and built-in NetSecurity functionality; it can elevate through UAC. Intended for Active Directory DCs, without a host-role check.

**These commands apply changes immediately; there is no `-Preview` parameter or `-WhatIf` implementation.** Choose the intended operation, not all three in sequence. `-ClientNetworks` is optional for initial setup; without it, the primary IPv4 subnet is detected. Replace the illustrative `192.168.1.0/24` with the actual authorized network.

```powershell
cd C:\CCDC
# Initial setup using the detected subnet:
.\dc-firewalls-barebones-v3.0.ps1
# Alternative initial setup with an explicit network:
.\dc-firewalls-barebones-v3.0.ps1 -ClientNetworks '192.168.1.0/24'
# Modify existing enabled local barebones rule scopes (explicit network required):
.\dc-firewalls-barebones-v3.0.ps1 -Modify -ClientNetworks '192.168.1.0/24'
```

Equivalent `powershell.exe` forms, also alternatives:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.0.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.0.ps1 -ClientNetworks '192.168.1.0/24'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.0.ps1 -Modify -ClientNetworks '192.168.1.0/24'
```

Initial setup creates/verifies 13 inbound AD Allow rules and enables Domain, Private, and Public firewall profiles. It **disables other enabled local inbound rules, including Allow and Block rules**. Retain console access: SSH, RDP, WinRM, additional scored services, and other AD services may lose access unless separately accommodated. Existing Group Policy rules can remain effective. It does not explicitly set `DefaultInboundAction` to Block. Verify effective policy and required connectivity afterward.

Backups and reports are fixed at `C:\CCDC\FirewallBackups`, even with a custom installer destination. Initial setup writes BEFORE and AFTER policy backups and readable rule reports (`firewall-before-<timestamp>.wfw` / `.txt`, `firewall-after-<timestamp>.wfw` / `.txt`) and prints a `netsh advfirewall import` rollback command. `-Modify` changes only remote scopes on enabled local script-managed barebones inbound rules and exports an after-modification policy/change report (`firewall-modify-after-<timestamp>.wfw` / `.txt`); it does not create a separate before-modification backup. No firewall script runs during installation.

### AD password resets

From [Tausetii/CCDC-tings](https://github.com/Tausetii/CCDC-tings), `PCRs/`. Required: ActiveDirectory module, domain connectivity, and password-reset rights. No explicit parameters are mandatory. These commands preview the existing targets:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\pcr.ps1 -WhatIf
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\pcra.ps1 -WhatIf
```

`pcr.ps1` selects privileged/high-exposure users; `pcra.ps1` selects administrator accounts. Both support `-ExcludeUsers`, `-OutFile`, `-IncludeSPNAccounts`, and `-ForceChangeAtLogon`, and can prompt for confirmation. Defaults skip `krbtgt`, the current username, disabled users, and SPN accounts. Omitting `-WhatIf` permits actual resets. English group lookups can fail; review warnings. Applying runs write **plaintext**, headerless TXT password records to `C:\Secure\pwreset_<timestamp>.txt` or `C:\Secure\admin_pwreset_<timestamp>.txt`. Use a unique `-OutFile`; the chosen file is initialized with overwrite behavior. Protect these files and do not commit them.

### Restore a known baseline

From the same Tausetii repository. Requires ActiveDirectory and reset/unlock rights. Supply either a properly formatted `Username,Password` baseline CSV or a `Username` reset-log CSV plus a secure baseline password:

```powershell
.\restore_passwords.ps1 -BaselineCsv 'C:\Secure\baseline.csv' -WhatIf
$baseline = Read-Host 'Known baseline password' -AsSecureString
.\restore_passwords.ps1 -ResetLog 'C:\Secure\reset-targets.csv' -BaselinePassword $baseline -WhatIf
```

The default reset TXT files are not directly compatible; changing their extension is insufficient. Without `-ResetLog`, single-password mode searches `C:\Secure\pwreset_*.csv`. `-BaselinePassword` is mandatory in that mode; `-BaselineCsv` is mandatory in per-user mode. Applying restore resets to known values and attempts to unlock accounts; `-ClearForceChange` also clears forced password changes. It cannot recover unknown old passwords and writes console output rather than an inventory report.

### OpenSSH setup

From [nosodium/yesodium](https://github.com/nosodium/yesodium). No script parameters or `-WhatIf` support. This command applies changes:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WIN_SSH.ps1
```

Requires administrator privileges and Windows PowerShell 5.1. Native setup needs an available OpenSSH capability source; legacy x64 setup downloads Win32-OpenSSH from GitHub to `$env:ProgramFiles\OpenSSH`. The script starts/restarts `sshd`, configures automatic startup, enables matched password-authentication directives, disables matched public-key directives, and replaces/adds an all-profile inbound TCP 22 rule. Verify `$env:ProgramData\ssh\sshd_config`; missing directives are not inserted. No hardening scripts are dependencies. Output is console progress; changes are not a read-only audit and do not use the toolkit `Output/` hierarchy.

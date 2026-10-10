# CCDC-Windows Command Cheatsheet

Run these commands from the repository root in Windows PowerShell 5.1. Each script is standalone and writes a unique timestamped report directory.

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

- These scripts do not perform network scans or change system configuration.
- Inventory and audit results may be partial or unavailable under limited privileges; read the terminal warnings and `summary.txt`.
- On domain controllers, `Get-UserAudit.ps1` reports Active Directory limitations when the optional built-in ActiveDirectory module is unavailable.

# Windows CCDC PowerShell Toolkit

A small, specification-driven toolkit for Windows CCDC inventory, auditing, and explicitly requested remediation tasks. Scripts target Windows PowerShell 5.1 and use only built-in Windows capabilities.

## Directory structure

```text
Inventory/    Read-only system inventory scripts
Audit/        Read-only security and configuration audit scripts
Remediation/  Explicitly requested remediation scripts
Tests/        Tests for implemented behavior
```

## Network Inventory v0.1 baseline

The initial tested baseline was executed successfully on a Windows Server 2025 domain controller in Kamino. Testing covered script execution, network configuration collection, TCP listeners, running services, firewall profiles, and successful report generation.

Outstanding validation includes Windows client testing, non-elevated execution, and comprehensive output validation.

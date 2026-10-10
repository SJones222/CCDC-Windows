# Contribution Rules

1. Target Windows PowerShell 5.1 on Windows Server and Windows clients.
2. Use built-in Windows commands, modules, and .NET APIs only. No external dependencies.
3. Every script must run independently without shared modules or network access.
4. Keep inventory and audit scripts read-only. Never mix remediation into them.
5. Do not add features beyond the approved specification.
6. Prefer straightforward, readable PowerShell over elaborate abstractions.
7. Make read-only scripts noninteractive and support partial results under limited privileges.
8. Use concise console summaries and detailed structured output files where specified.
9. Handle errors visibly and distinguish missing data from collection failures.
10. Never hardcode machine names, credentials, or environment-specific paths.
11. Do not change competition-critical services, firewall rules, users, or system settings unless explicitly requested in a separate remediation task.
12. Keep changes small, document assumptions, and add or update tests for implemented behavior.
13. Before adding dependencies or substantially increasing complexity, explain why and request approval.

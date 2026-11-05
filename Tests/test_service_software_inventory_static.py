"""Read-only source/contract checks. Run: python3 -m unittest discover -s Tests -p '*_static.py'.

These are not PowerShell parsing or runtime tests. The companion native test suite
must be run separately in Windows PowerShell 5.1; no third-party packages required.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "Inventory/Get-ServiceSoftwareInventory.ps1").read_text()
SPEC = (ROOT / "docs/SERVICE_SOFTWARE_INVENTORY_SPEC.md").read_text()


def function(name):
    match = re.search(r"^function " + re.escape(name) + r" \{\n(.*?)(?=^function |^try \{ \$result)", SOURCE, re.M | re.S)
    if not match:
        raise AssertionError("Missing function: " + name)
    return match.group(1)


class FoundationSourceTests(unittest.TestCase):
    def test_powershell_51_and_stage_identity(self):
        self.assertTrue(SOURCE.startswith("#requires -Version 5.1\n"))
        for value in ["service-software-inventory", "SchemaVersion = '0.1.0'", "Version = '0.1.0'",
                      "DevelopmentStage = 'Milestone 1.2A'", "ReleaseReady = $false"]:
            self.assertIn(value, SOURCE)
        self.assertNotRegex(SOURCE, r"\?\?|\?\.|ForEach-Object\s+-Parallel|^using namespace")

    def test_service_query_is_single_local_all_states(self):
        query = next(line for line in SOURCE.splitlines() if "Get-CimInstance -ClassName" in line)
        self.assertIn("Win32_Service", query)
        self.assertIn("-OperationTimeoutSec 30", query)
        self.assertNotIn("-Filter", query)
        self.assertNotRegex(SOURCE, r"-(?:ComputerName|CimSession)\b")
        self.assertEqual(SOURCE.count("Get-CimInstance -ClassName"), 1)

    def test_registry_is_machine_only_and_both_explicit_views(self):
        self.assertIn("@('Registry64', 'Registry32')", SOURCE)
        self.assertIn("[Microsoft.Win32.RegistryHive]::LocalMachine", SOURCE)
        self.assertNotIn("CurrentUser", SOURCE)
        self.assertIn("$base.OpenSubKey('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', $false)", SOURCE)
        self.assertIn("OpenSubKey($subkeyName, $false)", SOURCE)
        self.assertIn("DoNotExpandEnvironmentNames", SOURCE)
        self.assertIn("$key.Dispose()", SOURCE)
        self.assertIn("$root.BaseKey.Dispose()", SOURCE)

    def test_no_unapproved_collectors_or_state_changes(self):
        for prohibited in ["Win32_Product", "Win32_Process", "Get-NetTCPConnection", "Get-NetUDPEndpoint",
                           "Get-AuthenticodeSignature", "Get-FileHash", "Set-Acl", "Set-AD", "Set-Service",
                           "Start-Service", "Stop-Service", "Invoke-WebRequest", "DownloadFile", "SetValue(",
                           "Import-Module", "Invoke-Expression", "Start-Process"]:
            self.assertNotIn(prohibited, SOURCE)

    def test_placeholders_do_not_claim_required_process_success(self):
        self.assertIn("@{ Id = 'Processes'; Required = $true }", SOURCE)
        self.assertIn("@{ Id = 'NetworkEndpoints'; Required = $false }", SOURCE)
        self.assertIn("@{ Id = 'ExecutableFiles'; Required = $false }", SOURCE)
        self.assertIn("Unavailable @() @('NotImplemented:", SOURCE)
        self.assertIn("Status = 'Skipped'; ReasonCode = 'SignatureNetworkPolicy'", SOURCE)
        self.assertIn("Status = 'NotPerformed'; Findings = @()", SOURCE)

    def test_structured_issues_and_sanitized_messages(self):
        issue = function("Add-InventoryIssue")
        for field in ["DatasetId", "Stage", "Code", "Message"]:
            self.assertIn(field + " =", issue)
        self.assertNotIn("Exception.Message", SOURCE)
        self.assertNotIn("Write-Error $_", SOURCE)
        self.assertIn("$script:CollectionIssues.Add", issue)
        self.assertIn("$script:OutputIssues.Add", issue)

    def test_collection_error_identity_is_preserved_and_sanitized(self):
        classifier = function("Get-CollectionFailure")
        for identity in ["UnauthorizedAccessException", "SecurityException", "CommandNotFoundException",
                         "PlatformNotSupportedException", "NativeErrorCode", "InnerException"]:
            self.assertIn(identity, classifier)
        for code in ["AccessDenied", "CapabilityMissing", "QueryFailed"]:
            self.assertIn("'" + code + "'", classifier)
        self.assertNotIn(".Message", classifier)
        for collector in ["Get-ServiceDataset", "Get-SoftwareDataset", "Read-SoftwareRegistration"]:
            body = function(collector)
            self.assertIn("Get-CollectionFailure $_", body)
            self.assertIn("$problem.Code $problem.Message", body)
        self.assertIn("$openError = $_", function("Get-SoftwareDataset"))
        self.assertIn("$key $openError", function("Get-SoftwareDataset"))
        self.assertIn("throw $OpenError", function("Read-SoftwareRegistration"))

    def test_arrays_and_counts_are_explicit(self):
        dataset = function("New-InventoryDataset")
        self.assertIn("$retained = [object[]]@()", dataset)
        self.assertIn("Items = $retained", dataset)
        self.assertRegex(dataset, r"Count = if .*'Unavailable', 'Failed'.*\{ \$null \}")

    def test_required_only_aggregation_and_four_exit_codes(self):
        aggregate = function("Get-AggregateStatus")
        self.assertIn("Where-Object { $_.Required }", aggregate)
        self.assertLess(aggregate.index("'Success', 'Partial'"), aggregate.index("$_.Status -eq 'Failed'"))
        exits = function("Get-InventoryExitCode")
        self.assertIn("if (-not $ReportsSaved) { return 3 }", exits)
        for fragment in ["'Success' { return 0 }", "'Failed' { return 1 }", "default { return 2 }"]:
            self.assertIn(fragment, exits)

    def test_csv_columns_match_approved_spec_and_exclude_raw(self):
        publisher = function("Publish-InventoryReports")
        for name, variable in [("services.csv", "serviceColumns"), ("software.csv", "softwareColumns")]:
            actual = re.search(r"\$" + variable + r" = '([^']+)'\.Split", publisher).group(1)
            line = next(row for row in SPEC.splitlines() if row.startswith("| `" + name + "` |"))
            expected = line.split("|")[2].strip().strip("`")
            self.assertEqual(actual, expected)
            self.assertNotIn("RawCommandLine", actual.split(","))
        self.assertNotIn("RawCommandLine", function("Get-ServiceSoftwareSummary"))

    def test_acl_policy_rejects_uncertainty_without_changes(self):
        policy = function("Test-RestrictedDescriptor")
        for fragment in ["Descriptor.Owner", "DiscretionaryAclPresent", "$ace.IsCallback", "trustedSids -notcontains"]:
            self.assertIn(fragment, policy)
        self.assertIn("'S-1-5-18', 'S-1-5-32-544'", SOURCE)
        self.assertIn("GetSecurityDescriptorBinaryForm()", SOURCE)
        self.assertNotIn(".Translate(", SOURCE)
        self.assertNotIn("SetAccessRule", SOURCE)
        self.assertNotIn("SetAccessControl", SOURCE)

    def test_windows_servicing_trust_is_ancestor_only(self):
        policy = function("Test-RestrictedDescriptor")
        self.assertIn("$trustedSids = @($AllowedSids)", policy)
        self.assertRegex(policy, r"if \(\$Ancestor\) \{\s*(?:#[^\n]*\n\s*)*\$trustedSids \+= 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'")
        self.assertIn("$trustedSids -contains $ace.SecurityIdentifier.Value", policy)
        self.assertNotIn("$AllowedSids +=", policy)
        actual_reports = function("Assert-ProtectedReportPath")
        self.assertIn("Test-RestrictedDescriptor $descriptor $AllowedSids)", actual_reports)
        self.assertNotIn("Test-RestrictedDescriptor $descriptor $AllowedSids -Ancestor", actual_reports)

    def test_no_reparse_or_network_report_paths(self):
        local = function("Test-LocalNonReparsePath")
        self.assertIn("DriveType]::Fixed", local)
        self.assertIn("FileAttributes]::ReparsePoint", local)
        self.assertIn("foreach ($part in $parts)", local)
        self.assertIn("GetUnresolvedProviderPathFromPSPath", SOURCE)
        self.assertIn("$cursor -ne $Path", local)

    def test_enum_bitwise_operands_are_integers_for_powershell_51(self):
        enum_masks = [line for line in SOURCE.splitlines()
                      if '-band' in line and re.search(r'\[(?:IO\.FileAttributes|System\.Security\.AccessControl\.(?:AceFlags|ControlFlags))\]::', line)]
        self.assertEqual(len(enum_masks), 6)
        for line in enum_masks:
            self.assertRegex(line, r'\[int\]\$(?:attributes|Descriptor\.ControlFlags|ace\.AceFlags)\s+-band\s+\[int\]\[')

    def test_ancestor_replacement_checks_keep_data_allowlist_strict(self):
        policy = function("Test-RestrictedDescriptor")
        self.assertIn("[switch]$Ancestor", policy)
        self.assertIn("$inheritOnly -and $ace.SecurityIdentifier.Value -eq 'S-1-3-0'", policy)
        # DELETE, DELETE_CHILD, WRITE_DAC, WRITE_OWNER, GENERIC_ALL/WRITE.
        self.assertIn("$ace.AccessMask -band 0x500D0040", policy)
        ancestor = function("Assert-ReportAncestors")
        for fragment in ["GetParent($Path)", "$cursor = $cursor.Parent", "Get-Acl -LiteralPath",
                         "Test-RestrictedDescriptor $descriptor $AllowedSids -Ancestor", "FileAttributes]::ReparsePoint"]:
            self.assertIn(fragment, ancestor)
        self.assertIn("Assert-ReportAncestors $Path $AllowedSids", function("Assert-ProtectedReportPath"))
        location = function("New-ProtectedReportLocation")
        self.assertLess(location.index("Assert-ReportAncestors"), location.index("Directory]::CreateDirectory"))

    def test_preflight_precedes_sensitive_collection(self):
        main = function("Invoke-ServiceSoftwareInventory")
        self.assertLess(main.index("New-ProtectedReportLocation"), main.index("Get-ServiceDataset"))
        self.assertLess(main.index("no collection started"), main.index("Get-ServiceDataset"))
        location = function("New-ProtectedReportLocation")
        self.assertIn("FileMode]::CreateNew", location)
        self.assertIn("Assert-ProtectedReportPath $path", location)

    def test_json_last_nonoverwriting_publication_and_external_checks(self):
        publish = function("Publish-InventoryReports")
        self.assertIn("@($contents.Keys) + @('service-software.json')", publish)
        self.assertIn("[IO.File]::Move($temporaryPath, $finalPath)", publish)
        self.assertIn("ConvertFrom-Json -ErrorAction Stop", publish)
        self.assertIn("foreach ($name in $Report.Output.Files)", publish)
        self.assertIn("$published.RunId -ne $Report.RunId", publish)
        self.assertNotIn("-Force", publish)

    def test_success_is_not_published_in_supporting_summary_or_live_state_early(self):
        publish = function("Publish-InventoryReports")
        # Candidate JSON has its own Output dictionary, not an alias of live Output.
        self.assertIn("$candidate.Output = [ordered]@{}", publish)
        self.assertIn("$candidate.Output.Status = 'Success'", publish)
        self.assertIn("$Report.Output.Status = 'Failed'", publish)
        self.assertEqual(publish.count("$Report.Output.Status = 'Success'"), 1)
        self.assertLess(publish.index("throw 'ReportIdentityMismatch'"), publish.index("$Report.Output.Status = 'Success'"))
        self.assertLess(publish.index("OpenRead($temporaryPath)"), publish.index("File]::Move"))
        self.assertIn("OpenRead($finalPath)", publish)
        summary = function("Get-ServiceSoftwareSummary")
        self.assertIn("not certified by this supporting report", summary)
        self.assertIn("else { $lines.Add('Report-save status: ' + $Report.Output.Status) }", summary)
        self.assertIn("matching RunId in service-software.json", summary)

    def test_cleanup_only_tracks_created_files_and_checks_protection(self):
        cleanup = function("Remove-IncompleteReportFiles")
        self.assertIn("$Location.CreatedPaths.ToArray()", cleanup)
        self.assertIn("Assert-ProtectedReportPath $path", cleanup)
        self.assertIn("[IO.File]::Delete($path)", cleanup)
        self.assertIn("[array]::Reverse($paths)", cleanup)
        self.assertNotIn("-Recurse", SOURCE)
        self.assertNotIn("Directory]::Delete", SOURCE)

    def test_fallback_is_not_recollection_and_only_stage_files_are_declared(self):
        main = function("Invoke-ServiceSoftwareInventory")
        self.assertEqual(main.count("Get-ServiceDataset"), 1)
        self.assertEqual(main.count("Get-SoftwareDataset"), 1)
        self.assertIn("if (-not $report.Output.FallbackUsed)", main)
        self.assertIn("Files = @('summary.txt', 'services.csv', 'software.csv', 'service-software.json')", main)
        for filename in ["network-endpoints.csv", "processes.csv", "files.csv"]:
            self.assertNotIn(filename, SOURCE)

    def test_native_suite_has_explicit_windows_host_and_51_constraints(self):
        suite = (ROOT / "Tests/Test-ServiceSoftwareInventory.ps1").read_text()
        self.assertTrue(suite.startswith("#requires -Version 5.1\n"))
        self.assertIn("[PlatformID]::Win32NT", suite)
        self.assertIn("[Environment]::Is64BitOperatingSystem", suite)
        self.assertNotRegex(suite, r"\?\?|\?\.|ForEach-Object\s+-Parallel|^using namespace")
        self.assertIn("Parser]::ParseFile", suite)
        self.assertNotRegex(suite, r"(?m)^\s*\.\s+\$source")


if __name__ == "__main__":
    unittest.main()

"""Source/contract checks only; these do not parse or execute PowerShell."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "Inventory/Get-NetworkRelationships.ps1").read_text()
SPEC = (ROOT / "docs/NETWORK_RELATIONSHIPS_SPEC.md").read_text()
SUITE = (ROOT / "Tests/Test-NetworkRelationships.ps1").read_text()
PREVIOUS = (ROOT / "Inventory/Get-ServiceSoftwareInventory.ps1").read_text()


def function(name, text=SOURCE):
    match = re.search(r"^function " + re.escape(name) + r" \{\n.*?(?=^function |^try \{ \$result|\Z)", text, re.M | re.S)
    if not match:
        raise AssertionError("Missing function: " + name)
    return match.group().strip()


class NetworkRelationshipsSourceTests(unittest.TestCase):
    def test_identity_and_51_surface(self):
        self.assertTrue(SOURCE.startswith("#requires -Version 5.1\n"))
        for value in ["ModuleId = 'network-relationships'", "SchemaVersion = '0.1.0'",
                      "Version = '0.1.0'", "ReleaseReady = $false", "DevelopmentStage = 'Milestone 1.3'"]:
            self.assertIn(value, SOURCE)
        self.assertIn("param([string]$OutputDir)", SOURCE)
        self.assertNotRegex(SOURCE, r"\?\?|\?\.|ForEach-Object\s+-Parallel|^using namespace")

    def test_only_approved_local_sources(self):
        queries = function("Get-NetworkDataset")
        for query in ["Get-NetTCPConnection -State Established", "Get-NetIPAddress -AddressFamily $sourceId",
                      "Get-NetIPInterface -AddressFamily $sourceId", "Get-DnsClientServerAddress -AddressFamily $sourceId",
                      "Get-NetRoute -AddressFamily $sourceId -PolicyStore ActiveStore"]:
            self.assertIn(query, queries)
        for prohibited in ["Get-NetUDPEndpoint", "Get-NetTCPConnection -State Listen", "Get-NetNeighbor",
                           "Resolve-DnsName", "Test-NetConnection", "Test-Connection", "GetHostEntry", "GetHostAddresses",
                           "Win32_Product", "Win32_NetworkAdapter", "Get-AuthenticodeSignature", "Get-FileHash",
                           "CommandLine", "ExecutablePath", "Invoke-WebRequest", "New-CimSession", "Start-Process",
                           "Invoke-Expression", "Set-Acl", "Set-Service", "Get-NetFirewall", "Import-Module"]:
            self.assertNotIn(prohibited, SOURCE)
        self.assertNotRegex(SOURCE, r"-(?:ComputerName|CimSession|IncludeAllCompartments)\b")

    def test_exact_schemas_csvs_and_nine_files(self):
        layout = function("Get-RelationshipReportLayout")
        datasets = re.findall(r"^        (\w+) = @\{ File = '([^']+)'; Columns = '([^']+)'", layout, re.M)
        self.assertEqual(len(datasets), 7)
        for dataset, name, columns in datasets:
            row = next(line for line in SPEC.splitlines() if line.startswith("| `" + name + "` |"))
            self.assertEqual(columns, row.split("|")[2].strip().strip("`"))
            schema = next(line.split("|")[2].strip().strip("`") for line in SPEC.splitlines()
                          if line.startswith("| `" + dataset + "` | `Id:"))
            fields = re.findall(r"(?:^|,)([A-Za-z][A-Za-z0-9]*):", schema) + ["RecordStatus"]
            self.assertEqual(columns.split(","), fields)
        names = function("Get-RelationshipReportNames")
        self.assertIn("'summary.txt'", names)
        self.assertIn("'network-relationships.json'", names)

    def test_scalar_reader_preserves_types_and_rejects_arrays(self):
        reader = function("Read-ObservedProperty")
        self.assertEqual(reader, function("Read-ObservedProperty", PREVIOUS))
        self.assertIn("ProviderScalarExpected", reader)
        self.assertIn("$value -is [Enum]", function("Read-NetworkField"))

    def test_scope_normalization_does_not_resolve_names(self):
        parser = function("ConvertTo-NumericAddress")
        for value in ["[Net.IPAddress]::TryParse", "[uint32]::TryParse", "IsIPv4MappedToIPv6", "MapToIPv4()",
                      "IsIPv6LinkLocal", "IsIPv6SiteLocal", "[Net.IPAddress]::IsLoopback", "ScopeId = $scope"]:
            self.assertIn(value, parser)
        self.assertLess(parser.index("if ($Text.Contains('%'))"), parser.index("[Net.IPAddress]::TryParse"))
        self.assertIn("$scope = $null", parser)
        self.assertNotIn("$env:", parser)

    def test_relationship_classification_is_conservative(self):
        classifier = function("Set-ConnectionRelationships")
        for value in ["AmbiguousScope", "LoopbackRemote", "EqualEndpointAddresses", "RemoteMatchesLocalAddress",
                      "LocalCoverageIncomplete", "LocalContextUnknown", "RemoteOutsideObservedLocalSet"]:
            self.assertIn(value, classifier)
        self.assertLess(classifier.index("$Addresses.Status -ne 'Success'"), classifier.index("$item.Relationship = 'CrossMachineObserved'"))
        self.assertIn("$localZone -ne $remoteZone", classifier)
        self.assertIn("$indices.Count -ne 1", classifier)
        self.assertIn("$broadcasts.ContainsKey($remote.Normalized)", classifier)
        self.assertIn("$item.Initiator = 'Unknown'", function("Convert-NetworkRecord"))

    def test_pid_deduplication_precedes_priority_and_cap(self):
        targets = function("Get-ContextTargets")
        self.assertIn("CrossMachineObserved { 0 } Unknown { 1 } default { 2 }", targets)
        self.assertIn("[Math]::Min($map[$key].Priority, $priority)", targets)
        self.assertIn("Sort-Object Priority, { [uint32]$_.ProcessId }", targets)
        context = function("Get-ConnectionContext")
        self.assertLess(context.index("Get-ContextTargets"), context.index("$offset -ge 128"))
        self.assertIn("$offset += 32", context)
        self.assertIn("foreach ($name in @('Processes', 'Services'))", context)

    def test_targeted_queries_and_explicit_outcomes(self):
        query = function("Invoke-ContextBatch")
        self.assertIn("-Property ProcessId,Name,CreationDate -Filter $filter -OperationTimeoutSec 30", query)
        self.assertIn("-Property Name,DisplayName,State,ProcessId -Filter", query)
        self.assertEqual(query.count("Get-CimInstance -ClassName"), 2)
        for outcome in ["NotReturned", "NoObservedMatch", "PartialMetadata", "MatchesReturned"]:
            self.assertIn(outcome, query)
        context = function("Get-ConnectionContext")
        self.assertIn("TargetOutcomes", context)
        self.assertIn("$Budget[$name].SkippedCount += $batch.Count", context)
        self.assertIn("CandidateCount = if ($Connections.Status -eq 'Success')", context)
        self.assertIn("Get-ContextElapsedSeconds $clock) -ge 60", context)

    def test_required_only_status_and_standard_exits_reused(self):
        for name in ["Get-AggregateStatus", "Get-InventoryExitCode", "New-InventoryDataset"]:
            self.assertEqual(function(name), function(name, PREVIOUS))
        self.assertIn("($Id -in @('TCPConnections', 'LocalAddresses'))", function("Get-NetworkDataset"))

    def test_error_identity_and_timeout_are_sanitized(self):
        error = function("Get-CollectionFailure")
        for value in ["InnerException", "AccessDenied", "CapabilityMissing", "QueryTimeout", "TimeoutException"]:
            self.assertIn(value, error)
        self.assertNotIn("Exception.Message", SOURCE)
        self.assertNotIn("Write-Error $_", SOURCE)
        no_match = function("Get-NetworkDataset")
        self.assertIn("FullyQualifiedErrorId.Split(',')[0]", no_match)
        self.assertIn("CategoryInfo.Category -eq 'ObjectNotFound'", no_match)

    def test_existing_protection_policy_is_copied_without_weakening(self):
        for name in ["Test-LocalNonReparsePath", "Test-RestrictedDescriptor", "Assert-ReportAncestors",
                     "Assert-ProtectedReportPath", "Remove-IncompleteReportFiles", "Write-ProtectedReportText"]:
            self.assertEqual(function(name), function(name, PREVIOUS))
        entry = function("Invoke-NetworkRelationships")
        self.assertLess(entry.index("New-ProtectedReportLocation"), entry.index("Get-NetworkDataset TCPConnections"))
        self.assertIn("if ($null -eq $location)", entry)
        self.assertIn("no collection started", entry)

    def test_denied_identity_reads_do_not_become_unexpected_query_failures(self):
        classifier = function("Get-RecordFailureStatus")
        self.assertIn("@('AccessDenied', 'CapabilityMissing')", classifier)
        self.assertIn("return 'Unavailable'", classifier)
        self.assertIn("Get-RecordFailureStatus $issueStart", function("Get-NetworkDataset"))
        batch = function("Invoke-ContextBatch")
        self.assertIn("else { $parseStatus }", batch)
        self.assertIn("Failed = $parseStatus -eq 'Failed'", batch)

    def test_json_last_publication_retains_failed_live_status_until_verified(self):
        publisher = function("Publish-InventoryReports")
        self.assertIn("$Report.Output.Status = 'Failed'", publisher)
        self.assertIn("$candidate.Output.Status = 'Success'", publisher)
        self.assertIn("@($contents.Keys) + @('network-relationships.json')", publisher)
        self.assertIn("[IO.File]::Move($temporaryPath, $finalPath)", publisher)
        self.assertLess(publisher.index("throw 'ReportIdentityMismatch'"), publisher.index("$Report.Output.Status = 'Success'"))

    def test_output_layout_fallback_and_summary_limits(self):
        entry = function("Invoke-NetworkRelationships")
        for value in ["CCDC-NetworkRelationships", "'Inventory'", "'AGENTS.md'", "'README.md'", "Join-Path $PSScriptRoot 'Output'"]:
            self.assertIn(value, entry)
        self.assertIn("'NetworkRelationships_'", function("New-ProtectedReportLocation"))
        summary = function("Get-NetworkRelationshipSummary")
        self.assertIn("if ($Detailed) { 50 } else { 20 }", summary)
        self.assertIn("pending final verification", summary)
        self.assertIn("Initiator unknown", summary)

    def test_csv_arrays_are_json_and_empty_files_have_headers(self):
        csv = function("Convert-InventoryCsv")
        for name in ["RelatedServiceIds", "ConnectionIds", "InterfaceIds", "LocalAddressIds", "LocalInterfaceIds", "ServerAddresses"]:
            self.assertIn("'" + name + "'", csv)
        self.assertIn("ConvertTo-Json -InputObject @($item.$column) -Compress", csv)
        self.assertIn("if ($Items.Count -eq 0)", csv)

    def test_native_suite_is_synthetic_and_contains_priority_regressions(self):
        self.assertTrue(SUITE.startswith("#requires -Version 5.1\n"))
        for value in ["Parser]::ParseFile", "function script:Get-CimInstance", "function script:Get-NetTCPConnection",
                      "New-Connection 9000", "129", "Get-AggregateStatus", "RawSecurityDescriptor"]:
            self.assertIn(value, SUITE)
        names = re.findall(r"(?m)^    Run-Test '([^']+)'", SUITE)
        self.assertGreaterEqual(len(names), 40)
        self.assertEqual(len(names), len(set(names)))
        self.assertNotRegex(SUITE, r"(?m)^\s*\.\s+\$source")

    def test_windows_linux_boundary_is_explicit(self):
        for value in ["Windows and Linux", "Linux collection", "cross-host correlation", "dependency assessment",
                      "Approved for implementation", "CrossMachineObserved first, Unknown second"]:
            self.assertIn(value, SPEC)


if __name__ == "__main__":
    unittest.main()

<#
.SYNOPSIS
  Read-only Windows Code Integrity / App Control diagnosis for HIP startup.
.DESCRIPTION
  Captures active policy output and correlated Code Integrity events.
  Does NOT change policies, SAC, registry, EFI, or drivers.
  Raw XML may contain personal paths; review and redact before sharing.
.EXAMPLE
  pwsh -File .\tests\collect-windows-app-control-evidence.ps1 -Hours 12 -OutputDirectory C:\dev\yue2-hip-nightly\qa\codeintegrity
#>
[CmdletBinding()]
param(
    [ValidateRange(1,168)][int]$Hours = 24,
    [string]$OutputDirectory = (Join-Path (Get-Location).Path 'qa\codeintegrity'),
    [string]$ImagePattern = 'yue-server\.exe|ggml[-_.a-zA-Z0-9]*\.dll'
)
$ErrorActionPreference = 'Stop'
$dir = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$ciTool = Get-Command 'citool.exe' -ErrorAction SilentlyContinue
if ($ciTool) {
    $policyText = (& $ciTool.Source -lp 2>&1 | Out-String)
    $policyText | Set-Content -LiteralPath (Join-Path $dir 'active-policy-list.txt') -Encoding UTF8
} else {
    'CiTool.exe unavailable; collect active policy list manually with citool.exe -lp.' |
        Set-Content -LiteralPath (Join-Path $dir 'active-policy-list.txt') -Encoding UTF8
}

$logName = 'Microsoft-Windows-CodeIntegrity/Operational'
# 3076 = audit would-block; 3077 = enforcement block; 3089 = signer
# correlation; 3033 may occur without App Control; 3099 = policy loaded.
$ids = @(3033,3034,3076,3077,3089,3099,3118)
$since = (Get-Date).AddHours(-$Hours)
try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = $logName
        StartTime = $since
        Id = $ids
    } -MaxEvents 5000 -ErrorAction Stop)
} catch {
    throw "Unable to read $logName: $($_.Exception.Message). No security policy changed."
}

$targetIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$targetRecords = [System.Collections.Generic.HashSet[long]]::new()
foreach ($event in $events) {
    $xml = $event.ToXml()
    if (([string]$event.Message) -match $ImagePattern -or $xml -match $ImagePattern) {
        [void]$targetRecords.Add([long]$event.RecordId)
        try {
            [xml]$doc = $xml
            $activity = [string]$doc.Event.System.Correlation.ActivityID
            if ($activity) { [void]$targetIds.Add($activity) }
        } catch { }
    }
}
$xmlFolder = Join-Path $dir 'local-raw-xml'
New-Item -ItemType Directory -Force -Path $xmlFolder | Out-Null
$records = @($events | Sort-Object TimeCreated | ForEach-Object {
    $event = $_
    [xml]$doc = $event.ToXml()
    $activity = [string]$doc.Event.System.Correlation.ActivityID
    $direct = $targetRecords.Contains([long]$event.RecordId)
    $correlated = $activity -and $targetIds.Contains($activity) -and $event.Id -in @(3033,3034,3089,3076,3077)
    if ($direct -or $correlated) {
        $file = Join-Path $xmlFolder ("event-$($event.RecordId)-$($event.Id).xml")
        [System.IO.File]::WriteAllText($file, $event.ToXml(), [System.Text.UTF8Encoding]::new($false))
        [pscustomobject]@{
            event_id = [int]$event.Id
            time_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
            activity_id = $activity
            record_id = [long]$event.RecordId
            classification = switch ($event.Id) {
                3076 { 'AUDIT_ONLY' }
                3077 { 'ENFORCED_BLOCK' }
                3033 { 'SIGNING_OR_CIG_ERROR_REQUIRES_CORRELATION' }
                3089 { 'SIGNER_DETAILS_CORRELATED' }
                default { 'CONTEXT' }
            }
            local_xml_file = [IO.Path]::GetFileName($file)
        }
    }
})
$summary = [pscustomobject]@{
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    start_time_utc = $since.ToUniversalTime().ToString('o')
    target_pattern = $ImagePattern
    events_scanned = $events.Count
    matching_or_correlated = $records.Count
    events = $records
    policy_list_file = 'active-policy-list.txt'
    note = '3077 indicates an enforcing policy. The name SAC Evaluation is not sufficient to identify the blocker; compare PolicyId with CiTool. Raw XML is local-only and can include personal paths.'
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dir 'event-summary.json') -Encoding UTF8
Write-Host "Collected $($records.Count) matching/correlated Code Integrity events under $dir."
Write-Host 'READ-ONLY. Review local raw XML and policy list for private paths before sharing.'
if ($records.Count -eq 0) { Write-Warning 'No matching event does not prove the absence of an active execution policy.' }

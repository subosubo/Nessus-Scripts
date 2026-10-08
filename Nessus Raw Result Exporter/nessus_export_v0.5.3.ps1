<#
.SYNOPSIS
    Export Nessus scan reports for all folders or a selected folder, with optional scan-history date filtering.

.DESCRIPTION
    Based on test_v0.3.ps1 and adapted specifically for Tenable Nessus Professional's local API.

    PRODUCT:
      Tenable Nessus Professional using the local API at https://127.0.0.1:8834.
      Scan history is read from GET /scans/{id}; this product does not use the
      Tenable Vulnerability Management cloud GET /scans/{id}/history endpoint.

    Modes:
      1. -All
         Export the latest/current completed result for every scan in every folder.

      2. -FolderName <name>
         Export the latest/current completed result for every scan in one Nessus folder.

      3. Add -EndDate (and optionally -StartDate)
         Switch to history mode. The script inspects current + historical scan runs and exports
         only COMPLETED runs whose scan_end falls within the requested date range.

    ReportType defaults to Both:
      Both = Vulnerability HTML + Compliance HTML + CSV
      VA   = Vulnerability HTML + CSV
      HCR  = Compliance HTML + CSV

    IMPORTANT DATE RULE:
      Date filtering uses scan_end only. A scan that starts inside the range but ends after
      the EndDate is excluded.

.NOTES
    API keys are read from environment variables:
      NESSUS_ACCESS_KEY
      NESSUS_SECRET_KEY

    Example for the current PowerShell session:
      $env:NESSUS_ACCESS_KEY = "<access key>"
      $env:NESSUS_SECRET_KEY = "<secret key>"

    TLS certificate validation is bypassed for the local/self-signed Nessus certificate.
    This is appropriate for a trusted local/lab Nessus instance, not a general production pattern.
#>

[CmdletBinding()]
param (
    [switch]$All,

    [string]$FolderName,

    [string]$StartDate,

    [string]$EndDate,

    [ValidateSet("Both", "VA", "HCR")]
    [string]$ReportType = "Both",

    [Alias("h")]
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# =========================
# Configuration
# =========================
$NessusBaseUrl = "https://127.0.0.1:8834"

# Recommended: keep API keys in environment variables.
# Optional fallback: if you prefer the old test_v0.3 style, paste keys into the two
# Configured* variables below. Leave them blank when using environment variables.
$ConfiguredAccessKey = ""
$ConfiguredSecretKey = ""

$AccessKey = if ($env:NESSUS_ACCESS_KEY) { $env:NESSUS_ACCESS_KEY } else { $ConfiguredAccessKey }
$SecretKey = if ($env:NESSUS_SECRET_KEY) { $env:NESSUS_SECRET_KEY } else { $ConfiguredSecretKey }

# Save exports relative to the directory from which the script is launched.
$DownloadRoot = Join-Path (Get-Location).Path "Nessus Exports"

$ExportPollSeconds   = 2
$ExportTimeoutSeconds = 600

# =========================
# Help
# =========================
function Show-HelpMenu {
    @"
Tenable Nessus Professional Scan Report Exporter

USAGE
  .\nessus_export_v0.5.3.ps1 -All
  .\nessus_export_v0.5.3.ps1 -FolderName <name>
  .\nessus_export_v0.5.3.ps1 -FolderName <name> -StartDate <yyyy-MM-dd> -EndDate <yyyy-MM-dd>
  .\nessus_export_v0.5.3.ps1 -FolderName <name> -EndDate <yyyy-MM-dd>
  .\nessus_export_v0.5.3.ps1 -h

OPTIONS
  -All
      Process every Nessus folder.
      Without a date filter, only the latest/current completed result is exported.

  -FolderName <name>
      Process only the specified Nessus folder (case-insensitive exact match).

  -StartDate <yyyy-MM-dd>
      In history mode, include completed runs that ENDED on or after this date.
      Requires -EndDate.

  -EndDate <yyyy-MM-dd>
      Enables history mode.
      Include completed runs that ENDED on or before this date.
      If -StartDate is omitted, all completed runs up to this date are considered.

  -ReportType Both|VA|HCR
      Both (default) = Vulnerability HTML + Compliance HTML + CSV
      VA             = Vulnerability HTML + CSV
      HCR            = Compliance HTML + CSV

  -h, -Help
      Display this help menu.

OUTPUT LOCATION
  Reports are saved under the CURRENT DIRECTORY from which you launch the script:

      .\Nessus Exports\<FolderName>\<DateRange>\

EXAMPLES
  Export latest/current completed result for every scan:
      .\nessus_export_v0.5.3.ps1 -All

  Export latest/current completed result from one folder:
      .\nessus_export_v0.5.3.ps1 -FolderName "Windows Servers"

  Export initial-assessment runs from one folder:
      .\nessus_export_v0.5.3.ps1 -FolderName "Windows Servers" `
          -StartDate "2026-08-01" -EndDate "2026-09-15"

  Export all completed runs up to a follow-up cut-off date:
      .\nessus_export_v0.5.3.ps1 -FolderName "Windows Servers" `
          -EndDate "2026-09-15"

  Export VA reports only:
      .\nessus_export_v0.5.3.ps1 -FolderName "Network Devices" -ReportType VA

DATE FILTER BEHAVIOUR
  Filtering is based ONLY on scan_end.

  Started before range + ended inside range  = INCLUDED
  Started inside range + ended after range   = EXCLUDED

  No date filter:
      Scan history is NOT traversed.
      Only the latest/current completed result is exported.

  Date filter present:
      Historical runs are read from the history array returned by GET /scans/{id}.
      Each run is then queried using ?history_id=... so filtering uses its exact scan_end.
      Only COMPLETED runs whose scan_end falls in the range are exported.

CREDENTIALS
  The script reads these environment variables:
      NESSUS_ACCESS_KEY
      NESSUS_SECRET_KEY

  For the current PowerShell session:
      `$env:NESSUS_ACCESS_KEY = "<access key>"
      `$env:NESSUS_SECRET_KEY = "<secret key>"

  Alternatively, edit ConfiguredAccessKey and ConfiguredSecretKey in the
  Configuration section of this script (less secure because the keys are stored in plaintext).
"@
}

if ($Help) {
    Show-HelpMenu
    exit 0
}

# =========================
# Validation helpers
# =========================
function Parse-StrictDate {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$ParameterName
    )

    try {
        return [datetime]::ParseExact(
            $Value,
            "yyyy-MM-dd",
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None
        ).Date
    }
    catch {
        throw "$ParameterName must use yyyy-MM-dd format. Received: '$Value'"
    }
}

if ($All -and $FolderName) {
    Write-Host "[ERROR] Use either -All or -FolderName, not both." -ForegroundColor Red
    Write-Host "Use .\nessus_export_v0.5.3.ps1 -h for help."
    exit 1
}

if (-not $All -and [string]::IsNullOrWhiteSpace($FolderName)) {
    Write-Host "[ERROR] Specify either -All or -FolderName." -ForegroundColor Red
    Write-Host "Use .\nessus_export_v0.5.3.ps1 -h for help."
    exit 1
}

if ($StartDate -and -not $EndDate) {
    Write-Host "[ERROR] -StartDate requires -EndDate." -ForegroundColor Red
    Write-Host "Use .\nessus_export_v0.5.3.ps1 -h for help."
    exit 1
}

$HistoryMode = -not [string]::IsNullOrWhiteSpace($EndDate)
$StartDateValue = $null
$EndDateValue = $null
$EndExclusive = $null

try {
    if ($StartDate) {
        $StartDateValue = Parse-StrictDate -Value $StartDate -ParameterName "-StartDate"
    }

    if ($EndDate) {
        $EndDateValue = Parse-StrictDate -Value $EndDate -ParameterName "-EndDate"
        # Inclusive end date: compare against midnight of the following day.
        $EndExclusive = $EndDateValue.AddDays(1)
    }

    if ($StartDateValue -and ($StartDateValue -gt $EndDateValue)) {
        throw "-StartDate cannot be later than -EndDate."
    }
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($AccessKey) -or [string]::IsNullOrWhiteSpace($SecretKey)) {
    Write-Host "[ERROR] Nessus API credentials are not configured." -ForegroundColor Red
    Write-Host "Set NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY environment variables first."
    Write-Host "Run .\nessus_export_v0.5.3.ps1 -h for an example."
    exit 1
}

# =========================
# TLS handling
# =========================
if ($PSVersionTable.PSEdition -ne "Core") {
    try {
        # PowerShell keeps Add-Type classes loaded for the lifetime of the
        # current process.  Re-running the script in the same console can
        # therefore encounter an already-defined class.  Reuse it if present.
        $trustAllType = "NessusTrustAllCertsPolicy" -as [type]

        if ($null -eq $trustAllType) {
            Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;

public class NessusTrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint,
        X509Certificate certificate,
        WebRequest request,
        int certificateProblem) {
        return true;
    }
}
"@ -ErrorAction Stop

            $trustAllType = "NessusTrustAllCertsPolicy" -as [type]
        }

        if ($null -eq $trustAllType) {
            throw "Certificate policy class could not be loaded."
        }

        [System.Net.ServicePointManager]::CertificatePolicy = New-Object NessusTrustAllCertsPolicy

        # Nessus Professional normally negotiates TLS 1.2 on current releases.
        # Explicitly enable it for older Windows PowerShell/.NET defaults.
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -bor `
            [System.Net.SecurityProtocolType]::Tls12

        Write-Host "[*] TLS certificate validation disabled (Windows PowerShell)." -ForegroundColor Yellow
    }
    catch {
        Write-Host "[ERROR] Failed to configure TLS certificate bypass." -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkRed
        exit 1
    }
}

# =========================
# Authentication
# =========================
$headers = @{
    "X-ApiKeys" = "accessKey=$AccessKey; secretKey=$SecretKey;"
    "Accept"    = "application/json"
}

# =========================
# Utility functions
# =========================
function Get-WebCommonParameters {
    $p = @{}
    if ($PSVersionTable.PSEdition -eq "Core") {
        $p["SkipCertificateCheck"] = $true
    }
    return $p
}

function Invoke-NessusGet {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $params = @{
        Method  = "Get"
        Uri     = $Uri
        Headers = $headers
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        $params["SkipCertificateCheck"] = $true
    }

    try {
        return Invoke-RestMethod @params
    }
    catch {
        throw "GET failed: $Uri`n$($_.Exception.Message)"
    }
}

function Invoke-NessusPostJson {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Body
    )

    $params = @{
        Method      = "Post"
        Uri         = $Uri
        Headers     = $headers
        Body        = ($Body | ConvertTo-Json -Depth 5)
        ContentType = "application/json"
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        $params["SkipCertificateCheck"] = $true
    }

    try {
        return Invoke-RestMethod @params
    }
    catch {
        throw "POST failed: $Uri`n$($_.Exception.Message)"
    }
}

function Invoke-NessusDownload {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$OutFile
    )

    $params = @{
        Uri     = $Uri
        Headers = $headers
        OutFile = $OutFile
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        $params["SkipCertificateCheck"] = $true
    }
    else {
        $params["UseBasicParsing"] = $true
    }

    try {
        Invoke-WebRequest @params | Out-Null
    }
    catch {
        throw "Download failed: $Uri`n$($_.Exception.Message)"
    }
}

function Convert-ToSafeFileName {
    param ([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return "unnamed_scan"
    }

    return ($Name -replace '[\\/:*?"<>|]', '_').Trim()
}

function Convert-ToLocalDateTime {
    param ($Value)

    if ($null -eq $Value -or "$Value" -eq "") {
        return $null
    }

    # Unix timestamp (seconds)
    $numericValue = 0L
    if ([int64]::TryParse("$Value", [ref]$numericValue)) {
        try {
            return [DateTimeOffset]::FromUnixTimeSeconds($numericValue).ToLocalTime().DateTime
        }
        catch {
            return $null
        }
    }

    # ISO/date string fallback
    $dto = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse("$Value", [ref]$dto)) {
        return $dto.ToLocalTime().DateTime
    }

    return $null
}

function Test-DateInRange {
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$RunEnd
    )

    if ($StartDateValue -and ($RunEnd -lt $StartDateValue)) {
        return $false
    }

    if ($EndExclusive -and ($RunEnd -ge $EndExclusive)) {
        return $false
    }

    return $true
}

function New-OutputDirectory {
    param (
        [string]$ScopeName
    )

    $safeScope = Convert-ToSafeFileName $ScopeName

    if ($HistoryMode) {
        $rangeName = if ($StartDateValue) {
            "{0}_to_{1}" -f $StartDateValue.ToString("yyyy-MM-dd"), $EndDateValue.ToString("yyyy-MM-dd")
        }
        else {
            "Up_to_{0}" -f $EndDateValue.ToString("yyyy-MM-dd")
        }
    }
    else {
        $rangeName = "Latest"
    }

    $path = Join-Path (Join-Path $DownloadRoot $safeScope) $rangeName
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

# =========================
# Nessus export function
# =========================
function Export-NessusScan {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ScanId,

        [Parameter(Mandatory = $true)]
        [string]$Format,

        [Parameter(Mandatory = $true)]
        [string]$OutFile,

        [string]$Chapters,

        [Nullable[int]]$HistoryId
    )

    $body = @{ format = $Format }

    if (($Format -eq "html") -or ($Format -eq "pdf")) {
        if ($Chapters) {
            $body["chapters"] = $Chapters
        }
    }

    $exportUri = "${NessusBaseUrl}/scans/${ScanId}/export"
    if ($null -ne $HistoryId) {
        $exportUri += "?history_id=$HistoryId"
    }

    try {
        $export = Invoke-NessusPostJson -Uri $exportUri -Body $body
        $fileId = $export.file

        if ($null -eq $fileId) {
            throw "Nessus did not return an export file ID."
        }

        $statusUri = "${NessusBaseUrl}/scans/${ScanId}/export/${fileId}/status"
        $downloadUri = "${NessusBaseUrl}/scans/${ScanId}/export/${fileId}/download"

        $deadline = (Get-Date).AddSeconds($ExportTimeoutSeconds)

        while ($true) {
            if ((Get-Date) -gt $deadline) {
                throw "Timed out waiting for export after $ExportTimeoutSeconds seconds."
            }

            Start-Sleep -Seconds $ExportPollSeconds
            $check = Invoke-NessusGet -Uri $statusUri
            $status = "$($check.status)".ToLowerInvariant()

            if ($status -eq "ready") {
                break
            }

            if ($status -in @("error", "failed", "cancelled", "canceled")) {
                throw "Export entered failure status '$status'."
            }
        }

        Invoke-NessusDownload -Uri $downloadUri -OutFile $OutFile
        Write-Host "      [OK] $(Split-Path $OutFile -Leaf)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "      [FAIL] $(Split-Path $OutFile -Leaf)" -ForegroundColor Red
        Write-Host "             $($_.Exception.Message)" -ForegroundColor DarkRed
        return $false
    }
}

function Export-ReportSet {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ScanId,

        [Parameter(Mandatory = $true)]
        [string]$ScanName,

        [Parameter(Mandatory = $true)]
        [string]$OutputFolder,

        [Nullable[int]]$HistoryId,

        [Nullable[datetime]]$RunEnd
    )

    $safeScanName = Convert-ToSafeFileName $ScanName

    if ($null -ne $RunEnd) {
        $baseName = "{0}_{1}" -f $safeScanName, $RunEnd.ToString("yyyy-MM-dd_HHmmss")
    }
    else {
        $baseName = $safeScanName
    }

    $success = 0
    $failed = 0

    if ($ReportType -in @("Both", "VA")) {
        $ok = Export-NessusScan -ScanId $ScanId -Format "html" -Chapters "vuln_by_plugin" `
            -HistoryId $HistoryId -OutFile (Join-Path $OutputFolder "$baseName-vuln.html")
        if ($ok) { $success++ } else { $failed++ }
    }

    if ($ReportType -in @("Both", "HCR")) {
        $ok = Export-NessusScan -ScanId $ScanId -Format "html" -Chapters "compliance_exec" `
            -HistoryId $HistoryId -OutFile (Join-Path $OutputFolder "$baseName-compliance.html")
        if ($ok) { $success++ } else { $failed++ }
    }

    # CSV is always exported because it contains the raw findings used by the follow-on filter script.
    $ok = Export-NessusScan -ScanId $ScanId -Format "csv" `
        -HistoryId $HistoryId -OutFile (Join-Path $OutputFolder "$baseName-results.csv")
    if ($ok) { $success++ } else { $failed++ }

    return [pscustomobject]@{
        Success = $success
        Failed  = $failed
    }
}

# =========================
# History functions
# =========================
function Get-AllScanHistory {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ScanId
    )

    # Tenable Nessus Professional:
    # GET /scans/{id} returns the scan results and embeds all saved runs in
    # the top-level "history" array.  The cloud-only
    # GET /scans/{id}/history endpoint returns HTTP 405 on Nessus Professional.
    $details = Invoke-NessusGet -Uri "${NessusBaseUrl}/scans/${ScanId}"

    if ($null -eq $details.history) {
        return @()
    }

    $results = New-Object System.Collections.ArrayList
    $seenIds = @{}

    foreach ($item in @($details.history)) {
        $id = $null

        if ($null -ne $item.history_id) {
            $id = [int]$item.history_id
        }
        elseif ($null -ne $item.id) {
            $id = [int]$item.id
        }

        if ($null -eq $id) {
            continue
        }

        if (-not $seenIds.ContainsKey("$id")) {
            $seenIds["$id"] = $true
            [void]$results.Add($item)
        }
    }

    return @($results)
}

function Get-HistoryRunMetadata {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ScanId,

        [Parameter(Mandatory = $true)]
        $HistoryEntry
    )

    $historyId = $null

    if ($null -ne $HistoryEntry.history_id) {
        $historyId = [int]$HistoryEntry.history_id
    }
    elseif ($null -ne $HistoryEntry.id) {
        $historyId = [int]$HistoryEntry.id
    }

    if ($null -eq $historyId) {
        return $null
    }

    $status = "$($HistoryEntry.status)".ToLowerInvariant()

    # For Nessus Professional, get the exact saved run so that the date
    # decision is based on info.scan_end, not creation_date or an estimate.
    try {
        $details = Invoke-NessusGet -Uri "${NessusBaseUrl}/scans/${ScanId}?history_id=${historyId}"
    }
    catch {
        Write-Host "      [WARN] Unable to retrieve details for history ID $historyId." -ForegroundColor Yellow
        Write-Host "             $($_.Exception.Message)" -ForegroundColor DarkYellow
        return $null
    }

    if ($null -ne $details.info.status) {
        $status = "$($details.info.status)".ToLowerInvariant()
    }

    $runEndRaw = $null

    if ($null -ne $details.info.scan_end) {
        $runEndRaw = $details.info.scan_end
    }
    elseif ($null -ne $details.info.timestamp) {
        # Nessus commonly exposes timestamp as the completed-run timestamp too.
        # Use it only when scan_end is absent.
        $runEndRaw = $details.info.timestamp
    }

    $runEnd = Convert-ToLocalDateTime $runEndRaw

    return [pscustomobject]@{
        HistoryId = $historyId
        Status    = $status
        RunEnd    = $runEnd
        IsLatest  = $false
    }
}

function Get-LatestRunMetadata {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ScanId
    )

    try {
        $details = Invoke-NessusGet -Uri "${NessusBaseUrl}/scans/${ScanId}"
    }
    catch {
        Write-Host "      [WARN] Unable to retrieve latest scan details." -ForegroundColor Yellow
        Write-Host "             $($_.Exception.Message)" -ForegroundColor DarkYellow
        return $null
    }

    $status = "$($details.info.status)".ToLowerInvariant()

    $runEndRaw = $null
    if ($null -ne $details.info.scan_end) {
        $runEndRaw = $details.info.scan_end
    }
    elseif ($null -ne $details.info.timestamp) {
        $runEndRaw = $details.info.timestamp
    }

    $historyId = $null
    if ($null -ne $details.info.history_id) {
        $historyId = [int]$details.info.history_id
    }

    return [pscustomobject]@{
        HistoryId = $historyId
        Status    = $status
        RunEnd    = (Convert-ToLocalDateTime $runEndRaw)
        IsLatest  = $true
    }
}

function Get-QualifyingRuns {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ScanId
    )

    $qualified = New-Object System.Collections.ArrayList
    $seenHistoryIds = @{}

    $historyEntries = Get-AllScanHistory -ScanId $ScanId
    Write-Host "    History entries found: $(@($historyEntries).Count)" -ForegroundColor DarkGray

    foreach ($entry in $historyEntries) {
        $run = Get-HistoryRunMetadata -ScanId $ScanId -HistoryEntry $entry
        if ($null -eq $run) {
            continue
        }

        if ($run.Status -ne "completed") {
            continue
        }

        if ($null -eq $run.RunEnd) {
            Write-Host "      [SKIP] History ID $($run.HistoryId): no scan_end available." -ForegroundColor DarkYellow
            continue
        }

        if (-not (Test-DateInRange -RunEnd $run.RunEnd)) {
            continue
        }

        $seenHistoryIds["$($run.HistoryId)"] = $true
        [void]$qualified.Add($run)
    }

    # Explicitly inspect the latest/current result too. Usually it is already represented
    # in history; this block only adds it when history did not contain the same completed run.
    $latest = Get-LatestRunMetadata -ScanId $ScanId

    if ($null -ne $latest -and
        $latest.Status -eq "completed" -and
        $null -ne $latest.RunEnd -and
        (Test-DateInRange -RunEnd $latest.RunEnd)) {

        $alreadyPresent = $false

        if ($null -ne $latest.HistoryId -and $seenHistoryIds.ContainsKey("$($latest.HistoryId)")) {
            $alreadyPresent = $true
        }

        if (-not $alreadyPresent) {
            foreach ($existing in $qualified) {
                if ([math]::Abs(($existing.RunEnd - $latest.RunEnd).TotalSeconds) -lt 1) {
                    $alreadyPresent = $true
                    break
                }
            }
        }

        if (-not $alreadyPresent) {
            [void]$qualified.Add($latest)
        }
    }

    return @($qualified | Sort-Object RunEnd)
}

# =========================
# Main
# =========================
try {
    Write-Host "[*] Connecting to Tenable Nessus Professional at $NessusBaseUrl" -ForegroundColor Cyan
    Write-Host "[*] API mode: Nessus Professional local API" -ForegroundColor Cyan
    Write-Host "[*] Report type: $ReportType" -ForegroundColor Cyan

    if ($HistoryMode) {
        if ($StartDateValue) {
            Write-Host "[*] History mode: scan_end from $($StartDateValue.ToString('yyyy-MM-dd')) through $($EndDateValue.ToString('yyyy-MM-dd')) inclusive" -ForegroundColor Cyan
        }
        else {
            Write-Host "[*] History mode: scan_end up to $($EndDateValue.ToString('yyyy-MM-dd')) inclusive" -ForegroundColor Cyan
        }
    }
    else {
        Write-Host "[*] Latest mode: history will NOT be traversed." -ForegroundColor Cyan
    }

    $folderResponse = Invoke-NessusGet -Uri "${NessusBaseUrl}/folders"
    $allFolders = @($folderResponse.folders)

    if ($All) {
        $targetFolders = $allFolders
        $scopeName = "All Folders"
    }
    else {
        $targetFolders = @($allFolders | Where-Object { $_.name -ieq $FolderName })

        if ($targetFolders.Count -eq 0) {
            Write-Host "[ERROR] Nessus folder not found: $FolderName" -ForegroundColor Red
            Write-Host "Available folders:" -ForegroundColor Yellow
            foreach ($f in ($allFolders | Sort-Object name)) {
                Write-Host "  - $($f.name)"
            }
            exit 1
        }

        if ($targetFolders.Count -gt 1) {
            Write-Host "[ERROR] More than one folder matched '$FolderName'. Folder names must be unambiguous." -ForegroundColor Red
            exit 1
        }

        $scopeName = $targetFolders[0].name
    }

    $outputFolder = New-OutputDirectory -ScopeName $scopeName
    Write-Host "[*] Output: $outputFolder" -ForegroundColor Cyan

    $summary = [ordered]@{
        FoldersProcessed = 0
        ScansProcessed   = 0
        RunsMatched      = 0
        ReportsSucceeded = 0
        ReportsFailed    = 0
        ScansSkipped     = 0
    }

    foreach ($folder in $targetFolders) {
        $summary.FoldersProcessed++
        Write-Host "" 
        Write-Host "Folder: $($folder.name) (ID: $($folder.id))" -ForegroundColor Cyan

        # When exporting all folders, keep each Nessus folder in its own subfolder
        # to prevent identical scan names from overwriting one another.
        if ($All) {
            $folderOutput = Join-Path $outputFolder (Convert-ToSafeFileName "$($folder.name)")
            New-Item -ItemType Directory -Path $folderOutput -Force | Out-Null
        }
        else {
            $folderOutput = $outputFolder
        }

        $scanResponse = Invoke-NessusGet -Uri "${NessusBaseUrl}/scans?folder_id=$($folder.id)"
        $scans = @($scanResponse.scans)

        if ($scans.Count -eq 0) {
            Write-Host "  [INFO] No scans in this folder." -ForegroundColor DarkGray
            continue
        }

        foreach ($scan in $scans) {
            $summary.ScansProcessed++
            $scanId = [int]$scan.id
            $scanName = "$($scan.name)"

            Write-Host "  Scan: $scanName (ID: $scanId)" -ForegroundColor Yellow

            if ($HistoryMode) {
                try {
                    $runs = @(Get-QualifyingRuns -ScanId $scanId)
                }
                catch {
                    Write-Host "    [FAIL] Could not inspect scan history." -ForegroundColor Red
                    Write-Host "           $($_.Exception.Message)" -ForegroundColor DarkRed
                    $summary.ScansSkipped++
                    continue
                }

                if ($runs.Count -eq 0) {
                    Write-Host "    [SKIP] No completed runs ended within the selected date range." -ForegroundColor DarkGray
                    $summary.ScansSkipped++
                    continue
                }

                foreach ($run in $runs) {
                    $summary.RunsMatched++
                    $historyLabel = if ($null -ne $run.HistoryId) { "History ID $($run.HistoryId)" } else { "Latest result" }
                    Write-Host "    Run: $($run.RunEnd.ToString('yyyy-MM-dd HH:mm:ss')) ($historyLabel)" -ForegroundColor White

                    $result = Export-ReportSet -ScanId $scanId -ScanName $scanName `
                        -OutputFolder $folderOutput -HistoryId $run.HistoryId -RunEnd $run.RunEnd

                    $summary.ReportsSucceeded += $result.Success
                    $summary.ReportsFailed += $result.Failed
                }
            }
            else {
                # No date filter: preserve the simple v0.3 behavior, but avoid exporting scans
                # that clearly have no complete/latest result.
                $latestStatus = "$($scan.status)".ToLowerInvariant()

                if ($latestStatus -and $latestStatus -notin @("completed", "imported")) {
                    Write-Host "    [SKIP] Latest scan status is '$latestStatus'; no completed/latest report exported." -ForegroundColor DarkGray
                    $summary.ScansSkipped++
                    continue
                }

                $summary.RunsMatched++
                Write-Host "    Run: latest/current completed result" -ForegroundColor White

                $result = Export-ReportSet -ScanId $scanId -ScanName $scanName `
                    -OutputFolder $folderOutput -HistoryId $null -RunEnd $null

                $summary.ReportsSucceeded += $result.Success
                $summary.ReportsFailed += $result.Failed
            }
        }
    }

    Write-Host ""
    Write-Host "==================== SUMMARY ====================" -ForegroundColor Magenta
    Write-Host "Folders processed : $($summary.FoldersProcessed)"
    Write-Host "Scans processed   : $($summary.ScansProcessed)"
    Write-Host "Runs matched      : $($summary.RunsMatched)"
    Write-Host "Scans skipped     : $($summary.ScansSkipped)"
    Write-Host "Reports succeeded : $($summary.ReportsSucceeded)" -ForegroundColor Green

    if ($summary.ReportsFailed -gt 0) {
        Write-Host "Reports failed    : $($summary.ReportsFailed)" -ForegroundColor Red
    }
    else {
        Write-Host "Reports failed    : 0"
    }

    Write-Host "Output folder     : $outputFolder"
    Write-Host "=================================================" -ForegroundColor Magenta
}
catch {
    Write-Host "[FATAL] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

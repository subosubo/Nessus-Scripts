# Nessus Raw Result Exporter

A PowerShell utility for exporting vulnerability and compliance scan results from **Tenable Nessus Professional**.

Current script: `nessus_export_v0.5.3.ps1`

Setup helper: `setup_nessus_export_v0.3.bat`

## Supported Product

This script is designed for:

**Tenable Nessus Professional**

using the local Nessus API, typically:

```text
https://127.0.0.1:8834
```

It is not designed around the Tenable Vulnerability Management cloud API.

## What It Does

The exporter can:

- Export reports for all scan folders.
- Export reports from one specific Nessus folder.
- Export only the latest/current completed result.
- Inspect historical scan runs when a date filter is supplied.
- Filter historical runs by actual scan completion time (`scan_end`).
- Export VA and HCR reports together.
- Export VA-only or HCR-only reports when requested.
- Export CSV results for downstream processing.
- Save reports into a structured folder tree under the current working directory.

## Report Types

The default report type is:

```text
Both
```

For each qualifying scan run, this produces:

- Vulnerability HTML
- Compliance HTML
- CSV

Optional report modes:

```text
VA
HCR
Both
```

### Both

Produces:

```text
<scan>-vuln.html
<scan>-compliance.html
<scan>-results.csv
```

### VA

Produces:

```text
<scan>-vuln.html
<scan>-results.csv
```

### HCR

Produces:

```text
<scan>-compliance.html
<scan>-results.csv
```

CSV export is retained in all modes so the results can be processed by the Nessus CSV Splitter.

## Setup

Place these files in the same folder:

```text
nessus_export_v0.5.3.ps1
setup_nessus_export_v0.3.bat
```

Run:

```text
setup_nessus_export_v0.3.bat
```

The setup helper:

- checks that `nessus_export_v0.5.3.ps1` is present;
- prompts for the Nessus Access Key;
- prompts for the Nessus Secret Key;
- stores them as Windows user environment variables;
- creates a `Nessus Exports` folder in the current directory;
- checks whether local TCP port `8834` is reachable.

The environment variables used are:

```text
NESSUS_ACCESS_KEY
NESSUS_SECRET_KEY
```

After setup, close and reopen PowerShell so the new environment variables are available.

## Help

Display the built-in help menu:

```powershell
.\nessus_export_v0.5.3.ps1 -h
```

## Usage

### Export All Latest/Current Scan Results

```powershell
.\nessus_export_v0.5.3.ps1 -All
```

This processes all Nessus folders and exports the latest/current completed result for each scan.

Historical runs are not traversed when no date filter is supplied.

### Export One Nessus Folder

```powershell
.\nessus_export_v0.5.3.ps1 -FolderName "202609-ERP2"
```

Only scans inside the specified Nessus folder are processed.

Again, without a date filter, only the latest/current completed result is exported.

### Export an Initial Assessment Date Range

```powershell
.\nessus_export_v0.5.3.ps1 `
    -FolderName "202609-ERP2" `
    -StartDate "2026-09-01" `
    -EndDate "2026-10-04"
```

When a date is supplied, the script inspects the scan history for each scan.

Only completed scan runs whose `scan_end` falls inside the requested range are exported.

### Export Everything Up to a Cut-Off Date

```powershell
.\nessus_export_v0.5.3.ps1 `
    -FolderName "202609-ERP2" `
    -EndDate "2026-10-04"
```

This is useful for separating an initial assessment from later follow-up or retest activity.

It means:

```text
scan_end <= 2026-10-04 23:59:59
```

### VA Only

```powershell
.\nessus_export_v0.5.3.ps1 `
    -FolderName "Network Devices" `
    -ReportType VA
```

### HCR Only

```powershell
.\nessus_export_v0.5.3.ps1 `
    -FolderName "Windows HCR" `
    -ReportType HCR
```

## Date Filtering Rules

Date filtering is based on:

```text
scan_end
```

not scan creation time or modification time.

The date range is inclusive.

Example:

```text
Selected range:
01 Sep 2026 - 15 Sep 2026
```

### Included

```text
Started: 31 Aug
Ended:   02 Sep

Result: INCLUDE
```

The run ended inside the selected range.

### Excluded

```text
Started: 15 Sep
Ended:   16 Sep

Result: EXCLUDE
```

Even though the scan started inside the range, it completed outside the range.

This behaviour is intentional so assessment reports can be separated cleanly from follow-up reviews.

## History Behaviour

### No Date Filter

```text
No date supplied
      │
      ▼
Do not traverse historical runs
      │
      ▼
Export latest/current completed result only
```

### Date Filter Supplied

```text
Date supplied
      │
      ▼
GET /scans/{id}
      │
      ▼
Read embedded history entries
      │
      ▼
Retrieve each historical run by history_id
      │
      ▼
Read actual scan_end
      │
      ▼
Completed + within date range?
      │
   Yes│
      ▼
Export that historical run
```

Only completed runs are selected.

Stopped, cancelled, aborted, or incomplete runs are not intentionally included as assessment results.

## Output Location

Reports are saved relative to the directory from which the PowerShell script is launched.

For example, if PowerShell is currently at:

```text
C:\Tools\Nessus Assessment Toolkit
```

and you run:

```powershell
.\nessus_export_v0.5.3.ps1 `
    -FolderName "202609-ERP2" `
    -EndDate "2026-10-04"
```

the output is:

```text
C:\Tools\Nessus Assessment Toolkit\
└── Nessus Exports\
    └── 202609-ERP2\
        └── Up_to_2026-10-04\
```

In relative form:

```text
.\Nessus Exports\202609-ERP2\Up_to_2026-10-04\
```

For an explicit date range:

```text
.\Nessus Exports\202609-ERP2\2026-09-01_to_2026-10-04\
```

For exports without a date filter:

```text
.\Nessus Exports\202609-ERP2\Latest\
```

## Historical File Naming

Historical exports include the scan completion date/time in the filename to prevent multiple runs from overwriting one another.

Example:

```text
Server01_2026-09-12_211431-vuln.html
Server01_2026-09-12_211431-compliance.html
Server01_2026-09-12_211431-results.csv
```

A later run becomes:

```text
Server01_2026-09-28_220317-vuln.html
Server01_2026-09-28_220317-compliance.html
Server01_2026-09-28_220317-results.csv
```

## Nessus Professional History Handling

Nessus Professional exposes scan history through the normal scan-details request:

```text
GET /scans/{scan_id}
```

Historical runs are identified using their `history_id`.

The script then retrieves the relevant historical result and uses its completion timestamp for filtering.

This is different from the Tenable Vulnerability Management cloud API and is intentional.

## TLS Handling

Local Nessus installations commonly use a self-signed certificate.

For Windows PowerShell, the script configures a certificate-validation bypass for the current PowerShell process and enables TLS 1.2.

This is intended for the local Nessus Professional connection:

```text
https://127.0.0.1:8834
```

The bypass does not permanently modify Windows certificate trust.

## Credentials

The recommended configuration is to use:

```text
NESSUS_ACCESS_KEY
NESSUS_SECRET_KEY
```

as Windows user environment variables.

Avoid committing API keys directly into the PowerShell script or source-control repository.

If API keys have previously been embedded directly in a script, rotate them before sharing or committing that script.

## Typical Assessment Workflow

```text
Tenable Nessus Professional
          │
          ▼
nessus_export_v0.5.3.ps1
          │
          ├── Vulnerability HTML
          ├── Compliance HTML
          └── Raw CSV
                    │
                    ▼
              filter_v0.3.py
                    │
           ┌────────┴────────┐
           ▼                 ▼
      Network VA       Host Compliance
           │                 │
           └────────┬────────┘
                    ▼
             Verified XLSX
```

## Suggested Project Structure

```text
Nessus Assessment Toolkit\
├── nessus_export_v0.5.3.ps1
├── setup_nessus_export_v0.3.bat
├── filter_v0.3.py
├── README_Nessus_Raw_Result_Exporter.md
├── README_Nessus_CSV_Splitter.md
└── Nessus Exports\
```

## Notes

- Scan and folder names are sanitised where required for Windows filenames.
- Historical output is designed to prevent initial-assessment and follow-up results from being unintentionally mixed.
- A date filter should be used when the same Nessus scan definition has been executed multiple times across different assessment phases.
- `-EndDate` alone is particularly useful when the follow-up review starts after a known date.

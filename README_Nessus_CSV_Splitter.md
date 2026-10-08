# Nessus CSV Splitter

A small Python utility for converting Nessus CSV exports into a structured Excel workbook for easier review of **Network Vulnerability Assessment (VA)** and **Host Compliance Review (HCR)** results.

Current script: `filter_v0.3.py`

## What It Does

The script reads a Nessus CSV export and separates records based on the `Risk` column.

### Network VA

The following values are written to the **Network VA** worksheet:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `NONE`

### Host Compliance

The following values are written to the **Host Compliance** worksheet:

- `FAILED`
- `WARNING`
- `PASSED`

### Unclassified

Any unexpected `Risk` value that does not match the VA or compliance categories is written to an **Unclassified** worksheet.

This prevents unknown values from being silently misclassified.

## Features

- Process a single CSV file.
- Process all CSV files in a folder.
- Splits VA and HCR records into separate Excel worksheets.
- Sorts VA findings by severity:
  - Critical
  - High
  - Medium
  - Low
  - None
- Sorts HCR findings by:
  - Failed
  - Warning
  - Passed
- Disables automatic Excel URL conversion to avoid Nessus `See Also` URL warnings.
- Freezes worksheet headers.
- Adds Excel autofilters.
- Automatically adjusts column widths.
- Sanitises filenames for Windows.
- Performs CSV-to-XLSX record-count validation.

## Requirements

Python 3 and the following packages:

```powershell
pip install pandas xlsxwriter openpyxl
```

`xlsxwriter` is used to create the Excel workbook.

`openpyxl` is required for the post-export verification step, where the generated XLSX file is read back and checked against the source CSV.

## Usage

### Process One CSV

```powershell
python .\filter_v0.3.py "C:\Path\To\scan-results.csv"
```

The resulting Excel workbook is created in the same folder as the CSV.

Example:

```text
scan-results.csv
scan-results.xlsx
```

### Process All CSV Files in a Folder

```powershell
python .\filter_v0.3.py "C:\Path\To\Nessus Results"
```

Every `.csv` file directly inside the specified folder will be processed.

### Process the Current Directory

If no path is supplied:

```powershell
python .\filter_v0.3.py
```

the script processes all CSV files in the current working directory.

## Output Workbook

A typical workbook contains:

```text
scan-results.xlsx
├── Network VA
├── Host Compliance
└── Unclassified        (only when required)
```

## Record Integrity Checks

The script performs two checks.

### 1. In-Memory Check

Before writing the Excel file:

```text
Network VA
+ Host Compliance
+ Unclassified
= Original CSV record count
```

If the totals do not match, the workbook is not created.

### 2. Generated XLSX Check

After the workbook is created, the script reads the XLSX file back from disk and counts the records in all generated worksheets.

A successful run displays:

```text
[PASS] In-memory record count verified: 2847 records

Saved: scan-results.xlsx
Network VA      : 1832
Host Compliance : 1015
Unclassified    : 0
Original CSV    : 2847

[PASS] XLSX verification successful: CSV=2847, XLSX=2847
[PASS] CSV -> XLSX integrity verified.
```

This helps confirm that no records were lost during conversion.

## Nessus URL Handling

Nessus CSV exports may contain cells with many URLs, particularly in fields such as `See Also`.

Excel has limits on hyperlink length and quantity. To prevent XlsxWriter from attempting to convert these large text fields into hyperlinks, the script uses:

```python
strings_to_urls=False
```

The URL text remains in the workbook as normal text.

## Notes

- The input CSV must contain a `Risk` column.
- Column headings are trimmed before processing.
- `Risk` values are compared case-insensitively and with surrounding whitespace removed.
- The original record contents are preserved as text.
- Only CSV files directly inside the selected folder are processed; subfolders are not recursively scanned.

## Typical Workflow

```text
Nessus
   │
   ▼
Raw CSV Export
   │
   ▼
filter_v0.3.py
   │
   ├── Network VA
   ├── Host Compliance
   └── Unclassified
   │
   ▼
Verified Excel Workbook
```

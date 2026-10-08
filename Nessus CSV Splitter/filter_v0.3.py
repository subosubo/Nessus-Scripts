import pandas as pd
from pathlib import Path
import re
import sys

# ============================================================
# Nessus CSV -> Excel splitter
#
# Usage:
#   Process one CSV:
#     python filter_v0.3.py "C:\path\to\scan.csv"
#
#   Process all CSVs in a folder:
#     python filter_v0.3.py "C:\path\to\folder"
#
#   If no path is supplied, the current directory is used.
#
# Output sheets:
#   - Network VA
#   - Host Compliance
#   - Unclassified (only if unexpected Risk values are found)
#
# Integrity checks:
#   1. Confirms every CSV row is assigned to exactly one category.
#   2. Reads the generated XLSX back and confirms the total row
#      count matches the original CSV.
# ============================================================

COMPLIANCE_RISKS = {"PASSED", "FAILED", "WARNING"}
VA_RISKS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}

VA_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "NONE": 4,
}

COMPLIANCE_ORDER = {
    "FAILED": 0,
    "WARNING": 1,
    "PASSED": 2,
}


def clean_filename(name):
    """Replace characters that are unsafe/problematic in Windows filenames."""
    return re.sub(r'[<>:"/\\|?*\[\]() ]+', "_", name)


def get_input_files(input_path):
    """Return CSV files to process and the output directory."""
    if input_path.is_file():
        if input_path.suffix.lower() != ".csv":
            print(f"[ERROR] Input file is not a CSV: {input_path}")
            sys.exit(1)

        return [input_path], input_path.parent

    if input_path.is_dir():
        csv_files = sorted(input_path.glob("*.csv"))

        if not csv_files:
            print(f"No CSV files found in: {input_path}")
            sys.exit(0)

        return csv_files, input_path

    print(f"[ERROR] Path does not exist: {input_path}")
    sys.exit(1)


def format_worksheet(worksheet, dataframe):
    """Apply basic formatting to improve Excel readability."""
    worksheet.freeze_panes(1, 0)

    if len(dataframe.columns) == 0:
        return

    # Autofilter including header row.
    worksheet.autofilter(
        0,
        0,
        len(dataframe),
        len(dataframe.columns) - 1,
    )

    # Set reasonable column widths while preventing very long Nessus
    # fields such as Plugin Output / See Also from creating huge columns.
    for col_num, column in enumerate(dataframe.columns):
        if dataframe.empty:
            max_data_length = 0
        else:
            max_data_length = dataframe[column].astype(str).str.len().max()
            if pd.isna(max_data_length):
                max_data_length = 0

        width = min(max(len(str(column)), int(max_data_length)) + 2, 50)
        width = max(width, 12)

        worksheet.set_column(col_num, col_num, width)


def verify_xlsx(output_excel, expected_count):
    """
    Read the generated workbook back and confirm the physical XLSX
    contains the same number of data rows as the source CSV.
    """
    try:
        excel_file = pd.ExcelFile(output_excel)
        xlsx_count = 0
        sheet_counts = {}

        for sheet_name in excel_file.sheet_names:
            sheet_df = pd.read_excel(
                excel_file,
                sheet_name=sheet_name,
                dtype=str,
                keep_default_na=False,
            )

            count = len(sheet_df)
            sheet_counts[sheet_name] = count
            xlsx_count += count

        if xlsx_count == expected_count:
            print(
                f"  [PASS] XLSX verification successful: "
                f"CSV={expected_count}, XLSX={xlsx_count}"
            )
            return True, sheet_counts

        print(
            f"  [FAIL] XLSX record mismatch: "
            f"CSV={expected_count}, XLSX={xlsx_count}"
        )
        return False, sheet_counts

    except ImportError:
        print(
            "  [WARNING] XLSX was created, but post-export verification "
            "could not run because the Excel reader dependency is missing."
        )
        print("            Install it with: pip install openpyxl")
        return False, {}

    except Exception as exc:
        print(f"  [ERROR] Unable to verify XLSX: {exc}")
        return False, {}


def process_csv(csv_file, output_folder):
    print(f"\nProcessing: {csv_file.name}")

    try:
        # Read everything as text to preserve Nessus values exactly.
        df = pd.read_csv(
            csv_file,
            dtype=str,
            keep_default_na=False,
        )
    except Exception as exc:
        print(f"  [ERROR] Could not read file: {exc}")
        return

    # Normalise column headings.
    df.columns = df.columns.str.strip()

    if "Risk" not in df.columns:
        print("  [SKIPPED] 'Risk' column not found.")
        return

    csv_count = len(df)

    # Normalised Risk series used only for categorisation/sorting.
    risk = (
        df["Risk"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    # Split the CSV into three mutually exclusive groups.
    network_va = df[risk.isin(VA_RISKS)].copy()
    host_compliance = df[risk.isin(COMPLIANCE_RISKS)].copy()

    known_risks = VA_RISKS | COMPLIANCE_RISKS
    unclassified = df[~risk.isin(known_risks)].copy()

    # Sort Network VA by severity.
    if not network_va.empty:
        network_va["_sort"] = (
            network_va["Risk"]
            .astype(str)
            .str.strip()
            .str.upper()
            .map(VA_ORDER)
        )

        network_va = (
            network_va
            .sort_values("_sort", kind="stable")
            .drop(columns="_sort")
        )

    # Sort compliance findings by FAILED -> WARNING -> PASSED.
    if not host_compliance.empty:
        host_compliance["_sort"] = (
            host_compliance["Risk"]
            .astype(str)
            .str.strip()
            .str.upper()
            .map(COMPLIANCE_ORDER)
        )

        host_compliance = (
            host_compliance
            .sort_values("_sort", kind="stable")
            .drop(columns="_sort")
        )

    # First integrity check: every source row must appear in exactly one
    # of the three output DataFrames.
    output_count = (
        len(network_va)
        + len(host_compliance)
        + len(unclassified)
    )

    if csv_count != output_count:
        print(
            f"  [FAIL] In-memory record count mismatch: "
            f"CSV={csv_count}, Categorised={output_count}"
        )
        print("  Excel file was NOT created.")
        return

    print(
        f"  [PASS] In-memory record count verified: "
        f"{csv_count} records"
    )

    safe_filename = clean_filename(csv_file.stem)
    output_excel = output_folder / f"{safe_filename}.xlsx"

    try:
        # strings_to_urls=False prevents XlsxWriter from attempting to
        # convert very long multi-line Nessus "See Also" fields into a
        # single Excel hyperlink (Excel URL limit is 2079 characters).
        with pd.ExcelWriter(
            output_excel,
            engine="xlsxwriter",
            engine_kwargs={
                "options": {
                    "strings_to_urls": False
                }
            },
        ) as writer:

            network_va.to_excel(
                writer,
                sheet_name="Network VA",
                index=False,
            )

            host_compliance.to_excel(
                writer,
                sheet_name="Host Compliance",
                index=False,
            )

            sheets = {
                "Network VA": network_va,
                "Host Compliance": host_compliance,
            }

            if not unclassified.empty:
                unclassified.to_excel(
                    writer,
                    sheet_name="Unclassified",
                    index=False,
                )
                sheets["Unclassified"] = unclassified

            for sheet_name, dataframe in sheets.items():
                format_worksheet(
                    writer.sheets[sheet_name],
                    dataframe,
                )

    except Exception as exc:
        print(f"  [ERROR] Could not create XLSX: {exc}")
        return

    print(f"  Saved: {output_excel}")
    print(f"  Network VA      : {len(network_va)}")
    print(f"  Host Compliance : {len(host_compliance)}")
    print(f"  Unclassified    : {len(unclassified)}")
    print(f"  Original CSV    : {csv_count}")

    # Second integrity check: read the actual XLSX back from disk.
    verified, sheet_counts = verify_xlsx(
        output_excel,
        csv_count,
    )

    if verified:
        print("  [PASS] CSV -> XLSX integrity verified.")
    elif sheet_counts:
        print(f"  XLSX sheet counts: {sheet_counts}")


def main():
    input_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path.cwd()
    )

    csv_files, output_folder = get_input_files(input_path)

    print(f"Input: {input_path}")
    print(f"CSV files to process: {len(csv_files)}")

    for csv_file in csv_files:
        process_csv(csv_file, output_folder)

    print("\nDone.")


if __name__ == "__main__":
    main()

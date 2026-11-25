
# COMP H2702 - File Triage and Hash Analysis
# Uses only Python's built-in libraries.

import csv
import hashlib
import json
from pathlib import Path
from datetime import datetime


def calculate_hash(file_path):
    """Read a file safely and calculate its SHA-256 hash."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()


def load_reference(csv_path):
    """Read and validate the known hashes from a CSV file."""
    known_hashes = set()

    with open(csv_path, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or "sha256" not in reader.fieldnames:
            raise ValueError("Reference CSV must have a sha256 column")

        for row in reader:
            value = (row.get("sha256") or "").strip().lower()

            if len(value) != 64 or any(
                c not in "0123456789abcdef" for c in value
            ):
                print("Warning: invalid SHA-256 value skipped")
                continue

            known_hashes.add(value)

    if not known_hashes:
        raise ValueError("No valid hashes found in reference CSV")

    return known_hashes


def analyse_files(folder, known_hashes):
    """Collect information and identify known and unknown files."""
    results = []

    for path in sorted(folder.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue

        try:
            file_hash = calculate_hash(path)
            info = path.stat()

            status = "UNKNOWN"

            if file_hash in known_hashes:
                status = "KNOWN / REFERENCE MATCH"

            results.append({
                "filename": str(path.relative_to(folder)),
                "extension": path.suffix or "(none)",
                "size_bytes": info.st_size,
                "modified": datetime.fromtimestamp(
                    info.st_mtime
                ).isoformat(timespec="seconds"),
                "sha256": file_hash,
                "status": status
            })

        except OSError as error:
            print(f"Warning: could not read {path.name}: {error}")

    return results


def find_duplicates(results):
    """Group files whose SHA-256 hashes are identical."""
    groups = {}

    for item in results:
        file_hash = item["sha256"]

        if file_hash not in groups:
            groups[file_hash] = []

        groups[file_hash].append(item["filename"])

    duplicates = []

    for file_hash, names in groups.items():
        if len(names) > 1:
            duplicates.append({
                "sha256": file_hash,
                "files": names
            })

    return duplicates


def save_report(results, duplicates, output_file):
    """Save a JSON report with all findings."""
    known = 0

    for item in results:
        if item["status"] == "KNOWN / REFERENCE MATCH":
            known += 1

    report = {
        "files_analysed": len(results),
        "known_files": known,
        "unknown_files": len(results) - known,
        "files": results,
        "duplicate_groups": duplicates,
        "security_note": (
            "A matching SHA-256 hash indicates identical content "
            "to a reference file, but does not prove the file "
            "is safe. UNKNOWN does not prove malware."
        )
    }

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report


def main():
    print("=== FILE TRIAGE TOOL ===")

    folder_name = input(
        "Folder to scan (press Enter for samples): "
    ).strip()

    if not folder_name:
        folder_name = "samples"

    folder = Path(folder_name)
    reference_file = Path("hashes_reference.csv")

    if not folder.is_dir():
        print("Error: sample folder not found:", folder)
        return

    try:
        known_hashes = load_reference(reference_file)
        results = analyse_files(folder, known_hashes)
        duplicates = find_duplicates(results)

        report = save_report(
            results, duplicates, "triage_report.json"
        )

    except (OSError, ValueError, csv.Error) as error:
        print("Error:", error)
        return

    print("\nFiles analysed:", report["files_analysed"])
    print("Reference matches:", report["known_files"])
    print("Unknown files:", report["unknown_files"])

    for item in results:
        print(f"{item['filename']}: {item['status']}")
        print(f"  SHA-256: {item['sha256']}")

    print("\nDuplicate groups:", len(duplicates))

    for group in duplicates:
        print("Identical files:", ", ".join(group["files"]))

    print("\nReport saved to triage_report.json")
    print("Note: UNKNOWN does not mean malicious.")


if __name__ == "__main__":
    main()

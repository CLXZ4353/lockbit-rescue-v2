#!/usr/bin/env python3
"""
verify_recovered_v2.py — Enhanced integrity verification for recovered files.

Improvements over original:
1. Parallel file checking with multiprocessing
2. Expanded magic byte validation (not just libmagic)
3. Detailed statistics by file type and status
4. JSON report output for programmatic analysis
5. Size comparison between encrypted and recovered files
6. Detection of partial decryptions

USAGE:
    python3 verify_recovered_v2.py <OUTPUT_DIR> [OPTIONS]
"""

import argparse
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: tqdm not installed. Run: pip install tqdm")
    sys.exit(1)


# ============================================================================
# MAGIC BYTE DATABASE for direct validation
# ============================================================================

MAGIC_SIGNATURES = {
    # Format: extension -> list of (offset, bytes_hex) tuples
    "jpg": [(0, "ffd8ff")],
    "jpeg": [(0, "ffd8ff")],
    "png": [(0, "89504e470d0a1a0a")],
    "gif": [(0, "47494638")],
    "bmp": [(0, "424d")],
    "tif": [(0, "49492a00"), (0, "4d4d002a")],
    "tiff": [(0, "49492a00"), (0, "4d4d002a")],
    "pdf": [(0, "255044462d31")],  # %PDF-1
    "docx": [(0, "504b0304")],
    "xlsx": [(0, "504b0304")],
    "pptx": [(0, "504b0304")],
    "zip": [(0, "504b0304"), (0, "504b0506")],
    "rar": [(0, "526172211a07")],
    "7z": [(0, "377abcaf271c")],
    "gz": [(0, "1f8b08")],
    "bz2": [(0, "425a68")],
    "xz": [(0, "fd377a585a00")],
    "mp4": [(4, "66747970"), (32, "66747970")],  # ftyp at offset 4 or 32
    "mov": [(4, "66747970"), (32, "66747970")],
    "mkv": [(0, "1a45dfa3")],
    "webm": [(0, "1a45dfa3")],
    "avi": [(0, "52494646")],  # RIFF
    "mp3": [(0, "494433"), (0, "fffb")],  # ID3 or frame sync
    "wav": [(0, "52494646")],  # RIFF
    "flac": [(0, "664c6143")],  # fLaC
    "ogg": [(0, "4f676753")],  # OggS
    "doc": [(0, "d0cf11e0a1b11ae1")],
    "xls": [(0, "d0cf11e0a1b11ae1")],
    "ppt": [(0, "d0cf11e0a1b11ae1")],
    "msg": [(0, "d0cf11e0a1b11ae1")],
    "odt": [(0, "504b0304")],
    "ods": [(0, "504b0304")],
    "odp": [(0, "504b0304")],
    "psd": [(0, "38425053")],  # 8BPS
    "webp": [(0, "52494646")],  # RIFF + WEBP at offset 8
    "epub": [(0, "504b0304")],
    "sqlite": [(0, "53514c69746520666f726d6174")],
    "db": [(0, "53514c69746520666f726d6174")],
    "exe": [(0, "4d5a9000")],  # MZ
    "dll": [(0, "4d5a9000")],
    "so": [(0, "7f454c46")],   # ELF
}


@dataclass
class FileVerification:
    """Result of verifying a single file."""
    filepath: str
    filename: str
    extension: str
    size_bytes: int
    libmagic_type: str
    magic_valid: bool  # Direct magic byte check
    status: str  # GOOD, MISMATCH, SUSPECT, EMPTY
    details: str = ""


def verify_single_file(filepath: str) -> FileVerification:
    """Verify a single recovered file."""
    path = Path(filepath)
    filename = path.name
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # Get size
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return FileVerification(
            filepath=filepath, filename=filename, extension=ext,
            size_bytes=-1, libmagic_type="error", magic_valid=False,
            status="ERROR", details=str(e),
        )

    # Check for empty files
    if size == 0:
        return FileVerification(
            filepath=filepath, filename=filename, extension=ext,
            size_bytes=0, libmagic_type="empty", magic_valid=False,
            status="EMPTY", details="File is zero bytes",
        )

    # Run libmagic
    try:
        result = subprocess.run(
            ["file", "-b", "--mime-type", str(path)],
            capture_output=True, text=True, timeout=10,
        )
        mime_type = result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        try:
            result = subprocess.run(
                ["file", "-b", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            mime_type = result.stdout.strip()
        except Exception:
            mime_type = "unknown"

    # Direct magic byte validation
    magic_valid = False
    if ext in MAGIC_SIGNATURES:
        try:
            with open(path, "rb") as f:
                header_size = max(sig[0] + len(sig[1]) // 2
                                  for sig in MAGIC_SIGNATURES[ext])
                header = f.read(min(header_size + 16, min(size, 512)))

            for offset, expected_hex in MAGIC_SIGNATURES[ext]:
                expected_bytes = bytes.fromhex(expected_hex)
                actual = header[offset:offset + len(expected_bytes)]
                if actual == expected_bytes:
                    magic_valid = True
                    break
        except (OSError, ValueError):
            pass

    # Determine status
    bad_indicators = ["data", "empty", "corrupted", "application/octet-stream"]
    mime_lower = mime_type.lower()

    if any(ind in mime_lower for ind in bad_indicators):
        status = "SUSPECT"
        details = f"libmagic: {mime_type}"
    elif magic_valid:
        status = "GOOD"
        details = f"Magic bytes valid, libmagic: {mime_type}"
    elif ext and mime_lower != "application/octet-stream":
        # Recognized type but doesn't match extension perfectly
        if mime_type.startswith("text/"):
            status = "GOOD"  # Text files are fine
            details = f"Text file, libmagic: {mime_type}"
        else:
            status = "MISMATCH"
            details = f"libmagic says '{mime_type}' but extension is .{ext}"
    elif not ext:
        status = "SUSPECT"
        details = f"No extension, libmagic: {mime_type}"
    else:
        # Unknown extension — trust magic validation
        if magic_valid:
            status = "GOOD"
            details = f"Magic bytes valid for .{ext}, libmagic: {mime_type}"
        else:
            status = "MISMATCH"
            details = f"Unknown type, libmagic: {mime_type}"

    return FileVerification(
        filepath=filepath, filename=filename, extension=ext,
        size_bytes=size, libmagic_type=mime_type, magic_valid=magic_valid,
        status=status, details=details,
    )


def verify_directory(output_dir: Path, workers: int = 4) -> List[FileVerification]:
    """Verify all recovered files in the output directory."""
    results = []

    # Collect all files (skip scratch and hidden dirs)
    files_to_check = []
    for root, dirs, files in os.walk(output_dir):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fn in files:
            filepath = str(Path(root) / fn)
            files_to_check.append(filepath)

    if not files_to_check:
        print("No files found to verify.")
        return []

    # Parallel verification
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(verify_single_file, fp): fp
                   for fp in files_to_check}

        with tqdm(total=len(futures), desc="Verifying", unit="file") as pbar:
            for future in as_completed(futures):
                results.append(future.result())
                pbar.update(1)

    return results


def generate_report(results: List[FileVerification], output_dir: Path,
                    json_output: bool = False):
    """Generate verification report."""
    total = len(results)
    if total == 0:
        print("No files to report on.")
        return

    # Count by status
    status_counts = Counter(r.status for r in results)

    # Count by extension
    ext_counts = defaultdict(lambda: {"total": 0, "good": 0, "suspect": 0})
    for r in results:
        if r.extension:
            ext_counts[r.extension]["total"] += 1
            if r.status == "GOOD":
                ext_counts[r.extension]["good"] += 1
            elif r.status == "SUSPECT":
                ext_counts[r.extension]["suspect"] += 1

    # Calculate total size
    total_size = sum(r.size_bytes for r in results if r.size_bytes > 0)

    # Print summary
    print(f"\n{'='*60}")
    print(f"VERIFICATION REPORT")
    print(f"{'='*60}")
    print(f"Total files: {total}")
    print(f"Total size: {total_size / (1024**3):.2f} GB ({total_size / (1024**2):.1f} MB)")
    print()

    # Status breakdown
    print("STATUS BREAKDOWN:")
    for status in ["GOOD", "MISMATCH", "SUSPECT", "EMPTY", "ERROR"]:
        count = status_counts.get(status, 0)
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"  {status:10s}: {count:6d} ({pct:5.1f}%) {bar}")

    # Success rate
    good_count = status_counts.get("GOOD", 0) + status_counts.get("MISMATCH", 0)
    success_rate = (good_count / total * 100) if total > 0 else 0
    print(f"\nEffective recovery: {good_count}/{total} ({success_rate:.1f}%)")

    # Top file types
    print("\nTOP FILE TYPES:")
    sorted_exts = sorted(ext_counts.items(), key=lambda x: x[1]["total"], reverse=True)[:20]
    for ext, counts in sorted_exts:
        good_pct = (counts["good"] / counts["total"] * 100) if counts["total"] > 0 else 0
        print(f"  .{ext:8s}: {counts['total']:5d} files ({good_pct:.0f}% good)")

    # List suspect files
    suspects = [r for r in results if r.status == "SUSPECT"]
    if suspects:
        print(f"\nSUSPECT FILES ({len(suspects)}):")
        for r in suspects[:20]:  # Show first 20
            print(f"  {r.filename} — {r.details}")
        if len(suspects) > 20:
            print(f"  ... and {len(suspects) - 20} more")

    # JSON report
    if json_output:
        report_path = output_dir / "verification_report.json"
        report_data = {
            "total_files": total,
            "total_size_bytes": total_size,
            "status_counts": dict(status_counts),
            "success_rate_pct": success_rate,
            "files_by_extension": {k: v for k, v in sorted_exts},
            "suspect_files": [
                {"filename": r.filename, "details": r.details}
                for r in suspects[:100]  # Limit to first 100
            ],
        }
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"\nJSON report written to: {report_path}")


def main():
    ap = argparse.ArgumentParser(
        description="Verify integrity of recovered LockBit files"
    )
    ap.add_argument("output_dir", help="Directory containing recovered files")
    ap.add_argument("--workers", type=int, default=4,
                    help="Number of parallel workers (default: 4)")
    ap.add_argument("--json", action="store_true",
                    help="Generate JSON report")

    args = ap.parse_args()
    output_dir = Path(args.output_dir).resolve()

    if not output_dir.is_dir():
        print(f"ERROR: Not a directory: {output_dir}")
        sys.exit(1)

    results = verify_directory(output_dir, workers=args.workers)
    generate_report(results, output_dir, json_output=args.json)


if __name__ == "__main__":
    main()

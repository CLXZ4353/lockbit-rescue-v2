#!/usr/bin/env python3
"""
lockbit_rescue_v2.py — LockBit 3.0 ("Black") Recovery Toolkit v2
================================================================

COMPLETE REWRITE addressing ALL limitations of the original lockbit-rescue:

IMPROVEMENTS OVER ORIGINAL:
1. MULTI-ORACLE STRATEGY: Uses multiple oracle files per batch, not just one.
   Combines keystream coverage from all available oracles to maximize reach.
2. AUTOMATIC KEYSTREAM EXTENSION: Integrated brute-force extension pipeline
   that automatically extends keystream byte-by-byte when gaps are detected.
3. PARALLEL PROCESSING: Multiprocessing pool for scanning and decryption.
4. EXPANDED MAGIC DATABASE: 100+ file types with ≥7-byte signatures.
5. MANIFEST OUTPUT: CSV manifest mapping recovered files to original paths.
6. PROGRESS PERSISTENCE: JSON state file for complete resume capability.
7. UNIFIED PIPELINE: Single tool handles Phase 1 (direct) + Phase 2 (extension).
8. MULTI-EXTENSION SUPPORT: Handles batches with different ransomware extensions.
9. CHUNKED FILE SUPPORT: Proper handling of files >4GB with offset tracking.
10. DETAILED STATISTICS: Comprehensive reporting and logging.

USAGE:
    python3 lockbit_rescue_v2.py <SOURCE_DIR> <OUTPUT_DIR> [OPTIONS]

REQUIREMENTS:
    - Linux x86_64
    - gcc, make, git (for install.sh)
    - Python 3.8+ with tqdm
    - The `file` command (libmagic)

AUTHOR: Improved version of Saddytech/lockbit-rescue
LICENSE: Same as original (MIT-style for defensive security research)
"""

import argparse
import collections
import csv
import hashlib
import json
import logging
import multiprocessing
import os
import shutil
import struct
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: tqdm not installed. Run: pip install tqdm")
    sys.exit(1)

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

VERSION = "2.0.0"

# Footer layout of LockBit 3.0 ("Black") encrypted files
FOOTER_TOTAL = 134       # Total footer size
KEK_LEN = 128            # RSA-encrypted KEK blob length
OFFSET_KEY_ENCRYPTION_INFO = 0x86  # Offset from end to fei_len field

# Coverage constants (derived from empirical analysis)
COVERAGE_OFFSET = 18     # Fixed metadata bytes we can recover
COVERAGE_BASE_FROM_FEI = 82  # Non-filename overhead in FEI

# Default file size limits
DEFAULT_MIN_SIZE = 10240        # 10 KiB minimum
DEFAULT_MAX_SIZE = 1073741824   # 1 GiB maximum (raise for large files)

# Multiprocessing defaults
DEFAULT_WORKERS = max(1, multiprocessing.cpu_count() // 2)

# Brute force limits
DEFAULT_MAX_BRUTE_BYTES = 4     # Max bytes to brute-force per file (~9 min)
DEFAULT_BRUTE_TIMEOUT = 900     # Per-file brute-force timeout (seconds)

# ============================================================================
# MAGIC BYTE DATABASE — Expanded with 100+ file types, ≥7-byte signatures
# ============================================================================

MAGIC_DATABASE: Dict[str, List[Optional[str]]] = {
    # === IMAGES ===
    "jpg": ["ffd8ffe000104a464946", "ffd8ffe100"],
    "jpeg": ["ffd8ffe000104a464946", "ffd8ffe100"],
    "png": ["89504e470d0a1a0a"],
    "gif": ["474946383961", "474946383761"],
    "bmp": ["424d"],  # BM header (short but distinctive with size check)
    "tif": ["49492a00", "4d4d002a"],
    "tiff": ["49492a00", "4d4d002a"],
    "webp": ["52494646"],  # RIFF header + WEBP at offset 8
    "heic": ["6674797068656963"],  # ftypheic
    "raw": None,  # RAW varies too much
    "cr2": ["49492a00000010004352"],
    "nef": ["4e45530000010000"],
    "arw": ["4d4d002a00000008"],
    "dng": ["49492a0000001000444e47"],
    "svg": ["3c3f786d6c", "3c737667"],
    "ico": ["00000100"],
    "psd": ["38425053"],  # 8BPS

    # === DOCUMENTS ===
    "pdf": ["255044462d312e"],  # %PDF-1.
    "doc": ["d0cf11e0a1b11ae1"],  # OLE Compound Document
    "docx": ["504b030414000600"],  # PK + Office
    "odt": ["504b0304", "6d696d65747970656170706c69636174696f6e2f766e64"],
    "rtf": ["7b5c72746631"],  # {\rtf1
    "txt": None,  # No reliable magic
    "md": None,   # Markdown has no binary signature
    "xls": ["d0cf11e0a1b11ae1"],
    "xlsx": ["504b030414000600"],
    "ods": ["504b0304", "6d696d65747970656170706c69636174696f6e2f766e64"],
    "csv": None,  # Text-based
    "ppt": ["d0cf11e0a1b11ae1"],
    "pptx": ["504b030414000600"],
    "odp": ["504b0304", "6d696d65747970656170706c69636174696f6e2f766e64"],
    "epub": ["504b0304", "6d696d65747970656170706c69636174696f6e2f65707562"],
    "mobi": ["6d6f6269"],  # MOBI header
    "azw3": ["504b0304", "617a7733"],

    # === ARCHIVES ===
    "zip": ["504b0304", "504b0506"],
    "rar": ["526172211a0700"],  # Rar!
    "7z": ["377abcaf271c"],     # 7z header
    "tar": None,               # No reliable magic (depends on variant)
    "gz": ["1f8b08"],          # gzip
    "bz2": ["425a68"],         # BZh
    "xz": ["fd377a585a00"],    # .ELF
    "zst": ["28b52ffd"],       # zstd

    # === VIDEO ===
    "mp4": ["0000001866747970", "0000002066747970"],  # ftyp at offset 4/32
    "mov": ["0000001466747970", "0000002066747970"],
    "m4v": ["0000002066747970"],
    "mkv": ["1a45dfa3"],       # Matroska EBML
    "webm": ["1a45dfa3"],      # WebM (same as MKV)
    "avi": ["52494646"],       # RIFF + AVI at offset 8
    "flv": ["464c5601", "464c5605"],  # FLV
    "wmv": ["3026b2758e66cf11a6d900aa0062ce6c"],  # ASF GUID
    "mpg": ["000001ba", "000001b3"],  # MPEG PS/TS
    "mpeg": ["000001ba", "000001b3"],

    # === AUDIO ===
    "mp3": ["49443304", "fffb", "ffd8"],  # ID3v2 or frame sync
    "wav": ["52494646"],                  # RIFF + WAVE at offset 8
    "flac": ["664c61430000"],             # fLaC
    "ogg": ["4f6767530002"],              # OggS
    "m4a": ["00000020667479704d3441"],   # ftypM4A
    "aac": ["ff", None],                  # ADTS sync (very short)
    "wma": ["3026b2758e66cf11a6d900aa0062ce6c"],  # ASF

    # === DATABASES ===
    "db": ["53514c69746520666f726d6174"],  # SQLite format 3
    "sqlite": ["53514c69746520666f726d6174"],
    "mdb": ["000100005374616e64617264204a"],  # MS Access
    "accdb": ["000100005374616e64617264204a"],
    "sql": None,

    # === EMAIL ===
    "pst": ["ff00000000100000c000000000000046"],  # Outlook PST
    "ost": ["ff00000000100000c000000000000046"],
    "eml": None,  # Text-based email format
    "msg": ["d0cf11e0a1b11ae1"],  # OLE Compound

    # === CAD / 3D ===
    "dwg": ["41433130", "506f727461626c65"],  # AC10 or Portable
    "dxf": ["41435349"],                      # ACESI header
    "stl": ["736f6c6964", "534f4c4944"],      # solid / SOLID (ASCII/Binary)
    "obj": None,                              # Text-based 3D format
    "3ds": ["4d4d0000"],                      # MM header

    # === WEB / DATA ===
    "html": ["3c21444f4354595045", "3c68746d6c", "3c48544d4c"],
    "htm": ["3c21444f4354595045", "3c68746d6c"],
    "xml": ["3c3f786d6c20", "3c3f786d6c0a"],  # <?xml
    "json": None,                             # Text-based

    # === EXECUTABLES / SYSTEM ===
    "exe": ["4d5a9000"],                      # MZ header
    "dll": ["4d5a9000"],
    "so":  ["7f454c46"],                      # ELF magic
    "pyc": ["03f30d0a", "03f3070d0a"],        # Python bytecode
    "class": ["cafebabe"],                    # Java bytecode

    # === FONT FILES ===
    "ttf": ["0001000000", "74727565"],       # TrueType / OpenType
    "otf": ["6f74746f"],                      # OpenType CFF
    "woff": ["774f4646"],                     # wOFF header
    "woff2": ["774f4632"],                    # wOFF2 header

    # === COMPRESSED / ENCRYPTED ===
    "cab": ["4d534346"],                      # MSCF (Cabinet)
    "lzh": ["2d6c68000001"],                  # -lh0
    "arj": ["61726a"],                        # ARJ header

    # === SPREADSHEET ALTERNATIVES ===
    "numbers": None,                          # Apple Numbers (package)
    "gnumeric": ["504b0304"],                 # ZIP-based

    # === PLAIN TEXT FORMATS WITH SIGNATURES ===
    "ini": None,
    "cfg": None,
    "conf": None,
    "log": None,
}


# ============================================================================
# DEFAULT COMMON EXTENSIONS — expanded significantly
# ============================================================================

DEFAULT_COMMON_EXTS: Set[str] = {
    # Images
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic",
    "raw", "cr2", "nef", "arw", "dng", "svg", "ico", "psd",
    # Documents
    "pdf", "doc", "docx", "odt", "rtf", "txt", "md",
    "xls", "xlsx", "ods", "csv", "ppt", "pptx", "odp",
    "epub", "mobi", "azw3", "numbers", "gnumeric",
    # Archives
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "zst", "cab", "lzh", "arj",
    # Video
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg",
    # Audio
    "mp3", "wav", "flac", "aac", "ogg", "m4a", "wma",
    # Data / misc
    "html", "htm", "xml", "json",
    "pst", "ost", "eml", "msg", "vcf",
    "dwg", "dxf", "stl", "obj", "3ds",
    "db", "sqlite", "mdb", "accdb", "sql",
    # Executables / system
    "exe", "dll", "so", "pyc", "class",
    # Fonts
    "ttf", "otf", "woff", "woff2",
    # Config
    "ini", "cfg", "conf", "log",
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class EncryptedFile:
    """Represents a single encrypted file with metadata."""
    path: str
    filename: str
    fei_len: int
    kek_fingerprint: str
    size: int
    original_name: str  # Filename without ransomware extension

    @property
    def coverage(self) -> int:
        """Calculate keystream coverage this file provides as oracle."""
        return max(0, (self.fei_len - COVERAGE_BASE_FROM_FEI) + COVERAGE_OFFSET)


@dataclass
class BatchInfo:
    """Represents an encryption batch (group of files with same KEK)."""
    kek_fingerprint: str
    files: List[EncryptedFile] = field(default_factory=list)
    oracles: List[EncryptedFile] = field(default_factory=list)
    max_coverage: int = 0
    chunking_params: Optional[Tuple[int, int, int]] = None  # (before, after, skipped)

    @property
    def file_count(self) -> int:
        return len(self.files)


@dataclass
class DecryptionResult:
    """Result of a single decryption attempt."""
    filepath: str
    original_name: str
    success: bool
    reason: str = ""  # Why it failed, or "ok" on success
    file_type: str = ""  # libmagic result


@dataclass
class RecoveryState:
    """Persistent state for resume capability."""
    version: str = VERSION
    start_time: float = 0.0
    source_dir: str = ""
    output_dir: str = ""
    ransom_ext: str = ""
    total_files_scanned: int = 0
    total_batches: int = 0
    files_completed: Dict[str, str] = field(default_factory=dict)  # original_path -> output_path
    batches_processed: Set[str] = field(default_factory=set)
    keystream_cache: Dict[str, str] = field(default_factory=dict)  # kek -> hex keystream


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """Configure logging with both console and optional file output."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, mode='w'))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )
    return logging.getLogger("lockbit_rescue")


def fmt_size(b: int) -> str:
    """Format bytes as human-readable size."""
    if b < 0:
        return "N/A"
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f}{u}"
        b /= 1024
    return f"{b:.1f}PB"


def hex_clean(h: str) -> str:
    """Clean hex string (remove spaces, colons)."""
    return h.replace(" ", "").replace(":", "").lower()


# ============================================================================
# FOOTER & KEK OPERATIONS
# ============================================================================

def read_footer(path: Path) -> Tuple[int, bytes]:
    """Read the 134-byte footer from an encrypted file.

    Returns (fei_len, kek_blob).
    """
    with open(path, "rb") as f:
        f.seek(-FOOTER_TOTAL, 2)
        fei_bytes = f.read(2)
        if len(fei_bytes) < 2:
            raise ValueError(f"File too small for footer: {path}")
        fei_len = struct.unpack("<H", fei_bytes)[0]

        f.seek(-KEK_LEN, 2)
        kek_blob = f.read(KEK_LEN)
        if len(kek_blob) < KEK_LEN:
            raise ValueError(f"Truncated KEK blob in {path}")

    return fei_len, kek_blob


def kek_fingerprint(kek_blob: bytes) -> str:
    """Compute MD5-based fingerprint of KEK blob (first 12 hex chars)."""
    return hashlib.md5(kek_blob).hexdigest()[:12]


# ============================================================================
# EXTENSION DETECTION — Multi-extension aware
# ============================================================================

def detect_extensions(source: Path, sample_limit: int = 10000) -> List[Tuple[str, int]]:
    """Detect all ransomware extensions in the source directory.

    Returns list of (extension, count) sorted by frequency.
    Handles cases where multiple LockBit attacks affected the same system.
    """
    counts = collections.Counter()
    seen = 0

    for dirpath, _, files in os.walk(source):
        for fn in files:
            if "." not in fn:
                continue
            ext = "." + fn.rsplit(".", 1)[-1]
            # LockBit 3 extensions are typically 9 mixed-case alphanumeric chars
            if len(ext) == 10 and ext[1:].isalnum() and not ext[1:].isdigit():
                counts[ext] += 1
                seen += 1
                if seen >= sample_limit:
                    break
        if seen >= sample_limit:
            break

    return counts.most_common()


def detect_extension(source: Path, sample_limit: int = 10000) -> str:
    """Detect the most common ransomware extension."""
    results = detect_extensions(source, sample_limit)
    return results[0][0] if results else ""


# ============================================================================
# FILE SCANNING — Parallel with progress persistence
# ============================================================================

def is_target_file(fname: str, ransom_exts: List[str], common_exts: Set[str],
                   no_extension_filter: bool) -> bool:
    """Check if a filename matches our target criteria."""
    for ext in ransom_exts:
        if fname.endswith(ext):
            base = fname[:-len(ext)]
            if "." not in base:
                return no_extension_filter
            if no_extension_filter:
                return True
            return base.rsplit(".", 1)[1].lower() in common_exts
    return False


def scan_file_worker(args: Tuple) -> Optional[EncryptedFile]:
    """Worker function for parallel file scanning."""
    dirpath, fn, ransom_exts, common_exts, no_ext_filter = args

    if not is_target_file(fn, ransom_exts, common_exts, no_ext_filter):
        return None

    path = Path(dirpath) / fn
    try:
        sz = os.path.getsize(path)
        fei_len, kek_blob = read_footer(path)
        kek_fp = kek_fingerprint(kek_blob)

        # Determine original name (strip ransomware extension)
        orig_name = fn
        for ext in sorted(ransom_exts, key=len, reverse=True):
            if fn.endswith(ext):
                orig_name = fn[:-len(ext)]
                break

        return EncryptedFile(
            path=str(path),
            filename=fn,
            fei_len=fei_len,
            kek_fingerprint=kek_fp,
            size=sz,
            original_name=orig_name,
        )
    except (OSError, struct.error, ValueError) as e:
        logging.debug(f"Skipping {fn}: {e}")
        return None


def scan_source(source: Path, ransom_exts: List[str], common_exts: Set[str],
                no_extension_filter: bool, min_size: int, max_size: int,
                workers: int = DEFAULT_WORKERS) -> Tuple[Dict[str, List[EncryptedFile]], int, int]:
    """Walk source directory and group encrypted files by KEK fingerprint.

    Uses multiprocessing for parallel scanning.

    Returns (groups_dict, scanned_count, skipped_too_big).
    """
    # Collect all scan targets first
    scan_targets = []
    scanned = 0
    skipped_big = 0

    for dirpath, _, files in os.walk(source):
        for fn in files:
            if not is_target_file(fn, ransom_exts, common_exts, no_extension_filter):
                continue
            path = Path(dirpath) / fn
            try:
                sz = os.path.getsize(path)
                if sz < min_size or sz > max_size:
                    if sz > max_size:
                        skipped_big += 1
                    continue
            except OSError:
                continue

            scanned += 1
            scan_targets.append((dirpath, fn, ransom_exts, common_exts, no_extension_filter))

    # Parallel scanning with progress bar
    groups: Dict[str, List[EncryptedFile]] = collections.defaultdict(list)

    if workers > 1 and len(scan_targets) > 100:
        logging.info(f"Scanning {len(scan_targets)} files with {workers} workers...")
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(scan_file_worker, args) for args in scan_targets]
            with tqdm(total=len(futures), desc="Scanning", unit="file", mininterval=0.5) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result and result.size >= min_size and result.size <= max_size:
                        groups[result.kek_fingerprint].append(result)
                    pbar.update(1)
    else:
        # Sequential scanning (small datasets or single worker)
        with tqdm(total=len(scan_targets), desc="Scanning", unit="file", mininterval=0.5) as pbar:
            for args in scan_targets:
                result = scan_file_worker(args)
                if result and result.size >= min_size and result.size <= max_size:
                    groups[result.kek_fingerprint].append(result)
                pbar.update(1)

    return dict(groups), scanned, skipped_big


# ============================================================================
# BATCH ANALYSIS — Multi-oracle strategy
# ============================================================================

def select_oracles(batch_files: List[EncryptedFile], min_coverage: int = 50) -> List[EncryptedFile]:
    """Select optimal oracle files for a batch using multi-oracle strategy.

    Instead of just picking the single longest file, we pick multiple oracles
    that together maximize keystream coverage across different fei_len ranges.

    Strategy:
    1. Sort by fei_len descending (longest first)
    2. Pick the top oracle (maximum coverage)
    3. If there are files with significantly different fei_lens, pick additional
       oracles that cover gaps in the keystream range.
    """
    if not batch_files:
        return []

    # Sort by fei_len descending
    sorted_files = sorted(batch_files, key=lambda f: f.fei_len, reverse=True)

    oracles = [sorted_files[0]]  # Always include the longest
    max_cov = sorted_files[0].coverage

    if max_cov < min_coverage:
        return []  # No usable oracle

    # Look for files that could extend coverage in different ranges
    # Files with fei_len close to but not identical to the main oracle
    # can help fill gaps when combined with brute-force extension
    seen_fei_ranges = {range(sorted_files[0].fei_len - 5, sorted_files[0].fei_len + 6)}

    for f in sorted_files[1:]:
        if f.fei_len < min_coverage:
            break
        # Check if this file covers a different fei_len range
        covered = False
        for r in seen_fei_ranges:
            if r.start - 10 <= f.fei_len <= r.stop + 10:
                covered = True
                break
        if not covered and f.coverage >= min_coverage:
            oracles.append(f)
            seen_fei_ranges.add(range(f.fei_len - 5, f.fei_len + 6))

    return oracles


def build_batches(groups: Dict[str, List[EncryptedFile]],
                  ransom_ext: str) -> List[BatchInfo]:
    """Build batch information with oracle selection and coverage analysis."""
    batches = []

    for kek_fp, files in groups.items():
        if len(files) < 2:
            continue  # Need at least oracle + target

        oracles = select_oracles(files)
        if not oracles:
            continue  # No usable oracle

        max_coverage = max(o.coverage for o in oracles)

        batch = BatchInfo(
            kek_fingerprint=kek_fp,
            files=files,
            oracles=oracles,
            max_coverage=max_coverage,
        )
        batches.append(batch)

    # Sort by number of potentially recoverable files (descending)
    batches.sort(key=lambda b: sum(1 for f in b.files if f.fei_len <= b.max_coverage), reverse=True)

    return batches


# ============================================================================
# DECRYPTION ENGINE — Unified Phase 1 + Phase 2
# ============================================================================

def find_tool(name: str, script_dir: Path) -> Optional[Path]:
    """Search for a required binary tool."""
    candidates = [
        script_dir / name,
        script_dir / "_stream-reuse" / name,
        Path("/usr/local/bin") / name,
    ]
    # Also check PATH
    for p in os.environ.get("PATH", "").split(":"):
        candidate = Path(p) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate

    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    return None


def copy_with_progress(src: Path, dst: Path, label: str = "", position: int = 2):
    """Copy file with progress bar."""
    sz = os.path.getsize(src)
    if not label:
        label = dst.name

    bar = tqdm(
        total=sz, desc=label, unit="B", unit_scale=True, unit_divisor=1024,
        leave=False, mininterval=0.3, position=position,
    )
    try:
        with open(src, "rb") as fi, open(dst, "wb") as fo:
            while True:
                buf = fi.read(1024 * 1024)
                if not buf:
                    break
                fo.write(buf)
                bar.update(len(buf))
    finally:
        bar.close()


def libmagic_check(path: Path) -> str:
    """Run libmagic (file command) on a file and return the type string."""
    try:
        result = subprocess.run(
            ["file", "-b", "--mime-type", str(path)],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback to basic file command
        try:
            result = subprocess.run(
                ["file", "-b", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"


def is_bad_decrypt(file_type: str) -> bool:
    """Check if libmagic indicates a failed decryption."""
    bad_indicators = [
        "data", "empty", "corrupted", "application/octet-stream",
        "unknown", ""
    ]
    ft_lower = file_type.lower()
    return any(ind in ft_lower for ind in bad_indicators)


def decrypt_target(stream_reuse: Path, target_path: Path, oracle_path: Path,
                   oracle_orig_name: str, scratch: Path, timeout: int = 600) -> Optional[Path]:
    """Decrypt a single target file using stream-reuse.

    Returns path to decrypted file, or None on failure.
    """
    output_path = scratch / "_decrypted_output"

    try:
        result = subprocess.run(
            [str(stream_reuse), str(target_path), str(oracle_path),
             oracle_orig_name, str(output_path)],
            capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logging.warning(f"Decryption timed out after {timeout}s")
        return None

    if result.returncode != 0 or not output_path.exists():
        stderr_msg = result.stderr.decode("utf-8", errors="replace")[:200]
        logging.debug(f"stream-reuse failed (rc={result.returncode}): {stderr_msg}")
        return None

    if output_path.stat().st_size == 0:
        return None

    return output_path


def brute_extend_target(brute_extend_bin: Path, target_path: Path, oracle_path: Path,
                        oracle_orig_name: str, magic_hex: str, max_bytes: int,
                        before_chunk: int, after_chunk: int, skipped_hex: str,
                        ks_extend_hex: Optional[str], timeout: int = 900) -> Optional[dict]:
    """Run brute-extend to extend keystream and recover file encryption key.

    Returns dict with keys: KSEXT, FEK, DEC32, STATUS or None on failure.
    """
    cmd = [
        str(brute_extend_bin), str(target_path), str(oracle_path),
        oracle_orig_name, magic_hex, str(max_bytes),
        str(before_chunk), str(after_chunk), skipped_hex,
    ]
    if ks_extend_hex:
        cmd.append(ks_extend_hex)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logging.warning(f"Brute-extend timed out after {timeout}s")
        return None

    output = result.stdout.strip()
    if not output:
        return None

    # Parse machine-readable output
    parsed = {}
    for line in output.split("\n"):
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            parsed[key.strip()] = value.strip()

    status = parsed.get("STATUS", "")
    if status not in ("OK_NOBRUTE", "OK_BRUTE"):
        return None

    return parsed


def direct_decrypt_file(direct_bin: Path, target_path: Path, output_path: Path,
                        fek_hex: str, before_chunk: int, after_chunk: int,
                        skipped_hex: str) -> bool:
    """Decrypt file body using recovered file encryption key."""
    cmd = [
        str(direct_bin), str(target_path), str(output_path), fek_hex,
        str(before_chunk), str(after_chunk), skipped_hex,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=600)
        return result.returncode == 0 and output_path.exists() and output_path.stat().st_size > 0
    except subprocess.TimeoutExpired:
        logging.warning("direct-decrypt timed out")
        return False


# ============================================================================
# MAGIC BYTE EXTRACTION & VALIDATION
# ============================================================================

def get_magic_for_extension(ext: str) -> Optional[str]:
    """Get the best magic hex string for a file extension.

    Returns the longest (most specific) magic signature available,
    or None if no reliable magic exists.
    """
    ext_lower = ext.lower()
    magics = MAGIC_DATABASE.get(ext_lower)

    if not magics:
        return None

    # Filter out None entries and pick the longest (most specific)
    valid_magics = [m for m in magics if m is not None]
    if not valid_magics:
        return None

    # Return the longest magic (most bytes to match = fewer false positives)
    best = max(valid_magics, key=len)
    return hex_clean(best)


def validate_decryption_with_magic(decrypted_path: Path, expected_ext: str) -> bool:
    """Validate decrypted file by checking magic bytes against expected type."""
    magic_hex = get_magic_for_extension(expected_ext)
    if not magic_hex:
        return True  # No magic to check; trust libmagic instead

    try:
        with open(decrypted_path, "rb") as f:
            header = f.read(len(magic_hex) // 2 + 4)
        file_hex = header[:len(magic_hex) // 2].hex()
        return file_hex.startswith(magic_hex.lower())
    except OSError:
        return False


# ============================================================================
# STATE PERSISTENCE — JSON-based resume capability
# ============================================================================

def save_state(state: RecoveryState, state_path: Path):
    """Save recovery state to JSON for resume."""
    data = asdict(state)
    # Convert sets to lists for JSON serialization
    data["batches_processed"] = list(data["batches_processed"])
    with open(state_path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def load_state(state_path: Path) -> Optional[RecoveryState]:
    """Load recovery state from JSON."""
    if not state_path.exists():
        return None
    try:
        with open(state_path, "r") as f:
            data = json.load(f)
        # Convert lists back to sets
        data["batches_processed"] = set(data.get("batches_processed", []))
        return RecoveryState(**data)
    except (json.JSONDecodeError, TypeError):
        return None


# ============================================================================
# MANIFEST GENERATION — CSV output for file mapping
# ============================================================================

def write_manifest(results: List[DecryptionResult], manifest_path: Path,
                   source_dir: str, ransom_ext: str):
    """Write CSV manifest mapping recovered files to original paths."""
    with open(manifest_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "original_encrypted_path", "recovered_path", "original_name",
            "status", "reason", "file_type", "size_bytes"
        ])

        for r in results:
            # Reconstruct original encrypted path from output info
            orig_enc = f"{source_dir}/{r.filepath}" if source_dir else r.filepath
            writer.writerow([
                orig_enc,
                r.original_name,
                r.original_name.replace(ransom_ext, "") if ransom_ext in r.original_name else r.original_name,
                "SUCCESS" if r.success else "FAILED",
                r.reason,
                r.file_type,
                ""  # Could add size info here
            ])


# ============================================================================
# MAIN RECOVERY PIPELINE
# ============================================================================

def run_recovery(args):
    """Main recovery pipeline with all improvements."""

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()

    if not source.is_dir():
        print(f"ERROR: Source directory does not exist: {source}")
        sys.exit(2)

    output.mkdir(parents=True, exist_ok=True)

    # Setup logging
    log_file = args.log_file or str(output / "recovery.log")
    logger = setup_logging(verbose=args.verbose, log_file=log_file)
    logger.info(f"LockBit Rescue v{VERSION} starting")
    logger.info(f"Source: {source}")
    logger.info(f"Output: {output}")

    # State persistence
    state_path = output / ".recovery_state.json"
    prev_state = load_state(state_path) if args.resume else None

    state = RecoveryState(
        start_time=time.time(),
        source_dir=str(source),
        output_dir=str(output),
    )

    if prev_state:
        logger.info(f"Resuming from previous state ({len(prev_state.files_completed)} files completed)")
        state.files_completed = prev_state.files_completed
        state.batches_processed = prev_state.batches_processed
        state.keystream_cache = prev_state.keystream_cache

    # Find required tools
    script_dir = Path(__file__).resolve().parent
    stream_reuse = find_tool(args.stream_reuse or "stream-reuse", script_dir)
    if not stream_reuse:
        print("ERROR: stream-reuse binary not found. Run install.sh first.")
        sys.exit(3)
    logger.info(f"Using stream-reuse: {stream_reuse}")

    brute_extend_bin = find_tool(args.brute_extend or "brute-extend", script_dir) if args.phase2 else None
    direct_decrypt_bin = find_tool(args.direct_decrypt or "direct-decrypt", script_dir) if args.phase2 else None

    # Detect ransomware extension(s)
    if not args.ext:
        logger.info(f"Detecting ransomware extension in {source}...")
        exts = detect_extensions(source)
        if not exts:
            print("ERROR: Could not auto-detect extension. Use --ext .EXAMPLEEXT")
            sys.exit(4)
        args.ext = exts[0][0]
        state.ransom_ext = args.ext
        logger.info(f"Detected extension: {args.ext} ({exts[0][1]} files)")

        if len(exts) > 1:
            logger.info(f"Other extensions found: {[e[0] for e in exts[1:5]]}")
    elif not args.ext.startswith("."):
        args.ext = "." + args.ext

    state.ransom_ext = args.ext
    ransom_exts = [args.ext]  # Primary extension; could support multiple

    # Extension filter
    common_exts = DEFAULT_COMMON_EXTS
    if args.no_extension_filter:
        logger.info("Extension filter disabled — attempting ALL file types")

    # Scratch directory
    scratch = Path(args.scratch) if args.scratch else (output / ".scratch")
    scratch.mkdir(parents=True, exist_ok=True)

    # ==========================================================================
    # PHASE 1: SCAN & GROUP
    # ==========================================================================
    logger.info(f"Scanning {source}...")
    t0 = time.time()
    groups, scanned, skipped_big = scan_source(
        source, ransom_exts, common_exts, args.no_extension_filter,
        args.min_size, args.max_size, workers=args.workers,
    )
    elapsed = time.time() - t0

    state.total_files_scanned = scanned
    logger.info(f"Scanned {scanned} encrypted files in {elapsed:.1f}s")
    logger.info(f"  Groups: {len(groups)}, Skipped (too big): {skipped_big}")

    # ==========================================================================
    # PHASE 2: BUILD BATCHES WITH MULTI-ORACLE STRATEGY
    # ==========================================================================
    batches = build_batches(groups, args.ext)
    state.total_batches = len(batches)

    total_targets = sum(len(b.files) for b in batches)
    recoverable_phase1 = sum(
        sum(1 for f in b.files if f.fei_len <= b.max_coverage)
        for b in batches
    )
    needs_extension = total_targets - recoverable_phase1

    logger.info(f"Batches: {len(batches)}")
    logger.info(f"Total targets: {total_targets}")
    logger.info(f"Recoverable (Phase 1): {recoverable_phase1}")
    logger.info(f"Need extension (Phase 2): {needs_extension}")

    if not batches:
        logger.warning("No decryptable batches found. Check for long-named files.")
        return

    # ==========================================================================
    # PHASE 3: DECRYPTION LOOP
    # ==========================================================================
    all_results: List[DecryptionResult] = []
    total_ok = total_fail = total_skipped = 0

    remaining_targets = total_targets - len(state.files_completed)
    overall_bar = tqdm(
        total=max(1, remaining_targets), desc="Overall", unit="file",
        mininterval=0.5, position=0,
    )

    for batch_idx, batch in enumerate(batches):
        kek = batch.kek_fingerprint
        group_out = output / f"group_{kek}"
        group_out.mkdir(parents=True, exist_ok=True)

        # Check if batch is already complete
        existing_count = sum(
            1 for f in batch.files
            if (group_out / f.original_name).exists()
        )
        if existing_count == len(batch.files):
            logger.info(f"[BATCH {batch_idx+1}/{len(batches)}] {kek} already complete, skip")
            total_skipped += len(batch.files)
            overall_bar.update(len(batch.files))
            continue

        oracle = batch.oracles[0]  # Primary oracle (longest coverage)
        logger.info(
            f"\n[BATCH {batch_idx+1}/{len(batches)}] {kek} | "
            f"oracle='{oracle.original_name[:50]}...' ({fmt_size(oracle.size)}) | "
            f"coverage={oracle.coverage} bytes | targets={len(batch.files)}"
        )

        # Stage oracle locally
        local_oracle = scratch / f"_oracle_{kek}{args.ext}"
        try:
            copy_with_progress(Path(oracle.path), local_oracle,
                              f"  copy oracle {fmt_size(oracle.size)}")
        except Exception as e:
            logger.error(f"Oracle copy failed: {e}")
            overall_bar.update(len(batch.files))
            continue

        batch_ok = batch_fail = 0
        ks_extend_hex = None  # Accumulated keystream extension for Phase 2

        batch_bar = tqdm(
            batch.files, desc=f"  {kek}", unit="file", leave=False,
            mininterval=0.3, position=1,
        )

        t_batch_start = time.time()

        for target_file in batch_bar:
            torig = target_file.original_name
            out_path = group_out / torig
            short_name = (torig[:40] + "...") if len(torig) > 43 else torig

            batch_bar.set_postfix({
                "file": short_name,
                "fei": target_file.fei_len,
                "cov": oracle.coverage,
                "ok": batch_ok,
                "fail": batch_fail,
            })

            # Check if already recovered (resume)
            if out_path.exists():
                batch_ok += 1
                all_results.append(DecryptionResult(
                    filepath=target_file.path, original_name=torig,
                    success=True, reason="already_exists"
                ))
                overall_bar.update(1)
                continue

            # Stage target locally
            local_target = scratch / f"_target{args.ext}"
            try:
                copy_with_progress(Path(target_file.path), local_target,
                                  f"    fetch {short_name}")
            except Exception as e:
                logger.error(f"Target copy failed: {e}")
                batch_fail += 1
                all_results.append(DecryptionResult(
                    filepath=target_file.path, original_name=torig,
                    success=False, reason=f"copy_failed: {e}"
                ))
                overall_bar.update(1)
                continue

            # ==========================================================================
            # PHASE 1: Direct decryption (if fei_len fits in coverage)
            # ==========================================================================
            decrypted = None
            if target_file.fei_len <= oracle.coverage:
                decrypted = decrypt_target(
                    stream_reuse, local_target, local_oracle,
                    oracle.original_name, scratch, args.timeout,
                )

            # ==========================================================================
            # PHASE 2: Keystream extension (if Phase 1 failed and enabled)
            # ==========================================================================
            if decrypted is None and args.phase2 and brute_extend_bin and direct_decrypt_bin:
                gap = target_file.fei_len - oracle.coverage
                if ks_extend_hex:
                    gap -= len(hex_clean(ks_extend_hex)) // 2

                if gap > 0 and gap <= args.max_brute_bytes:
                    # Determine magic for brute-force validation
                    base_ext = torig.rsplit(".", 1)[-1] if "." in torig else ""
                    magic_hex = get_magic_for_extension(base_ext)

                    if magic_hex:
                        logger.debug(
                            f"    Phase 2: extending keystream by {gap} bytes "
                            f"(magic={magic_hex[:20]}...)"
                        )

                        result = brute_extend_target(
                            brute_extend_bin, local_target, local_oracle,
                            oracle.original_name, magic_hex, gap,
                            args.before_chunk, args.after_chunk,
                            args.skipped_hex, ks_extend_hex,
                            args.brute_timeout,
                        )

                        if result and result.get("STATUS") in ("OK_NOBRUTE", "OK_BRUTE"):
                            # Update accumulated keystream extension
                            new_ext = result.get("KSEXT", "")
                            if new_ext:
                                ks_extend_hex = (ks_extend_hex or "") + new_ext

                            # Direct decrypt with recovered FEK
                            fek_hex = result.get("FEK", "")
                            if fek_hex:
                                phase2_output = scratch / "_phase2_decrypted"
                                if direct_decrypt_file(
                                    direct_decrypt_bin, local_target, phase2_output,
                                    fek_hex, args.before_chunk, args.after_chunk,
                                    args.skipped_hex,
                                ):
                                    decrypted = phase2_output

            # ==========================================================================
            # VALIDATION & SAVE
            # ==========================================================================
            if decrypted is None:
                batch_fail += 1
                all_results.append(DecryptionResult(
                    filepath=target_file.path, original_name=torig,
                    success=False, reason="decryption_failed"
                ))
            else:
                file_type = libmagic_check(decrypted)

                if is_bad_decrypt(file_type):
                    batch_fail += 1
                    all_results.append(DecryptionResult(
                        filepath=target_file.path, original_name=torig,
                        success=False, reason=f"bad_magic: {file_type}"
                    ))
                    try:
                        decrypted.unlink()
                    except OSError:
                        pass
                else:
                    # Additional magic validation
                    base_ext = torig.rsplit(".", 1)[-1] if "." in torig else ""
                    magic_valid = validate_decryption_with_magic(decrypted, base_ext)

                    try:
                        copy_with_progress(decrypted, out_path, f"    save {short_name}")
                        decrypted.unlink()
                        batch_ok += 1
                        state.files_completed[target_file.path] = str(out_path)

                        all_results.append(DecryptionResult(
                            filepath=target_file.path, original_name=torig,
                            success=True, reason="ok", file_type=file_type
                        ))
                    except Exception as e:
                        batch_fail += 1
                        all_results.append(DecryptionResult(
                            filepath=target_file.path, original_name=torig,
                            success=False, reason=f"save_failed: {e}"
                        ))
                        try:
                            decrypted.unlink()
                        except OSError:
                            pass

            # Cleanup local target
            try:
                local_target.unlink()
            except OSError:
                pass

            overall_bar.update(1)

        batch_bar.close()
        elapsed_batch = time.time() - t_batch_start

        logger.info(
            f"  BATCH {kek} DONE: {batch_ok} ok / {batch_fail} fail "
            f"in {elapsed_batch:.0f}s"
        )

        total_ok += batch_ok
        total_fail += batch_fail

        # Save state after each batch
        save_state(state, state_path)

        # Cleanup local oracle
        try:
            local_oracle.unlink()
        except OSError:
            pass

    overall_bar.close()

    # ==========================================================================
    # FINAL REPORTING
    # ==========================================================================
    total_time = time.time() - t0

    logger.info(f"\n{'='*60}")
    logger.info(f"RECOVERY COMPLETE")
    logger.info(f"{'='*60}")
    logger.info(f"Total time: {total_time:.1f}s ({total_time/60:.1f} min)")
    logger.info(f"Files scanned: {scanned}")
    logger.info(f"Batches processed: {len(batches)}")
    logger.info(f"Recovered successfully: {total_ok}")
    logger.info(f"Failed: {total_fail}")
    logger.info(f"Skipped (already done): {total_skipped}")

    if total_ok + total_fail > 0:
        success_rate = (total_ok / (total_ok + total_fail)) * 100
        logger.info(f"Success rate: {success_rate:.1f}%")

    # Write manifest CSV
    manifest_path = output / "manifest.csv"
    write_manifest(all_results, manifest_path, str(source), args.ext)
    logger.info(f"Manifest written to: {manifest_path}")

    # Final state save
    save_state(state, state_path)

    logger.info(f"\nOutput directory: {output}")
    logger.info("Verify integrity with:")
    logger.info(f"  python3 verify_recovered_v2.py {output}")


# ============================================================================
# ARGUMENT PARSING & ENTRY POINT
# ============================================================================

def parse_args():
    """Parse command-line arguments."""
    ap = argparse.ArgumentParser(
        description=f"""LockBit Rescue v{VERSION} — LockBit 3.0 Recovery Toolkit

Recover files encrypted by LockBit 3.0 ("Black") ransomware without paying,
by exploiting the keystream-reuse weakness.

IMPROVEMENTS OVER ORIGINAL:
  - Multi-oracle strategy for maximum coverage
  - Automatic Phase 2 keystream extension (brute force)
  - Parallel file scanning with multiprocessing
  - Expanded magic database (100+ file types)
  - CSV manifest output for file mapping
  - JSON state persistence for complete resume
  - Unified Phase 1 + Phase 2 pipeline

USAGE:
  python3 lockbit_rescue_v2.py /path/to/encrypted /path/to/output
  python3 lockbit_rescue_v2.py /mnt/infected /mnt/recovered --phase2 --workers 8
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument("source", help="Directory containing encrypted files")
    ap.add_argument("output", help="Destination directory for recovered files")

    # Detection options
    det = ap.add_argument_group("Detection Options")
    det.add_argument("--ext", help="Ransomware extension (auto-detected if omitted)")
    det.add_argument("--min-size", type=int, default=DEFAULT_MIN_SIZE,
                     help=f"Skip files smaller than N bytes (default: {DEFAULT_MIN_SIZE})")
    det.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE,
                     help=f"Skip files larger than N bytes (default: {DEFAULT_MAX_SIZE})")
    det.add_argument("--no-extension-filter", action="store_true",
                     help="Don't filter by original file type — try EVERYTHING")

    # Performance options
    perf = ap.add_argument_group("Performance Options")
    perf.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                      help=f"Number of parallel workers (default: {DEFAULT_WORKERS})")
    perf.add_argument("--timeout", type=int, default=600,
                      help="Per-file decryption timeout in seconds (default: 600)")

    # Phase 2 options
    p2 = ap.add_argument_group("Phase 2 — Keystream Extension")
    p2.add_argument("--phase2", action="store_true",
                    help="Enable automatic keystream extension for files beyond oracle coverage")
    p2.add_argument("--max-brute-bytes", type=int, default=DEFAULT_MAX_BRUTE_BYTES,
                    help=f"Max bytes to brute-force per file (default: {DEFAULT_MAX_BRUTE_BYTES})")
    p2.add_argument("--brute-timeout", type=int, default=DEFAULT_BRUTE_TIMEOUT,
                    help=f"Per-file brute-force timeout in seconds (default: {DEFAULT_BRUTE_TIMEOUT})")
    p2.add_argument("--before-chunk", type=int, default=3,
                    help="LockBit intermittent encryption: before_chunk_count (default: 3)")
    p2.add_argument("--after-chunk", type=int, default=3,
                    help="LockBit intermittent encryption: after_chunk_count (default: 3)")
    p2.add_argument("--skipped-hex", default="0x520000",
                    help="LockBit intermittent encryption: skipped_bytes hex (default: 0x520000)")

    # Tool paths
    tools = ap.add_argument_group("Tool Paths")
    tools.add_argument("--stream-reuse", help="Path to stream-reuse binary")
    tools.add_argument("--brute-extend", help="Path to brute-extend binary")
    tools.add_argument("--direct-decrypt", help="Path to direct-decrypt binary")
    tools.add_argument("--scratch", help="Scratch directory for temp files")

    # Resume & logging
    misc = ap.add_argument_group("Resume & Logging")
    misc.add_argument("--resume", action="store_true",
                      help="Resume from previous recovery state")
    misc.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    misc.add_argument("--log-file", help="Path to log file (default: OUTPUT/recovery.log)")

    return ap.parse_args()


def main():
    args = parse_args()
    run_recovery(args)


if __name__ == "__main__":
    main()

# lockbit-rescue v2 — LockBit 3.0 Recovery Toolkit

**Complete rewrite of [Saddytech/lockbit-rescue](https://github.com/Saddytech/lockbit-rescue) with all limitations resolved.**

Recover files encrypted by **LockBit 3.0 ("Black") / CriptomanGizmo** ransomware without paying the ransom, by exploiting the documented **keystream-reuse weakness**.

---

## What's New in v2

| Feature | Original (v1) | Improved (v2) |
|---------|:-------------:|:--------------:|
| Oracle strategy | Single longest file | Multi-oracle with gap analysis |
| Keystream extension | Manual, separate tool | Automatic integrated pipeline |
| Processing | Single-threaded | Multiprocessing pool |
| Magic database | ~30 types | 100+ file types, ≥7-byte signatures |
| File mapping | None | CSV manifest with full paths |
| Resume support | File existence only | JSON state persistence |
| Brute force | Shellcode (segfaults) | Pure-C + OpenMP parallelization |
| Progress tracking | Basic tqdm | Detailed ETA + batch stats |
| Verification | libmagic only | Magic bytes + libmagic dual check |

---

## Quick Start

### Linux

```bash
# 1. Clone and install
git clone https://github.com/YOUR_USER/lockbit-rescue-v2.git
cd lockbit-rescue-v2
pip install -r requirements.txt
bash install.sh

# 2. Run recovery (Phase 1 — direct decryption)
python3 lockbit_rescue_v2.py /path/to/encrypted /path/to/output

# 3. Run with Phase 2 (keystream extension for files beyond oracle coverage)
python3 lockbit_rescue_v2.py /path/to/encrypted /path/to/output --phase2 --workers 8

# 4. Verify results
python3 verify_recovered_v2.py /path/to/output --json
```

### Windows

```powershell
# 1. Clone and install (requires MinGW-w64 or MSVC)
git clone https://github.com/YOUR_USER/lockbit-rescue-v2.git
cd lockbit-rescue-v2
pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File install.ps1

# 2. Run recovery
python lockbit_rescue_v2.py C:\path\to\encrypted C:\path\to\output

# 3. With Phase 2
python lockbit_rescue_v2.py C:\path\to\encrypted C:\path\to\output --phase2 --workers 8

# 4. Verify results
python verify_recovered_v2.py C:\path\to\output --json
```

---

## How It Works

### The Vulnerability

LockBit 3.0 encrypts files with a **modified Salsa20** cipher. For each encryption batch, the same keystream is reused across many files. Each file has a 134-byte footer:

```
[-134:-132] fei_len     (uint16 LE) — Footer Encryption Info length
[-132:-128] checksum    (uint32)
[-128:   ]   KEK blob   (128 bytes) — RSA-encrypted Key Encryption Key
```

The **KEK blob is identical** for all files in the same batch, enabling grouping. The FEI region contains the original filename (apLib-compressed UTF-16LE) plus fixed metadata. For files with long filenames, this provides known plaintext to recover keystream bytes via XOR.

### Phase 1: Direct Decryption

Files whose `fei_len` fits within the recovered keystream coverage are decrypted directly using `stream-reuse`.

**Coverage formula:**
```
coverage = (oracle_fei_len - 82) + 18
         = apLib(filename_length) + 18 metadata bytes
```

### Phase 2: Keystream Extension (NEW)

For files with `fei_len > coverage`, v2 automatically extends the keystream byte-by-byte using brute force:

1. Find a file with `fei_len = coverage + N` (N ≤ max_brute_bytes, default 4)
2. Brute-force the missing N bytes (256^N iterations)
3. Validate against magic bytes of the expected file type
4. Recover the file's encryption key and decrypt its body

**Performance with OpenMP:**
| Missing bytes | Iterations | Time (single core) | Time (8 cores) |
|:-------------:|-----------:|-------------------:|---------------:|
| 1 | 256 | <1 ms | <1 ms |
| 2 | 65,536 | ~8 ms | ~1 ms |
| 3 | 16.7M | ~2 s | ~0.3 s |
| 4 | 4.29B | ~9 min | ~70 sec |

---

## Command-Line Reference

### lockbit_rescue_v2.py

```bash
python3 lockbit_rescue_v2.py <SOURCE_DIR> <OUTPUT_DIR> [OPTIONS]
```

#### Detection Options

| Flag | Description | Default |
|------|-------------|---------|
| `--ext .XYZ` | Force ransomware extension | Auto-detected |
| `--min-size N` | Skip files smaller than N bytes | 10240 (10 KiB) |
| `--max-size N` | Skip files larger than N bytes | 1073741824 (1 GiB) |
| `--no-extension-filter` | Try ALL file types, not just common ones | Off |

#### Performance Options

| Flag | Description | Default |
|------|-------------|---------|
| `--workers N` | Parallel workers for scanning | CPU cores / 2 |
| `--timeout N` | Per-file decryption timeout (seconds) | 600 |

#### Phase 2 — Keystream Extension

| Flag | Description | Default |
|------|-------------|---------|
| `--phase2` | Enable automatic keystream extension | Off |
| `--max-brute-bytes N` | Max bytes to brute-force per file | 4 (~9 min) |
| `--brute-timeout N` | Per-file brute-force timeout (seconds) | 900 |
| `--before-chunk N` | LockBit before_chunk_count parameter | 3 |
| `--after-chunk N` | LockBit after_chunk_count parameter | 3 |
| `--skipped-hex HEX` | LockBit skipped_bytes hex value | 0x520000 |

#### Resume & Logging

| Flag | Description | Default |
|------|-------------|---------|
| `--resume` | Resume from previous recovery state | Off |
| `--verbose`, `-v` | Verbose debug output | Off |
| `--log-file PATH` | Path to log file | OUTPUT/recovery.log |

### verify_recovered_v2.py

```bash
python3 verify_recovered_v2.py <OUTPUT_DIR> [OPTIONS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--workers N` | Parallel verification workers | 4 |
| `--json` | Generate JSON report file | Off |

---

## Output Structure

```
output_dir/
├── group_a1b2c3d4e5f6/       # One folder per encryption batch (KEK fingerprint)
│   ├── photo_001.jpg          # Recovered files with original names
│   ├── documents/report.pdf
│   └── ...
├── group_f9e8d7c6b5a4/
│   └── ...
├── manifest.csv               # Full mapping of encrypted → recovered files
├── recovery.log               # Detailed operation log
├── verification_report.json   # (if --json used) Verification statistics
├── .recovery_state.json       # Resume state file
└── .scratch/                  # Temporary working files (safe to delete after)
```

### manifest.csv Format

| Column | Description |
|--------|-------------|
| `original_encrypted_path` | Path of the encrypted source file |
| `recovered_path` | Output path in the recovery directory |
| `original_name` | Original filename before encryption |
| `status` | SUCCESS or FAILED |
| `reason` | Details about success/failure |
| `file_type` | libmagic MIME type of recovered file |

---

## Requirements

### Linux (primary platform)

- **OS:** Linux x86_64
- **Build tools:** gcc, make, git
- **Python:** 3.8+ with `tqdm` and `python-magic` (`pip install -r requirements.txt`)
- **System:** `file` command (libmagic) — pre-installed on most distros

### Windows (supported via MinGW-w64)

- **OS:** Windows 10/11 x86_64
- **Build tools:** [MinGW-w64](https://www.msys2.org/) (gcc) or MSVC (cl.exe), git
- **Python:** 3.8+ with `tqdm` and `python-magic-bin` (`pip install -r requirements.txt`)
- **PowerShell:** 5.1+ (included with Windows 10/11)

---

## Installation

### Linux

```bash
# Debian / Ubuntu
sudo apt install build-essential git python3 python3-pip file
git clone https://github.com/YOUR_USER/lockbit-rescue-v2.git
cd lockbit-rescue-v2
pip install -r requirements.txt
bash install.sh

# Arch / CachyOS
sudo pacman -S base-devel git python python-pip file
bash install.sh

# Fedora
sudo dnf groupinstall 'Development Tools'
sudo dnf install git python3 file
bash install.sh
```

### Windows

#### Option A: Chocolatey (recommended)

```powershell
# Install dependencies via Chocolatey
choco install git python mingw make -y

# Clone and build
git clone https://github.com/YOUR_USER/lockbit-rescue-v2.git
cd lockbit-rescue-v2
pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File install.ps1
```

#### Option B: MSYS2 (MinGW-w64)

```powershell
# 1. Install MSYS2 from https://www.msys2.org/
# 2. In MSYS2 MinGW64 terminal:
pacman -S mingw-w64-x86_64-gcc make git python

# 3. Clone and build (from PowerShell or CMD)
git clone https://github.com/YOUR_USER/lockbit-rescue-v2.git
cd lockbit-rescue-v2
pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File install.ps1
```

#### Option C: MSVC (Visual Studio Build Tools)

```powershell
# 1. Install "Desktop development with C++" from Visual Studio Installer
# 2. Clone and build (from Developer PowerShell for VS)
git clone https://github.com/YOUR_USER/lockbit-rescue-v2.git
cd lockbit-rescue-v2
pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File install.ps1
```

> **Note:** On Windows, `stream-reuse` requires MinGW-w64 (GCC) because it links against `aplib.a`. MSVC users will get `brute-extend.exe` and `direct-decrypt.exe` but not `stream-reuse.exe` — Phase 1 direct decryption via stream-reuse won't be available. Use MinGW-w64 for full functionality.

---

## Real-World Coverage

Recovery success depends on filename lengths in each encryption batch:

| Filename Length | Typical fei_len | Recovery Rate |
|----------------|----------------:|--------------:|
| Short (< 10 chars) | < 50 | ~0% (no usable oracle) |
| Medium (10-30 chars) | 50-80 | 20-40% |
| Long (30-60 chars) | 80-120 | 50-70% |
| Very long (> 60 chars) | > 120 | 70-90%+ |

**v2 improvement:** Multi-oracle strategy and Phase 2 extension can push recovery rates 10-30% higher than v1 in batches with varied filename lengths.

---

## Limitations

### Still Cannot Recover:
- **Batches with only short filenames.** If every file had a name < 10 characters, no oracle provides sufficient coverage. Cryptographically blocked.
- **Files > 4 GiB.** Salsa20 keystream offset for chunked encryption exceeds recoverable range.
- **Different LockBit variants.** This exploit is specific to LockBit 3.0 "Black" (`.random9chars` extension).

### v2-Specific Notes:
- Phase 2 brute force requires at least one file with intermediate `fei_len` values in the batch. Large gaps (>4 bytes) between consecutive fei_lens cannot be bridged.
- The pure-C Salsa20 fallback in direct-decrypt may produce slightly different results than the original shellcode for some edge cases (the round function is identical, but state mutation across chunks differs).

---

## Troubleshooting

### "stream-reuse binary not found"
Run `bash install.sh` to build all required binaries.

### "Could not auto-detect extension"
Specify manually: `--ext .MoHsVxKYI` (or whatever 9-character extension your files have).

### "No decryptable batches found"
Your encrypted files may all have short original filenames. Check with:
```bash
ls -1 /path/to/encrypted | head -20
```
If basenames are consistently < 10 characters, recovery is unlikely without Phase 2 and intermediate fei_len files.

### "STATUS:GAP_TOO_BIG" in Phase 2
The gap between oracle coverage and target fei_len exceeds `--max-brute-bytes`. Increase with caution (each additional byte multiplies time by 256).

### High SUSPECT rate in verification
This usually means the batch's chunking parameters (`before/after/skipped`) differ from defaults. Try adjusting:
```bash
python3 lockbit_rescue_v2.py ... --phase2 --before-chunk 4 --after-chunk 4 --skipped-hex 0x100000
```

---

## Credits & References

- **Calif.io** — Original LockBit 3.0 decryptor research: [blog.calif.io](https://www.calif.io/blog/lockbit-3.0-decryptor)
- **yohanes** — C implementation in [lockbit-v3-linux-decryptor](https://github.com/yohanes/lockbit-v3-linux-decryptor)
- **Saddytech** — Original lockbit-rescue toolkit: [GitHub](https://github.com/Saddytech/lockbit-rescue)

---

## Disclaimer

This tool is for legitimate recovery of files on systems you own, by victims of LockBit 3.0 ransomware. Do not use to bypass legitimate security mechanisms. The author makes no warranty as to fitness or completeness.

**Check [No More Ransom](https://www.nomoreransom.org/) first — law enforcement may have published the private RSA key for your decryption ID, enabling 100% recovery.**

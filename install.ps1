# lockbit-rescue-v2 installer (Windows)
# ======================================
# Builds all required binaries and installs Python dependencies.
#
# Usage:   powershell -ExecutionPolicy Bypass -File install.ps1
# Requires: MinGW-w64 (gcc) or MSVC (cl.exe), Python 3.8+, git
#
# To install MinGW-w64:
#   - Via MSYS2: https://www.msys2.org/
#     pacman -S mingw-w64-x86_64-gcc make
#   - Via Chocolatey: choco install mingw make

$ErrorActionPreference = "Stop"

$Here = $PSScriptRoot
$UpstreamDir = Join-Path $Here "_stream-reuse"
$UpstreamRepo = "https://github.com/yohanes/lockbit-v3-linux-decryptor.git"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  lockbit-rescue v2 Installer (Windows)" -ForegroundColor Cyan
Write-Host "  Target: $Here" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ============================================================================
# Dependency checks
# ============================================================================

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host ""
Write-Host "[*] Checking system dependencies..."

$Missing = @()

if (-not (Test-Command "git"))       { $Missing += "git" }
if (-not (Test-Command "python"))    { $Missing += "python" }
if (-not (Test-Command "gcc") -and -not (Test-Command "cl")) { $Missing += "gcc or cl.exe (MinGW-w64 or MSVC)" }

# make is optional — we can use gcc directly if missing
$HasMake = Test-Command "make"
if (-not $HasMake) {
    Write-Host "[!] 'make' not found — will compile with direct gcc commands" -ForegroundColor Yellow
}

if ($Missing.Count -gt 0) {
    Write-Host ""
    Write-Host "ERROR: Missing dependencies:" -ForegroundColor Red
    foreach ($m in $Missing) {
        Write-Host "  - $m" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Install via Chocolatey (recommended):" -ForegroundColor Yellow
    Write-Host "  choco install git python mingw make" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Or manually:" -ForegroundColor Yellow
    Write-Host "  Git:     https://git-scm.com/download/win" -ForegroundColor Gray
    Write-Host "  Python:  https://www.python.org/downloads/" -ForegroundColor Gray
    Write-Host "  MinGW:   https://www.msys2.org/ (then: pacman -S mingw-w64-x86_64-gcc make)" -ForegroundColor Gray
    exit 1
}

Write-Host "[+] All required dependencies found" -ForegroundColor Green

# Detect compiler
$Compiler = "gcc"
if (Test-Command "cl") {
    $Compiler = "cl"
    Write-Host "[+] MSVC (cl.exe) detected" -ForegroundColor Green
} else {
    Write-Host "[+] GCC (MinGW-w64) detected: $(gcc --version | Select-Object -First 1)" -ForegroundColor Green
}

# Check for OpenMP support (GCC only)
$OpenmpFlag = ""
if ($Compiler -eq "gcc") {
    $TestCode = @"
#include <omp.h>
int main() { return 0; }
"@
    $TmpFile = [System.IO.Path]::GetTempFileName() + ".c"
    Set-Content -Path $TmpFile -Value $TestCode -Encoding ASCII
    try {
        gcc -fopenmp -x c - -o "$env:TEMP\omp_test.exe" $TmpFile 2>$null
        if ($LASTEXITCODE -eq 0) {
            $OpenmpFlag = "-fopenmp"
            Write-Host "[+] OpenMP supported — brute force will use multiple cores" -ForegroundColor Green
        } else {
            Write-Host "[!] OpenMP not available — brute force will be single-threaded" -ForegroundColor Yellow
        }
    } finally {
        Remove-Item $TmpFile -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\omp_test.exe" -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# Python dependencies
# ============================================================================

Write-Host ""
Write-Host "[*] Checking Python dependencies..."

if (-not (python -c "import tqdm" 2>$null)) {
    Write-Host "[*] Installing tqdm..."
    python -m pip install --user tqdm
}

# python-magic-bin for Windows (includes libmagic DLL)
if (-not (python -c "import magic" 2>$null)) {
    Write-Host "[*] Installing python-magic-bin (Windows-compatible file type detection)..."
    python -m pip install --user python-magic-bin
}

# ============================================================================
# Clone upstream decryptor
# ============================================================================

Write-Host ""
Write-Host "[*] Setting up upstream decryptor..."

if (-not (Test-Path (Join-Path $UpstreamDir ".git"))) {
    Write-Host "    Cloning: $UpstreamRepo"
    git clone --depth=1 $UpstreamRepo $UpstreamDir
} else {
    Write-Host "    Updating existing clone..."
    Push-Location $UpstreamDir
    git pull --ff-only 2>$null
    Pop-Location
}

# ============================================================================
# Rebuild aplib.a for native architecture (64-bit) if needed
# ============================================================================

Write-Host ""
Write-Host "[*] Checking aplib library architecture..."

$AplibPath = Join-Path $UpstreamDir "aplib.a"
if (Test-Path $AplibPath) {
    # Check file type using Python (cross-platform way to detect PE vs ELF arch)
    try {
        $ArchInfo = python -c "
import struct, sys
with open('$AplibPath', 'rb') as f:
    data = f.read(20)
# ELF magic check
if data[:4] == b'\x7fELF':
    bits = '64-bit' if data[4] == 2 else '32-bit'
    print(f'ELF {bits}')
else:
    # ar archive — check first object inside
    print('ar-archive')
" 2>$null
        Write-Host "    aplib.a detected as: $ArchInfo" -ForegroundColor Gray

        if ($ArchInfo -match '32-bit|PE32') {
            Write-Host "[!] aplib.a is 32-bit — rebuilding for x86_64..." -ForegroundColor Yellow

            # Download and compile aplib source
            $AplibSrcDir = Join-Path $UpstreamDir "aplib-src"
            if (-not (Test-Path $AplibSrcDir)) {
                Write-Host "    Downloading aPLib source..."
                $TmpZip = [System.IO.Path]::GetTempFileName() + ".zip"
                try {
                    Invoke-WebRequest -Uri "http://www.ibsensoftware.com/files/aPLib-1.1.1.zip" `
                        -OutFile $TmpZip -ErrorAction Stop | Out-Null

                    # Extract to aplib-src directory
                    Expand-Archive -Path $TmpZip -DestinationPath $AplibSrcDir -Force 2>$null
                } catch {
                    Write-Host "[!] Failed to download aPLib source" -ForegroundColor Red
                    Write-Host "    Manual: Download from http://www.ibsensoftware.com/files/aPLib-1.1.1.zip" -ForegroundColor Yellow
                } finally {
                    Remove-Item $TmpZip -ErrorAction SilentlyContinue
                }
            }

            # Compile aplib for x86_64
            if (Test-Path (Join-Path $AplibSrcDir "aplib.c")) {
                Write-Host "    Compiling aPLib for x86_64..."
                gcc -O2 -c -o "$UpstreamDir\aplib.o" "$AplibSrcDir\aplib.c" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    ar rcs $AplibPath "$UpstreamDir\aplib.o" 2>$null
                    Remove-Item "$UpstreamDir\aplib.o" -ErrorAction SilentlyContinue
                    Write-Host "[+] aplib.a rebuilt for x86_64 successfully" -ForegroundColor Green
                } else {
                    Write-Host "[!] Failed to compile aPLib" -ForegroundColor Red
                }
            } else {
                Write-Host "[!] aPLib source not found at $AplibSrcDir" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[+] aplib.a architecture OK" -ForegroundColor Green
        }
    } catch {
        Write-Host "[?] Could not detect aplib.a architecture — proceeding anyway" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] aplib.a not found — binaries requiring it will fail" -ForegroundColor Red
}

# ============================================================================
# Build stream-reuse (upstream)
# ============================================================================

Write-Host ""
Write-Host "[*] Building stream-reuse..."

$StreamReuseSrc = Join-Path $UpstreamDir "stream-reuse.c"
$AplibLib = Join-Path $UpstreamDir "aplib.a"
$StreamReuseOut = Join-Path $UpstreamDir "stream-reuse.exe"

if ($Compiler -eq "gcc") {
    gcc -O0 -fno-stack-protector -D_FILE_OFFSET_BITS=64 `
        -o $StreamReuseOut $StreamReuseSrc $AplibLib 2>&1
} else {
    # MSVC doesn't support .a libraries directly — skip stream-reuse for now
    Write-Host "[!] MSVC detected: stream-reuse requires aplib.a (GCC format)" -ForegroundColor Yellow
    Write-Host "    Skipping stream-reuse build. Use MinGW-w64 for full functionality." -ForegroundColor Yellow
}

if (Test-Path $StreamReuseOut) {
    Write-Host "[+] stream-reuse.exe built successfully" -ForegroundColor Green
} else {
    Write-Host "[!] Failed to build stream-reuse" -ForegroundColor Red
}

# ============================================================================
# Build brute_extend_v2 (our optimized version)
# ============================================================================

Write-Host ""
Write-Host "[*] Building brute_extend_v2..."

$BruteSrc = Join-Path $Here "src\brute_extend_v2.c"
$BruteOut = Join-Path $UpstreamDir "brute_extend_v2.exe"

if (Test-Path $BruteSrc) {
    Copy-Item -Force $BruteSrc (Join-Path $UpstreamDir "brute_extend_v2.c")

    if ($Compiler -eq "gcc") {
        gcc -O2 $OpenmpFlag `
            -o $BruteOut `
            (Join-Path $UpstreamDir "brute_extend_v2.c") `
            $AplibLib `
            -fno-stack-protector `
            -D_FILE_OFFSET_BITS=64 2>&1
    } else {
        cl /O2 /D_FILE_OFFSET_BITS=64 `
           /Fe:$BruteOut `
           (Join-Path $UpstreamDir "brute_extend_v2.c") 2>&1
    }

    if (Test-Path $BruteOut) {
        Write-Host "[+] brute_extend_v2.exe built successfully" -ForegroundColor Green
    } else {
        Write-Host "[!] Failed to build brute_extend_v2 (Phase 2 will be unavailable)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] src/brute_extend_v2.c not found — skipping" -ForegroundColor Yellow
}

# ============================================================================
# Build direct_decrypt_v2 (our optimized version)
# ============================================================================

Write-Host ""
Write-Host "[*] Building direct_decrypt_v2..."

$DirectSrc = Join-Path $Here "src\direct_decrypt_v2.c"
$DirectOut = Join-Path $UpstreamDir "direct_decrypt_v2.exe"

if (Test-Path $DirectSrc) {
    Copy-Item -Force $DirectSrc (Join-Path $UpstreamDir "direct_decrypt_v2.c")

    $HaveFrankH = Test-Path (Join-Path $UpstreamDir "frank.h")
    $DefineFrank = if ($HaveFrankH) { "/DHAVE_FRANK_H" } else { "" }

    if ($Compiler -eq "gcc") {
        # Try with frank.h first, then fallback to pure-C
        gcc -O0 `
            -o $DirectOut `
            (Join-Path $UpstreamDir "direct_decrypt_v2.c") `
            -fno-stack-protector `
            -D_FILE_OFFSET_BITS=64 `
            -DHAVE_FRANK_H 2>$null

        if (-not (Test-Path $DirectOut)) {
            # Fallback: pure-C Salsa20 (no shellcode)
            gcc -O2 `
                -o $DirectOut `
                (Join-Path $UpstreamDir "direct_decrypt_v2.c") `
                -fno-stack-protector `
                -D_FILE_OFFSET_BITS=64 2>&1
        }
    } else {
        cl /O2 /D_FILE_OFFSET_BITS=64 $DefineFrank `
           /Fe:$DirectOut `
           (Join-Path $UpstreamDir "direct_decrypt_v2.c") 2>&1
    }

    if (Test-Path $DirectOut) {
        Write-Host "[+] direct_decrypt_v2.exe built successfully" -ForegroundColor Green
    } else {
        Write-Host "[!] Failed to build direct_decrypt_v2 (Phase 2 will be unavailable)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] src/direct_decrypt_v2.c not found — skipping" -ForegroundColor Yellow
}

# ============================================================================
# Copy binaries to project root (Windows: copy instead of symlink)
# ============================================================================

Write-Host ""
Write-Host "[*] Setting up tool shortcuts..."

$Tools = @{
    "stream-reuse.exe"       = Join-Path $UpstreamDir "stream-reuse.exe"
    "brute-extend.exe"       = Join-Path $UpstreamDir "brute_extend_v2.exe"
    "direct-decrypt.exe"     = Join-Path $UpstreamDir "direct_decrypt_v2.exe"
}

foreach ($Name in $Tools.Keys) {
    $Src = $Tools[$Name]
    $Dst = Join-Path $Here $Name
    if (Test-Path $Src) {
        Copy-Item -Force $Src $Dst
        Write-Host "  [+] $Name -> copied" -ForegroundColor Green
    } else {
        Write-Host "  [-] $Name -> source not found" -ForegroundColor Yellow
    }
}

# ============================================================================
# Verification
# ============================================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Build Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

$CheckTools = @("stream-reuse.exe", "brute-extend.exe", "direct-decrypt.exe")
foreach ($Tool in $CheckTools) {
    $Path = Join-Path $Here $Tool
    if (Test-Path $Path) {
        $Size = (Get-Item $Path).Length
        Write-Host "[+] $Tool : OK ($([math]::Round($Size/1024, 1)) KB)" -ForegroundColor Green
    } else {
        Write-Host "[-] $Tool : MISSING" -ForegroundColor Red
    }
}

Write-Host ""
$PyVer = python --version 2>&1
Write-Host "[+] Python: $PyVer" -ForegroundColor Green

try {
    $TqdmVer = python -c "import tqdm; print(tqdm.__version__)" 2>$null
    Write-Host "[+] tqdm:   $TqdmVer" -ForegroundColor Green
} catch {
    Write-Host "[?] tqdm:   installed (version check failed)" -ForegroundColor Yellow
}

try {
    python -c "import magic; print(magic.from_file('$Here\install.ps1', mime=True))" 2>$null | Out-Null
    Write-Host "[+] magic:  available (python-magic-bin)" -ForegroundColor Green
} catch {
    Write-Host "[?] magic:  not installed — subprocess fallback will be used" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Ready to use!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Basic usage:" -ForegroundColor White
Write-Host "  python $Here\lockbit_rescue_v2.py C:\path\to\encrypted C:\path\to\output" -ForegroundColor Gray
Write-Host ""
Write-Host "With Phase 2 (keystream extension):" -ForegroundColor White
Write-Host "  python $Here\lockbit_rescue_v2.py C:\path\to\encrypted C:\path\to\output --phase2" -ForegroundColor Gray
Write-Host ""
Write-Host "Verify recovered files:" -ForegroundColor White
Write-Host "  python $Here\verify_recovered_v2.py C:\path\to\output" -ForegroundColor Gray

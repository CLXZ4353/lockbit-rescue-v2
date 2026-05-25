#!/usr/bin/env bash
#
# lockbit-rescue-v2 installer
# ============================
# Builds all required binaries and installs Python dependencies.
#
# Usage:   bash install.sh
# Tested:  Linux x86_64; works on Debian/Ubuntu/Arch/CachyOS/Fedora.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM_DIR="${HERE}/_stream-reuse"
UPSTREAM_REPO="https://github.com/yohanes/lockbit-v3-linux-decryptor.git"

echo "============================================"
echo "  lockbit-rescue v2 Installer"
echo "  Target: ${HERE}"
echo "============================================"

# ============================================================================
# Dependency checks
# ============================================================================

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: Missing '$1'. Install via your package manager:"
        case "$1" in
            gcc)     echo "  Debian/Ubuntu: sudo apt install build-essential" ;;
            make)    echo "  Arch/CachyOS:  sudo pacman -S base-devel" ;;
            git)     echo "  Fedora:        sudo dnf groupinstall 'Development Tools'" ;;
            python3) echo "  All distros:   your package manager" ;;
            file)    echo "  Debian/Ubuntu: sudo apt install file" ;;
            *)       echo "  Install '$1' via your package manager" ;;
        esac
        exit 1;
    }
}

echo ""
echo "[*] Checking system dependencies..."
need git
need make
need gcc
need file
need python3

# Check for OpenMP support (optional but recommended)
if gcc -fopenmp -x c - -o /dev/null 2>/dev/null << 'EOF'
#include <omp.h>
int main() { return 0; }
EOF
then
    OPENMP_FLAG="-fopenmp"
    echo "[+] OpenMP supported — brute force will use multiple cores"
else
    OPENMP_FLAG=""
    echo "[!] OpenMP not available — brute force will be single-threaded"
fi

# ============================================================================
# Python dependencies
# ============================================================================

echo ""
echo "[*] Checking Python dependencies..."

if ! python3 -c "import tqdm" >/dev/null 2>&1; then
    echo "[*] Installing tqdm..."
    pip install --user tqdm || pip3 install --user tqdm || {
        echo "ERROR: Could not install tqdm. Try: pip install --user tqdm"
        exit 1
    }
fi

# ============================================================================
# Clone upstream decryptor
# ============================================================================

echo ""
echo "[*] Setting up upstream decryptor..."

if [ ! -d "${UPSTREAM_DIR}/.git" ]; then
    echo "    Cloning: ${UPSTREAM_REPO}"
    git clone --depth=1 "${UPSTREAM_REPO}" "${UPSTREAM_DIR}"
else
    echo "    Updating existing clone..."
    git -C "${UPSTREAM_DIR}" pull --ff-only 2>/dev/null || true
fi

# ============================================================================
# Build stream-reuse (upstream)
# ============================================================================

echo ""
echo "[*] Building stream-reuse..."
make -C "${UPSTREAM_DIR}" stream-reuse 2>&1 | tail -3

if [ ! -f "${UPSTREAM_DIR}/stream-reuse" ]; then
    echo "ERROR: Failed to build stream-reuse"
    exit 1
fi

# ============================================================================
# Build brute_extend_v2 (our optimized version)
# ============================================================================

echo ""
echo "[*] Building brute_extend_v2..."

if [ -f "${HERE}/src/brute_extend_v2.c" ]; then
    cp -f "${HERE}/src/brute_extend_v2.c" "${UPSTREAM_DIR}/brute_extend_v2.c"

    gcc -O2 ${OPENMP_FLAG} \
        -o "${UPSTREAM_DIR}/brute_extend_v2" \
        "${UPSTREAM_DIR}/brute_extend_v2.c" \
        "${UPSTREAM_DIR}/aplib.a" \
        -m32 -fno-stack-protector \
        -D_FILE_OFFSET_BITS=64 \
        -liconv 2>/dev/null || \
    gcc -O2 ${OPENMP_FLAG} \
        -o "${UPSTREAM_DIR}/brute_extend_v2" \
        "${UPSTREAM_DIR}/brute_extend_v2.c" \
        "${UPSTREAM_DIR}/aplib.a" \
        -m32 -fno-stack-protector \
        -D_FILE_OFFSET_BITS=64

    if [ -f "${UPSTREAM_DIR}/brute_extend_v2" ]; then
        echo "[+] brute_extend_v2 built successfully"
    else
        echo "[!] Failed to build brute_extend_v2 (Phase 2 will be unavailable)"
    fi
else
    echo "[!] src/brute_extend_v2.c not found — skipping"
fi

# ============================================================================
# Build direct_decrypt_v2 (our optimized version)
# ============================================================================

echo ""
echo "[*] Building direct_decrypt_v2..."

if [ -f "${HERE}/src/direct_decrypt_v2.c" ]; then
    cp -f "${HERE}/src/direct_decrypt_v2.c" "${UPSTREAM_DIR}/direct_decrypt_v2.c"

    # Try with frank.h first (shellcode support)
    if [ -f "${UPSTREAM_DIR}/frank.h" ]; then
        gcc -O0 \
            -o "${UPSTREAM_DIR}/direct_decrypt_v2" \
            "${UPSTREAM_DIR}/direct_decrypt_v2.c" \
            -m32 -z execstack -fno-stack-protector -no-pie \
            -Wl,-z,norelro -static \
            -D_FILE_OFFSET_BITS=64 \
            -DHAVE_FRANK_H 2>/dev/null || {
                # Fallback without static linking but WITH shellcode support
                gcc -O0 \
                    -o "${UPSTREAM_DIR}/direct_decrypt_v2" \
                    "${UPSTREAM_DIR}/direct_decrypt_v2.c" \
                    -m32 -z execstack -fno-stack-protector \
                    -D_FILE_OFFSET_BITS=64 \
                    -DHAVE_FRANK_H 2>/dev/null || {
                        # Final fallback: pure-C Salsa20 (no shellcode)
                        gcc -O2 \
                            -o "${UPSTREAM_DIR}/direct_decrypt_v2" \
                            "${UPSTREAM_DIR}/direct_decrypt_v2.c" \
                            -m32 -fno-stack-protector \
                            -D_FILE_OFFSET_BITS=64
                    }
            }
    else
        # Build without shellcode support (pure-C fallback)
        gcc -O2 \
            -o "${UPSTREAM_DIR}/direct_decrypt_v2" \
            "${UPSTREAM_DIR}/direct_decrypt_v2.c" \
            -m32 -fno-stack-protector \
            -D_FILE_OFFSET_BITS=64
    fi

    if [ -f "${UPSTREAM_DIR}/direct_decrypt_v2" ]; then
        echo "[+] direct_decrypt_v2 built successfully"
    else
        echo "[!] Failed to build direct_decrypt_v2 (Phase 2 will be unavailable)"
    fi
else
    echo "[!] src/direct_decrypt_v2.c not found — skipping"
fi

# ============================================================================
# Create symlinks
# ============================================================================

echo ""
echo "[*] Creating tool symlinks..."

ln -sfn "${UPSTREAM_DIR}/stream-reuse"       "${HERE}/stream-reuse"
ln -sfn "${UPSTREAM_DIR}/brute_extend_v2"    "${HERE}/brute-extend"
ln -sfn "${UPSTREAM_DIR}/direct_decrypt_v2"  "${HERE}/direct-decrypt"

chmod +x "${HERE}/lockbit_rescue_v2.py" "${HERE}/verify_recovered_v2.py" 2>/dev/null || true

# ============================================================================
# Verification
# ============================================================================

echo ""
echo "============================================"
echo "  Build Summary"
echo "============================================"

check_tool() {
    if [ -x "$1" ]; then
        echo "[+] $(basename $1): OK ($(file -b $1 | head -c 60))"
    else
        echo "[-] $(basename $1): MISSING"
    fi
}

check_tool "${HERE}/stream-reuse"
check_tool "${HERE}/brute-extend"
check_tool "${HERE}/direct-decrypt"

echo ""
echo "[+] Python: $(python3 --version 2>&1)"
echo "[+] tqdm:   $(python3 -c 'import tqdm; print(tqdm.__version__)' 2>/dev/null || echo 'installed')"

echo ""
echo "============================================"
echo "  Ready to use!"
echo "============================================"
echo ""
echo "Basic usage:"
echo "  python3 ${HERE}/lockbit_rescue_v2.py /path/to/encrypted /path/to/output"
echo ""
echo "With Phase 2 (keystream extension):"
echo "  python3 ${HERE}/lockbit_rescue_v2.py /path/to/encrypted /path/to/output --phase2"
echo ""
echo "Verify recovered files:"
echo "  python3 ${HERE}/verify_recovered_v2.py /path/to/output"

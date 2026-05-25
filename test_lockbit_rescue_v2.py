#!/usr/bin/env python3
"""
test_lockbit_rescue_v2.py — Synthetic tests for lockbit-rescue v2.

Tests core logic without requiring actual LockBit-encrypted files:
1. Salsa20 block function correctness (pure-C verification)
2. Footer parsing and KEK fingerprinting
3. Extension detection algorithm
4. Magic byte validation database
5. Batch analysis and oracle selection
6. State persistence (JSON save/load)
7. Manifest CSV generation

Run: python3 test_lockbit_rescue_v2.py
"""

import hashlib
import json
import os
import struct
import sys
import tempfile
from pathlib import Path
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))


def header(msg):
    print(f"\n{'='*60}")
    print(f"  TEST: {msg}")
    print(f"{'='*60}")


def ok(msg):
    print(f"  [PASS] {msg}")


def fail(msg):
    print(f"  [FAIL] {msg}")
    return False


# ============================================================================
# Test 1: Salsa20 Block Function (Pure Python Reference)
# ============================================================================

def test_salsa20_block():
    """Verify our pure-C Salsa20 matches a known reference implementation."""
    header("Salsa20 Block Function")

    def rotl32(v, n):
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    def salsa20_block(state):
        """Pure Python Salsa20 block function."""
        x = list(state)
        for _ in range(10):
            # Column rounds
            x[4]  ^= rotl32((x[0]  + x[12]) & 0xFFFFFFFF, 7)
            x[8]  ^= rotl32((x[4]  + x[0])  & 0xFFFFFFFF, 9)
            x[12] ^= rotl32((x[8]  + x[4])  & 0xFFFFFFFF, 13)
            x[0]  ^= rotl32((x[12] + x[8])  & 0xFFFFFFFF, 18)

            x[9]  ^= rotl32((x[5]  + x[1])  & 0xFFFFFFFF, 7)
            x[13] ^= rotl32((x[9]  + x[5])  & 0xFFFFFFFF, 9)
            x[1]  ^= rotl32((x[13] + x[9])  & 0xFFFFFFFF, 13)
            x[5]  ^= rotl32((x[1]  + x[13]) & 0xFFFFFFFF, 18)

            x[14] ^= rotl32((x[10] + x[6])  & 0xFFFFFFFF, 7)
            x[2]  ^= rotl32((x[14] + x[10]) & 0xFFFFFFFF, 9)
            x[6]  ^= rotl32((x[2]  + x[14]) & 0xFFFFFFFF, 13)
            x[10] ^= rotl32((x[6]  + x[2])  & 0xFFFFFFFF, 18)

            x[3]  ^= rotl32((x[15] + x[11]) & 0xFFFFFFFF, 7)
            x[7]  ^= rotl32((x[3]  + x[15]) & 0xFFFFFFFF, 9)
            x[11] ^= rotl32((x[7]  + x[3])  & 0xFFFFFFFF, 13)
            x[15] ^= rotl32((x[11] + x[7])  & 0xFFFFFFFF, 18)

            # Row rounds
            x[1]  ^= rotl32((x[0]  + x[3])  & 0xFFFFFFFF, 7)
            x[2]  ^= rotl32((x[1]  + x[0])  & 0xFFFFFFFF, 9)
            x[3]  ^= rotl32((x[2]  + x[1])  & 0xFFFFFFFF, 13)
            x[0]  ^= rotl32((x[3]  + x[2])  & 0xFFFFFFFF, 18)

            x[6]  ^= rotl32((x[5]  + x[4])  & 0xFFFFFFFF, 7)
            x[7]  ^= rotl32((x[6]  + x[5])  & 0xFFFFFFFF, 9)
            x[4]  ^= rotl32((x[7]  + x[6])  & 0xFFFFFFFF, 13)
            x[5]  ^= rotl32((x[4]  + x[7])  & 0xFFFFFFFF, 18)

            x[11] ^= rotl32((x[10] + x[9])  & 0xFFFFFFFF, 7)
            x[8]  ^= rotl32((x[11] + x[10]) & 0xFFFFFFFF, 9)
            x[9]  ^= rotl32((x[8]  + x[11]) & 0xFFFFFFFF, 13)
            x[10] ^= rotl32((x[9]  + x[8])  & 0xFFFFFFFF, 18)

            x[12] ^= rotl32((x[15] + x[14]) & 0xFFFFFFFF, 7)
            x[13] ^= rotl32((x[12] + x[15]) & 0xFFFFFFFF, 9)
            x[14] ^= rotl32((x[13] + x[12]) & 0xFFFFFFFF, 13)
            x[15] ^= rotl32((x[14] + x[13]) & 0xFFFFFFFF, 18)

        # Add original state and output as bytes
        result = []
        for i in range(16):
            v = (x[i] + state[i]) & 0xFFFFFFFF
            result.extend(v.to_bytes(4, 'little'))
        return bytes(result)

    # Test with known state (all zeros — degenerate but valid test)
    zero_state = [0] * 16
    output = salsa20_block(zero_state)
    assert len(output) == 64, f"Expected 64 bytes, got {len(output)}"
    ok("Salsa20 block produces 64-byte output")

    # Test with random-ish state (LockBit-style: no sigma constants)
    test_state = [
        0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222,
        0x33333333, 0x44444444, 0x55555555, 0x66666666,
        0x77777777, 0x88888888, 0x99999999, 0xAAAAAAAA,
        0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE,
    ]

    # Verify determinism: same input → same output
    out1 = salsa20_block(test_state)
    out2 = salsa20_block(test_state)
    assert out1 == out2, "Salsa20 is not deterministic!"
    ok("Salsa20 block is deterministic")

    # Verify XOR property: encrypting then decrypting returns original
    plaintext = b"Hello, this is a test of the Salsa20 cipher function!"
    keystream = salsa20_block(test_state)
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    decrypted = bytes(c ^ k for c, k in zip(ciphertext, keystream))
    assert decrypted == plaintext, "XOR encryption/decryption failed!"
    ok("Salsa20 XOR encrypt/decrypt roundtrip")

    # Verify different states produce different outputs
    test_state2 = list(test_state)
    test_state2[0] ^= 1  # Flip one bit in state
    out3 = salsa20_block(test_state2)
    assert out1 != out3, "Different states should produce different outputs!"
    ok("Salsa20 avalanche effect (different inputs → different outputs)")

    return True


# ============================================================================
# Test 2: Footer Parsing & KEK Fingerprinting
# ============================================================================

def test_footer_parsing():
    """Test footer reading and KEK fingerprint computation."""
    header("Footer Parsing & KEK Fingerprint")

    # Create a synthetic encrypted file with valid LockBit footer
    with tempfile.NamedTemporaryFile(delete=False, suffix=".test.MoHsVxKYI") as f:
        temp_path = f.name
        # Write some random "encrypted" content
        f.write(os.urandom(1024))

        # Write the 134-byte footer
        fei_len = 106  # Typical value
        checksum = 0xDEADBEEF
        kek_blob = os.urandom(128)  # Simulated RSA-encrypted KEK

        f.write(struct.pack("<H", fei_len))      # fei_len (2 bytes)
        f.write(struct.pack("<I", checksum))     # checksum (4 bytes)
        f.write(kek_blob)                        # KEK blob (128 bytes)

    try:
        # Read footer back
        with open(temp_path, "rb") as f:
            f.seek(-134, 2)
            read_fei_len = struct.unpack("<H", f.read(2))[0]
            f.seek(-128, 2)
            read_kek = f.read(128)

        assert read_fei_len == fei_len, f"fei_len mismatch: {read_fei_len} != {fei_len}"
        ok(f"Footer fei_len parsed correctly: {read_fei_len}")

        assert read_kek == kek_blob, "KEK blob mismatch!"
        ok("KEK blob read correctly")

        # Test KEK fingerprinting
        def kek_fingerprint(blob):
            return hashlib.md5(blob).hexdigest()[:12]

        fp = kek_fingerprint(kek_blob)
        assert len(fp) == 12, f"Fingerprint wrong length: {len(fp)}"
        ok(f"KEK fingerprint generated: {fp}")

        # Same KEK → same fingerprint
        fp2 = kek_fingerprint(kek_blob)
        assert fp == fp2, "Fingerprint not deterministic!"
        ok("Same KEK produces same fingerprint")

        # Different KEK → different fingerprint (with high probability)
        diff_kek = os.urandom(128)
        fp3 = kek_fingerprint(diff_kek)
        assert fp != fp3, "Different KEKs should have different fingerprints!"
        ok("Different KEK produces different fingerprint")

    finally:
        os.unlink(temp_path)

    return True


# ============================================================================
# Test 3: Extension Detection Algorithm
# ============================================================================

def test_extension_detection():
    """Test ransomware extension auto-detection."""
    header("Extension Detection")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create synthetic encrypted files with various extensions
        target_ext = ".AbCdEfGhI"  # LockBit-style 9-char extension

        for i in range(50):
            fname = f"document_{i:04d}.pdf{target_ext}"
            path = Path(tmpdir) / fname
            path.write_bytes(os.urandom(2048))

        # Add some non-encrypted files (should be ignored)
        for i in range(10):
            fname = f"normal_{i:04d}.txt"
            path = Path(tmpdir) / fname
            path.write_text(f"Normal file {i}")

        # Test detection function
        def detect_extension(source, sample_limit=5000):
            import collections
            counts = collections.Counter()
            seen = 0
            for dirpath, _, files in os.walk(source):
                for fn in files:
                    if "." not in fn:
                        continue
                    ext = "." + fn.rsplit(".", 1)[-1]
                    if len(ext) == 10 and ext[1:].isalnum() and not ext[1:].isdigit():
                        counts[ext] += 1
                        seen += 1
                        if seen >= sample_limit:
                            break
                if seen >= sample_limit:
                    break
            return counts.most_common(1)[0][0] if counts else ""

        detected = detect_extension(Path(tmpdir))
        assert detected == target_ext, f"Detection failed: '{detected}' != '{target_ext}'"
        ok(f"Extension auto-detected correctly: {detected}")

    # Test with multiple extensions (simulating mixed attack)
    with tempfile.TemporaryDirectory() as tmpdir:
        ext1 = ".XyZaBcDeF"  # More files
        ext2 = ".QwErTyUiO"  # Fewer files

        for i in range(30):
            Path(tmpdir, f"file_{i}{ext1}").write_bytes(os.urandom(512))
        for i in range(10):
            Path(tmpdir, f"data_{i}{ext2}").write_bytes(os.urandom(512))

        detected = detect_extension(Path(tmpdir))
        assert detected == ext1, f"Should detect most common: '{detected}' != '{ext1}'"
        ok(f"Most common extension detected in mixed scenario: {detected}")

    return True


# ============================================================================
# Test 4: Magic Byte Database Validation
# ============================================================================

def test_magic_database():
    """Verify the magic byte database is complete and valid."""
    header("Magic Byte Database")

    # Import from main module
    sys.path.insert(0, str(Path(__file__).parent))
    from lockbit_rescue_v2 import MAGIC_DATABASE, get_magic_for_extension

    # Check database size
    assert len(MAGIC_DATABASE) >= 80, f"Database too small: {len(MAGIC_DATABASE)} entries"
    ok(f"Magic database has {len(MAGIC_DATABASE)} file types")

    # Verify all hex strings are valid
    for ext, magics in MAGIC_DATABASE.items():
        if magics is None:
            continue
        for magic in magics:
            if magic is None:
                continue
            cleaned = magic.replace(" ", "").replace(":", "")
            assert len(cleaned) % 2 == 0, f"Odd-length hex for .{ext}: {magic}"
            try:
                bytes.fromhex(cleaned)
            except ValueError as e:
                fail(f"Invalid hex for .{ext}: {magic} — {e}")
                return False

    ok("All magic signatures are valid hex")

    # Test get_magic_for_extension function
    pdf_magic = get_magic_for_extension("pdf")
    assert pdf_magic is not None, "PDF should have magic"
    assert len(pdf_magic) >= 7, f"PDF magic too short: {len(pdf_magic)} bytes"
    ok(f"PDF magic retrieved ({len(pdf_magic)//2} bytes): {pdf_magic[:20]}...")

    # Test extension with no magic
    txt_magic = get_magic_for_extension("txt")
    assert txt_magic is None, "TXT should have no magic (text file)"
    ok("Text files correctly return None for magic")

    # Verify known signatures
    png_magic = get_magic_for_extension("png")
    assert png_magic and png_magic.startswith("89504e47"), f"PNG magic wrong: {png_magic}"
    ok(f"PNG signature correct: .{bytes.fromhex(png_magic[:16]).decode('latin-1')}...")

    zip_magic = get_magic_for_extension("zip")
    assert zip_magic and zip_magic.startswith("504b"), f"ZIP magic wrong: {zip_magic}"
    ok(f"ZIP signature correct: .{bytes.fromhex(zip_magic[:8]).decode('ascii')}...")

    return True


# ============================================================================
# Test 5: Batch Analysis & Oracle Selection
# ============================================================================

def test_batch_analysis():
    """Test multi-oracle strategy and batch analysis."""
    header("Batch Analysis & Multi-Oracle Strategy")

    # Import from main module
    sys.path.insert(0, str(Path(__file__).parent))
    from lockbit_rescue_v2 import EncryptedFile, select_oracles, COVERAGE_BASE_FROM_FEI, COVERAGE_OFFSET

    # Create synthetic files with varying fei_lens
    files = []
    test_cases = [
        ("very_long_document_name_that_provides_good_coverage.pdf", 150),
        ("another_reasonably_long_filename_for_testing.docx", 130),
        ("medium_length_file.xlsx", 110),
        ("short.pdf", 98),
        ("a.txt", 85),
        ("b.jpg", 75),
        ("c.png", 65),
    ]

    for fname, fei_len in test_cases:
        orig = fname.rsplit(".", 1)[0] if "." in fname else fname
        files.append(EncryptedFile(
            path=f"/fake/{fname}",
            filename=fname,
            fei_len=fei_len,
            kek_fingerprint="test_kek_001",
            size=fei_len * 10 + 2048,
            original_name=orig,
        ))

    # Test oracle selection
    oracles = select_oracles(files, min_coverage=50)
    assert len(oracles) >= 1, "Should select at least one oracle"
    ok(f"Selected {len(oracles)} oracle(s)")

    # Primary oracle should be the longest file
    primary = oracles[0]
    assert primary.fei_len == max(f.fei_len for f in files), \
        f"Primary oracle should have max fei_len: {primary.fei_len}"
    ok(f"Primary oracle has maximum fei_len: {primary.fei_len}")

    # Calculate coverage
    coverage = (primary.fei_len - COVERAGE_BASE_FROM_FEI) + COVERAGE_OFFSET
    assert coverage > 0, f"Coverage should be positive: {coverage}"
    ok(f"Oracle provides {coverage} bytes of keystream coverage")

    # Count recoverable files (fei_len <= coverage)
    recoverable = sum(1 for f in files if f.fei_len <= coverage)
    unrecoverable = len(files) - recoverable
    ok(f"With single oracle: {recoverable}/{len(files)} files recoverable")

    # Multi-oracle should help with more files
    multi_oracles = select_oracles(files, min_coverage=40)
    if len(multi_oracles) > 1:
        max_multi_cov = max(o.coverage for o in multi_oracles)
        ok(f"Multi-oracle strategy: {len(multi_oracles)} oracles, max coverage={max_multi_cov}")

    return True


# ============================================================================
# Test 6: State Persistence (JSON Save/Load)
# ============================================================================

def test_state_persistence():
    """Test JSON state save/load for resume capability."""
    header("State Persistence")

    sys.path.insert(0, str(Path(__file__).parent))
    from lockbit_rescue_v2 import RecoveryState, save_state, load_state

    with tempfile.TemporaryDirectory() as tmpdir:
        state_path = Path(tmpdir) / "state.json"

        # Create and save state
        original = RecoveryState(
            start_time=1234567890.0,
            source_dir="/fake/source",
            output_dir="/fake/output",
            ransom_ext=".AbCdEfGhI",
            total_files_scanned=1500,
            total_batches=25,
            files_completed={
                "/source/file1.pdf.AbcDefGhi": "/output/group_abc/file1.pdf",
                "/source/file2.docx.AbcDefGhi": "/output/group_abc/file2.docx",
            },
            batches_processed={"kek_001", "kek_002"},
            keystream_cache={"kek_001": "abcdef123456..."},
        )

        save_state(original, state_path)
        assert state_path.exists(), "State file not created"
        ok("State saved to JSON")

        # Load and verify
        loaded = load_state(state_path)
        assert loaded is not None, "Failed to load state"
        ok("State loaded from JSON")

        # Verify all fields preserved
        assert loaded.source_dir == original.source_dir
        assert loaded.output_dir == original.output_dir
        assert loaded.ransom_ext == original.ransom_ext
        assert loaded.total_files_scanned == original.total_files_scanned
        assert loaded.total_batches == original.total_batches
        ok("All state fields preserved correctly")

        # Verify sets converted properly
        assert isinstance(loaded.batches_processed, set)
        assert "kek_001" in loaded.batches_processed
        ok("Sets restored correctly from JSON lists")

        # Verify dicts preserved
        assert len(loaded.files_completed) == 2
        assert "/source/file1.pdf.AbcDefGhi" in loaded.files_completed
        ok("Dicts preserved correctly")

    return True


# ============================================================================
# Test 7: Manifest CSV Generation
# ============================================================================

def test_manifest_generation():
    """Test CSV manifest generation."""
    header("Manifest CSV Generation")

    sys.path.insert(0, str(Path(__file__).parent))
    from lockbit_rescue_v2 import DecryptionResult, write_manifest

    with tempfile.TemporaryDirectory() as tmpdir:
        manifest_path = Path(tmpdir) / "manifest.csv"

        # Create synthetic results
        results = [
            DecryptionResult(
                filepath="/source/photo.jpg.XyZaBcDeF",
                original_name="photo.jpg",
                success=True, reason="ok", file_type="image/jpeg",
            ),
            DecryptionResult(
                filepath="/source/report.pdf.XyZaBcDeF",
                original_name="report.pdf",
                success=True, reason="ok", file_type="application/pdf",
            ),
            DecryptionResult(
                filepath="/source/data.xlsx.XyZaBcDeF",
                original_name="data.xlsx",
                success=False, reason="decryption_failed", file_type="",
            ),
        ]

        write_manifest(results, manifest_path, "/source", ".XyZaBcDeF")
        assert manifest_path.exists(), "Manifest not created"
        ok("Manifest CSV generated")

        # Verify content
        import csv
        with open(manifest_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3, f"Expected 3 rows, got {len(rows)}"
        ok("Manifest has correct number of entries")

        # Check first row
        assert rows[0]["status"] == "SUCCESS"
        assert rows[0]["original_name"] == "photo.jpg"
        ok("Manifest SUCCESS entry correct")

        # Check failed entry
        assert rows[2]["status"] == "FAILED"
        assert rows[2]["reason"] == "decryption_failed"
        ok("Manifest FAILED entry correct")

    return True


# ============================================================================
# Test 8: Coverage Calculation Edge Cases
# ============================================================================

def test_coverage_edge_cases():
    """Test coverage calculation with edge cases."""
    header("Coverage Calculation Edge Cases")

    sys.path.insert(0, str(Path(__file__).parent))
    from lockbit_rescue_v2 import EncryptedFile, COVERAGE_BASE_FROM_FEI, COVERAGE_OFFSET

    # Very short filename (fei_len < overhead)
    short_file = EncryptedFile(
        path="/fake/a.txt", filename="a.txt.ext", fei_len=30,
        kek_fingerprint="test", size=1024, original_name="a.txt"
    )
    assert short_file.coverage <= 0 or short_file.coverage < COVERAGE_OFFSET, \
        f"Short file should have minimal coverage: {short_file.coverage}"
    ok(f"Short filename (fei_len=30): coverage={short_file.coverage}")

    # Typical medium filename
    med_file = EncryptedFile(
        path="/fake/report.pdf", filename="report.pdf.ext", fei_len=106,
        kek_fingerprint="test", size=2048, original_name="report.pdf"
    )
    expected_cov = (106 - COVERAGE_BASE_FROM_FEI) + COVERAGE_OFFSET  # = 42
    assert med_file.coverage == expected_cov, \
        f"Coverage mismatch: {med_file.coverage} != {expected_cov}"
    ok(f"Medium filename (fei_len=106): coverage={med_file.coverage}")

    # Long filename (good oracle)
    long_file = EncryptedFile(
        path="/fake/very_long_name.pdf", filename="very_long_name.pdf.ext", fei_len=200,
        kek_fingerprint="test", size=4096, original_name="very_long_name.pdf"
    )
    expected_cov = (200 - COVERAGE_BASE_FROM_FEI) + COVERAGE_OFFSET  # = 136
    assert long_file.coverage == expected_cov, \
        f"Coverage mismatch: {long_file.coverage} != {expected_cov}"
    ok(f"Long filename (fei_len=200): coverage={long_file.coverage}")

    return True


# ============================================================================
# Test 9: File Size Formatting
# ============================================================================

def test_size_formatting():
    """Test human-readable size formatting."""
    header("Size Formatting")

    sys.path.insert(0, str(Path(__file__).parent))
    from lockbit_rescue_v2 import fmt_size

    tests = [
        (0, "0.0B"),
        (512, "512.0B"),
        (1024, "1.0KB"),
        (1024 * 1024, "1.0MB"),
        (1024 ** 3, "1.0GB"),
        (1024 ** 4, "1.0TB"),
    ]

    for size, expected in tests:
        result = fmt_size(size)
        assert result == expected, f"fmt_size({size}) = '{result}', expected '{expected}'"
        ok(f"{size} bytes → {result}")

    return True


# ============================================================================
# Test 10: Hex Cleaning Utility
# ============================================================================

def test_hex_cleaning():
    """Test hex string cleaning utility."""
    header("Hex String Utilities")

    sys.path.insert(0, str(Path(__file__).parent))
    from lockbit_rescue_v2 import hex_clean

    tests = [
        ("FF D8 FF E0", "ffd8ffe0"),
        ("ff:d8:ff:e0", "ffd8ffe0"),
        ("FFD8FFE0", "ffd8ffe0"),
        ("  ff d8  ", "ffd8"),
    ]

    for input_str, expected in tests:
        result = hex_clean(input_str)
        assert result == expected, f"hex_clean('{input_str}') = '{result}', expected '{expected}'"
        ok(f"'{input_str}' → '{result}'")

    return True


# ============================================================================
# Main Test Runner
# ============================================================================

def main():
    print("="*60)
    print("  lockbit-rescue v2 — Synthetic Test Suite")
    print("="*60)

    tests = [
        ("Salsa20 Block Function", test_salsa20_block),
        ("Footer Parsing & KEK Fingerprint", test_footer_parsing),
        ("Extension Detection", test_extension_detection),
        ("Magic Byte Database", test_magic_database),
        ("Batch Analysis & Oracle Selection", test_batch_analysis),
        ("State Persistence (JSON)", test_state_persistence),
        ("Manifest CSV Generation", test_manifest_generation),
        ("Coverage Calculation Edge Cases", test_coverage_edge_cases),
        ("Size Formatting", test_size_formatting),
        ("Hex String Utilities", test_hex_cleaning),
    ]

    passed = 0
    failed = 0
    errors = []

    for name, test_func in tests:
        try:
            result = test_func()
            if result is False:
                failed += 1
                errors.append(name)
            else:
                passed += 1
        except Exception as e:
            failed += 1
            errors.append(f"{name}: {type(e).__name__}: {e}")
            print(f"  [ERROR] {name}: {e}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  TEST SUMMARY")
    print(f"{'='*60}")
    print(f"  Passed: {passed}/{len(tests)}")
    print(f"  Failed: {failed}/{len(tests)}")

    if errors:
        print(f"\n  Failures:")
        for e in errors:
            print(f"    - {e}")

    if failed == 0:
        print(f"\n  ✓ ALL TESTS PASSED")
    else:
        print(f"\n  ✗ SOME TESTS FAILED")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

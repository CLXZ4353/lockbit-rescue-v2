#!/usr/bin/env python3
"""Genera file sintetici che simulano la struttura LockBit 3.0 per testare il parser."""

import os
import struct
import hashlib
import random

OUTPUT_DIR = "lockbit-rescue-v2/test_data/synthetic_lockbit"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Simula un batch reale: stessa KEK per tutti i file
KEK = bytes(random.getrandbits(8) for _ in range(128))
EXTENSION = ".xYz123AbC"  # LockBit usa estensioni random di 9 char

def create_lockbit_file(name, fei_len, body_size=4096):
    """Crea un file con struttura LockBit 3.0: [body][FEI][footer_134]"""
    encrypted_name = name + EXTENSION
    path = os.path.join(OUTPUT_DIR, encrypted_name)

    # Body "criptato" (byte casuali — in realtà sarebbe Salsa20 stream)
    body = bytes(random.getrandbits(8) for _ in range(body_size))

    # FEI block variabile (contenuto cifrato con lo stesso keystream)
    fei = bytes(random.getrandbits(8) for _ in range(fei_len))

    # Footer 134 byte: [fei_len:2][checksum:4][KEK:128]
    footer = struct.pack('<H', fei_len) + hashlib.md5(body).digest()[:4] + KEK
    assert len(footer) == 134

    with open(path, 'wb') as f:
        f.write(body + fei + footer)

    coverage = max(0, (fei_len - 82) + 18)
    return name, fei_len, coverage, body_size

# Batch principale — 7 file con nomi di lunghezza diversa
files = [
    ("Document_Financial_Report_2024_Q3.xlsx", 150),   # Oracle: nome lunghissimo
    ("Budget_Summary.pdf", 80),                         # Copertura media
    ("Meeting_Notes.docx", 90),                         # Copertura media
    ("Photo.jpg", 50),                                  # Nome corto → zero coverage
    ("Presentation_Final.pptx", 120),                   # Buona copertura
    ("Database_Backup.zip", 100),                       # Media-buona
    ("config.ini", 45),                                 # Molto corto
]

print("Generazione file sintetici LockBit 3.0...")
print(f"Directory: {OUTPUT_DIR}")
print(f"Extension ransomware: {EXTENSION}")
print(f"KEK fingerprint: {hashlib.md5(KEK).hexdigest()[:12]}")
print("-" * 60)

for name, fei_len in files:
    _, fl, cov, bs = create_lockbit_file(name, fei_len)
    print(f"  {name:<45} fei={fei_len:>3} coverage={cov:>3}B size={bs}")

# Batch separato — KEK diversa
other_kek = bytes(random.getrandbits(8) for _ in range(128))
create_lockbit_file("Other_Batch_File.pdf", 100, body_size=2048)
print(f"\n+ Other batch (KEK={hashlib.md5(other_kek).hexdigest()[:12]})")

total = sum(os.path.getsize(os.path.join(OUTPUT_DIR, f)) for f in os.listdir(OUTPUT_DIR))
print(f"\nTotale: {len(files)+1} file, {total/1024:.1f} KB")

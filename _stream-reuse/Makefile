# Cross-platform Makefile for lockbit-rescue-v2 upstream tools
# Compiles to native architecture (x86_64 on both Linux and Windows/MinGW)

CC ?= gcc
CFLAGS_COMMON = -O0 -fno-stack-protector -D_FILE_OFFSET_BITS=64

# Detect platform
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)

ifeq ($(UNAME_S),Linux)
    CFLAGS_LINUX = -z execstack -pie -no-pie -Wl,-z,norelro -static
endif

# aPLib source directory (if available for rebuilding)
APLIB_SRC := $(wildcard aplib-src/aplib.c)

all: frank stream-reuse

frank: frank.c frank.h
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_LINUX) -o $@ $<

stream-reuse: stream-reuse.c aplib.a
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_LINUX) -o $@ $< aplib.a

# Rebuild aplib.a from source if available (for native architecture support)
aplib.a:
ifeq ($(APLIB_SRC),)
	@echo "[!] aPLib source not found — download from http://www.ibsensoftware.com/files/aPLib-1.1.1.zip"
	@echo "    Extract to: aplib-src/ (needs aplib.c)"
	@exit 1
endif
	$(CC) -O2 -c -o aplib.o aplib-src/aplib.c
	ar rcs $@ aplib.o && rm -f aplib.o

clean:
	rm -f frank stream-reuse brute_extend_v2 direct_decrypt_v2 aplib.o

.PHONY: all clean

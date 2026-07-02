#!/usr/bin/env python3
"""
run.py - build and run every Riptide conformance-vector program, exit non-zero
if any known answer drifted.

This is the runnable conformance gate CLAUDE.md and IMPLEMENTATION-PLAN.md
section 6 call for. It pins Riptide's deterministic wire format so a libsodium
bump (or a coding error) that changed any derivation or any canonical encoding
fails CI instead of silently breaking interop.

Two programs, both self-contained against libsodium (no SodiumXT shim needed, so
this runs anywhere libsodium is installed):

  vectors.c        the KDF / BLAKE2b / ed25519 DERIVATIONS pinned in
                   12-conformance-vectors.md (identity, rendezvous, presence,
                   inbox, safety number, BEP44 signature).
  wire_vectors.c   the byte-exact SERIALIZATIONS the constitution fixes: the AD
                   binding bencode({e,q,t}) (3.5.1), the BEP44 signing buffer
                   (3.7, cross-checked to 12.6), and the identity-card bencode.
                   Uses the reference encoder rt_bencode.c.

Usage:
    python3 tests/vectors/run.py            # build with cc and run both
    CC=gcc python3 tests/vectors/run.py     # pick a compiler

The on-engine self-test (examples/riptide-tests.livecodescript) asserts the SAME
frozen answers through the sx* handlers, so the C path and the OXT path are
pinned to one truth.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# program -> extra source files it needs to link (besides itself and -lsodium)
PROGRAMS = {
    "vectors.c": [],
    "wire_vectors.c": ["rt_bencode.c"],
}


def have_libsodium(cc):
    """Compile a trivial program that includes sodium.h, to give a clear error
    instead of a wall of missing-symbol noise when libsodium is absent."""
    src = "#include <sodium.h>\nint main(void){return sodium_init()<0;}\n"
    with tempfile.TemporaryDirectory() as tmp:
        cpath = os.path.join(tmp, "probe.c")
        opath = os.path.join(tmp, "probe")
        with open(cpath, "w") as handle:
            handle.write(src)
        proc = subprocess.run([cc, "-O0", cpath, "-lsodium", "-o", opath],
                              capture_output=True, text=True)
        return proc.returncode == 0, proc.stderr


def main():
    cc = os.environ.get("CC", "cc")
    if shutil.which(cc) is None:
        print(f"run.py: compiler '{cc}' not found (set CC=... to choose one)")
        return 2

    ok, err = have_libsodium(cc)
    if not ok:
        print("run.py: libsodium headers/library not available.\n"
              "  Install it (Debian/Ubuntu: apt-get install libsodium-dev;\n"
              "  macOS: brew install libsodium) and re-run.\n"
              f"  compiler said:\n{err}")
        return 2

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for program, extra in PROGRAMS.items():
            srcs = [os.path.join(HERE, program)] + [os.path.join(HERE, e) for e in extra]
            out = os.path.join(tmp, program[:-2])
            cmd = [cc, "-O2", "-Wall", "-Wextra", "-std=c11"] + srcs + ["-lsodium", "-o", out]
            print(f"== building {program} ==")
            build = subprocess.run(cmd, capture_output=True, text=True)
            if build.returncode != 0:
                print(f"run.py: build FAILED for {program}\n{build.stderr}")
                failures += 1
                continue
            if build.stderr.strip():
                print(f"run.py: build warnings for {program}:\n{build.stderr}")
            print(f"== running {program} ==")
            run = subprocess.run([out], capture_output=True, text=True)
            sys.stdout.write(run.stdout)
            if run.stderr.strip():
                sys.stderr.write(run.stderr)
            if run.returncode != 0:
                failures += 1

    print("=" * 40)
    if failures == 0:
        print("run.py: ALL CONFORMANCE PROGRAMS PASSED")
        return 0
    print(f"run.py: {failures} conformance program(s) FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())

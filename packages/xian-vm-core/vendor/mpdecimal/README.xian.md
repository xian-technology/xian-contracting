# Pinned Decimal arithmetic backend

Upstream: https://www.bytereef.org/mpdecimal/
Version: 4.0.0 (matches the pinned Python 3.12.10 historical oracle).
Archive: https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-4.0.0.tar.gz
SHA256: 942445c3245b22730fd41a67a7c5c231d11cb1b9936b9c0f76334fb7d0b4468c
License: Simplified BSD; see COPYRIGHT.txt and retained per-file notices.
Include COPYRIGHT.txt with binary distributions.

The C sources and internal headers are unmodified. mpdecimal.h is generated
from the retained mpdecimal.h.in by replacing @MPD_HEADER_CONFIG@ with the
64-bit ABI configuration and contradictory-configuration checks. We compile
CONFIG_64 + ANSI, without assembly or native uint128, consistently on supported
64-bit targets. The public MPD_CONFIG_64 macro and internal CONFIG_64 macro
are both necessary. No system mpdecimal library or build-time download is used.

The adapter is src/decimal_shim.c; it uses quiet operations and a local explicit
91-digit, ROUND_DOWN, Emin=-100, Emax=100, clamp=0 context. Python-compatible
operation-specific rounding remains in upstream functions. No global context,
trap handler, allocator, or minimum allocation setting is mutated.

Raw exact inputs are bounded separately from arithmetic precision. The Rust
wrapper caps input text at 128 KiB and the shim caps coefficient digits and raw
exponent magnitude at 131072. Transcendental/power work accepts at most 4096
coefficient digits; ordinary power is further limited to 1024 coefficient
digits per operand because fractional powers increase internal precision to
match the base. Integer power and modular-power exponent extent (digits + exponent) is limited
to 512. Long near-one bases with larger integer exponents otherwise permit
seconds of repeated-squaring work despite a 91-digit final result.
These deterministic resource limits supplement, not replace, VM metering.
Formatting and integer-ratio expansion are owned by the Rust VM and must be
bounded before allocation. The shim never expands results into fixed notation.

Upgrade discipline: verify the source checksum, review changes, regenerate the
header, preserve this provenance, and run historical differential fixtures and
ARM64/x86_64 consensus tests before changing the pinned version/configuration.

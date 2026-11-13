# Pinned LMDB storage engine

Upstream: OpenLDAP LMDB, https://git.openldap.org/openldap/openldap
Tag: LMDB_0.9.36 (commit 028f61b6832032174f893484719ed4848d8d60db), path libraries/liblmdb
Version: 0.9.36 (MDB_VERSION_DATE "Aug 6, 2026"), the LMDB release bundled by
py-lmdb 3.0.0, which created the existing node state.
License: OpenLDAP Public License 2.8; see LICENSE and COPYRIGHT. Include both
with binary distributions.

Files (unmodified upstream bytes; sha256, git blob id at the tag):

| File | SHA256 | Git blob |
|---|---|---|
| mdb.c | c00c693c753ded36295637e5bfd8e3bb19133a51aaa25461178db471597d1ed0 | 07a73694b3f68d426760099f0d0b45fbeab31b41 |
| midl.c | 91110543f2e84c516188c1e3960b1f504e1c60a4766027a782349c000276ca93 | b0ea5383b2884a09fea4e8e172fdf2aa7041e467 |
| lmdb.h | f5282169fed4df94b246dc144009274bab5565e221da7de280610a78fd5fe194 | c247e9c46fa9e095e2a00c578b9f7f8d255be485 |
| midl.h | cef8236dc7dce9b5346d212d31e8330f9158bacabe270b14ab1e99745db118c6 | f3fdf1663da51bf3cb8b0291cd0dd47ec5b47c09 |
| LICENSE | 310fe25c858a9515fc8c8d7d1f24a67c9496f84a91e0a0e41ea9975b1371e569 | 05ad7571e448b9d83ead5d4691274d9484574714 |
| COPYRIGHT | 3c87f63656b6a12fda225b6f798c547fe89e3404f499e890b445761eb310fd4f | 14eb1493d625c27ba4eecd41e0454946658d972c |

Each file was fetched from
https://git.openldap.org/openldap/openldap/-/raw/LMDB_0.9.36/libraries/liblmdb/<file>
and checked against the GitLab API (repository/files at ref LMDB_0.9.36:
content_sha256 and blob_id) before it was copied here.

Why vendored: the node keeps one LMDB environment per state directory in one
process. The Rust VM reads that environment directly, so the environment must
be owned by Rust instead of a second LMDB copy in py-lmdb (two LMDB
environments on the same files in one process drop each other's POSIX locks).
Pinning the exact release that wrote the existing files keeps the on-disk
format identical; no crate from crates.io is needed.

Build: build.rs compiles mdb.c and midl.c with the cc crate. No build-time
download and no system liblmdb are used.

Upgrade discipline: fetch only the files above from a new release tag, verify
them against the tag as above, review the upstream changes, update this table,
and run the py-lmdb compatibility tests (tests/integration/test_lmdb_compat.py
in xian-contracting) before changing the pinned version.

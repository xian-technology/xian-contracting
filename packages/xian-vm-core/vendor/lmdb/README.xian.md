# Pinned LMDB storage engine

Upstream: OpenLDAP LMDB, https://git.openldap.org/openldap/openldap
Tag: LMDB_0.9.37 (commit ff3f48f7ba57ed482567ed23b0019c5eabada293), path libraries/liblmdb
Version: 0.9.37 (MDB_VERSION_DATE "Oct 21, 2026"). Existing node state was
created by py-lmdb 3.0.0 (LMDB 0.9.36); 0.9.37 keeps the on-disk format (the
py-lmdb compatibility tests prove both directions and byte-identical files).
License: OpenLDAP Public License 2.8; see LICENSE and COPYRIGHT. Include both
with binary distributions.

Files (unmodified upstream bytes; sha256, git blob id at the tag):

| File | SHA256 | Git blob |
|---|---|---|
| mdb.c | 5db0a5422694a1dbf2e98fb7b06372293e700000a9ec26911ee951de521f9396 | d81cf2104f338f696ba67750abc5fb80cd4a2481 |
| midl.c | 91110543f2e84c516188c1e3960b1f504e1c60a4766027a782349c000276ca93 | b0ea5383b2884a09fea4e8e172fdf2aa7041e467 |
| lmdb.h | b93f1d27055e722437a6ea396dbc25c34ba66dc15ec12db2eb48f916cde4f0b8 | f2f166d8dada5ba4a32a45ae214171be3bbfafb2 |
| midl.h | cef8236dc7dce9b5346d212d31e8330f9158bacabe270b14ab1e99745db118c6 | f3fdf1663da51bf3cb8b0291cd0dd47ec5b47c09 |
| LICENSE | 310fe25c858a9515fc8c8d7d1f24a67c9496f84a91e0a0e41ea9975b1371e569 | 05ad7571e448b9d83ead5d4691274d9484574714 |
| COPYRIGHT | 3c87f63656b6a12fda225b6f798c547fe89e3404f499e890b445761eb310fd4f | 14eb1493d625c27ba4eecd41e0454946658d972c |

Each file was fetched from
https://git.openldap.org/openldap/openldap/-/raw/LMDB_0.9.37/libraries/liblmdb/<file>
and checked against the GitLab API (repository/files at ref LMDB_0.9.37:
content_sha256 and blob_id) before it was copied here.

Why vendored: the node keeps one LMDB environment per state directory in one
process. The Rust VM reads that environment directly, so the environment must
be owned by Rust instead of a second LMDB copy in py-lmdb (two LMDB
environments on the same files in one process drop each other's POSIX locks).
Staying on the 0.9 release line that wrote the existing files keeps the
on-disk format identical; no crate from crates.io is needed.

Build: build.rs compiles mdb.c and midl.c with the cc crate. No build-time
download and no system liblmdb are used.

Upgrade discipline: fetch only the files above from a new release tag, verify
them against the tag as above, review the upstream changes, update this table,
and run the py-lmdb compatibility tests (tests/integration/test_lmdb_compat.py
in xian-contracting) before changing the pinned version. The Rust test
`the_vendored_engine_is_lmdb_0_9_37` (src/lmdb_env.rs) pins the version.

0.9.37 changes against 0.9.36 (ITS#10615 OpenBSD cache coherency, an explicit
msync that is a no-op elsewhere; ITS#10642 mdb_subdb_adjust alignment and
ITS#10643 DUPSORT delete page counts, both only for named or DUPSORT
databases) do not touch the paths the node uses (the unnamed main database
on macOS and Linux).

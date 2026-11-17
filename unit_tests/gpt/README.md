# GPT CRC / tamper-detection tests

These tests exercise the GPT primary/backup CRC32 validation and
primary-backup consistency checks implemented in `tsk/vs/gpt.c`.

They are intentionally self-contained: they do not require autotools or
cppunit, so they can be built with a plain C/C++ toolchain against the
in-tree TSK sources.

## What is covered

`gen_gpt_images.py` generates real GPT disk images whose UEFI CRC32
checksums are computed with `zlib.crc32` (polynomial 0x04C11DB7,
reflected). Each image is a valid GPT until its scenario deliberately
mutates specific bytes:

| Image | Mutation | Expected result |
|-------|----------|-----------------|
| `valid.img` | none | opens, partitions reported |
| `tamper_primary_head_crc.img` | primary header byte flipped, header CRC not updated | open refused, `TSK_ERR_VS_CRC` |
| `tamper_backup_head_crc.img` | backup header byte flipped | open refused, `TSK_ERR_VS_CRC` |
| `tamper_primary_table_crc.img` | primary entry-array byte flipped | open refused, `TSK_ERR_VS_CRC` |
| `tamper_backup_table_crc.img` | backup entry-array byte flipped | open refused, `TSK_ERR_VS_CRC` |
| `tamper_header_field_mismatch.img` | shared header field differs, both header CRCs still valid | open refused, `TSK_ERR_VS_CRC` (consistency) |
| `tamper_entry_mismatch.img` | entry arrays differ, both array CRCs still valid | open refused, `TSK_ERR_VS_CRC` (consistency) |
| `wipe_primary.img` | protective MBR + primary GPT zeroed, backup intact | opens in backup-only mode |

`crc_kat.c` is a known-answer test for the `tsk_crc32_uefi()`
implementation against the standard CRC-32 check vectors.

## Building and running

A helper script builds only the TSK objects needed and links the test
harness. From the repository root:

    unit_tests/gpt/run_tests.sh

The script:
  1. compiles the required `tsk/base`, `tsk/img`, `tsk/util` and `tsk/vs`
     objects into a scratch build directory;
  2. generates the images with `python3 -I gen_gpt_images.py`;
  3. runs the CRC known-answer test and the GPT scenario test.

A run exits non-zero if any check fails.

/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file gpt.c
 * The internal functions required to process the GPT GUID Partiition Table.
 *
 * Before any partition is reported, both on-disk copies of the GPT (the
 * primary header in LBA 1 and the backup header in the last LBA) are
 * validated against their UEFI CRC32 checksums and compared against each
 * other.  A copy whose header CRC or partition-entry-array CRC does not
 * match is never trusted as a source of partition information, and a
 * mismatch between the two copies is explicitly reported as a tampering /
 * corruption risk.  Only when both copies are valid and agree do we load
 * partitions, so partially corrupted on-disk structures cannot silently
 * pollute the partition layout returned to callers.
 */
#include "tsk_vs_i.h"
#include "tsk_gpt.h"
#include "tsk_dos.h"
#include "tsk/base/crc.h"

#include <string.h>

/* Cap inherited from the previous implementation: larger entry counts are
 * treated as corruption rather than trusted. */
#define GPT_MAX_ENTRIES 8192

/*
 * Locate the header sector (relative and absolute LBA) for either copy.
 */
static void
gpt_header_lba(TSK_VS_INFO * vs, GPT_LOCATION_ENUM gpt_type,
    TSK_DADDR_T * rel_lba, TSK_DADDR_T * abs_lba)
{
    if (gpt_type == PRIMARY_TABLE) {
        *rel_lba = GPT_PART_SOFFSET + 1;
        *abs_lba = vs->offset / vs->block_size + GPT_PART_SOFFSET + 1;
    }
    else {
        *rel_lba = ((vs->img_info->size - vs->offset) / vs->block_size) - 1;
        *abs_lba = (vs->img_info->size / vs->block_size) - 1;
    }
}

/*
 * Read and sanity-check one GPT header sector (without trusting any of its
 * CRC fields yet).  The DOS safety partition is only checked for the
 * primary copy, preserving the previous behaviour.
 *
 * Returns 0 on success (head_buf filled with the raw header bytes) and 1
 * on error (tsk_errno / tsk_errstr set).
 */
static uint8_t
gpt_read_header(TSK_VS_INFO * vs, GPT_LOCATION_ENUM gpt_type,
    uint8_t * head_buf)
{
    TSK_DADDR_T rel_lba, abs_lba;
    ssize_t cnt;

    gpt_header_lba(vs, gpt_type, &rel_lba, &abs_lba);

    if (tsk_verbose)
        tsk_fprintf(stderr, "gpt_read_header: Sector: %" PRIuDADDR "\n",
            abs_lba);

    if (gpt_type == PRIMARY_TABLE) {
        TSK_DADDR_T dos_rel = GPT_PART_SOFFSET;
        TSK_DADDR_T dos_abs = vs->offset / vs->block_size + GPT_PART_SOFFSET;
        dos_sect *dos_safety = (dos_sect *) head_buf;

        cnt = tsk_vs_read_block(vs, dos_rel, (char *) head_buf,
            vs->block_size);
        /* if -1, then tsk_errno is already set */
        if (cnt != (ssize_t) vs->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_READ);
            }
            tsk_error_set_errstr2
                ("Error reading DOS safety partition table in Sector: %"
                PRIuDADDR, dos_abs);
            return 1;
        }

        /* Sanity Check */
        if (tsk_vs_guessu16(vs, dos_safety->magic, DOS_MAGIC)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr
                ("Missing DOS safety partition (invalid magic) (Sector: %"
                PRIuDADDR ")", dos_abs);
            return 1;
        }

        if (dos_safety->ptable[0].ptype != GPT_DOS_TYPE) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr
                ("Missing DOS safety partition (invalid type in table: %d)",
                dos_safety->ptable[0].ptype);
            return 1;
        }
    }

    /* Read the GPT header itself. */
    cnt = tsk_vs_read_block(vs, rel_lba, (char *) head_buf,
        vs->block_size);
    if (cnt != (ssize_t) vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2("GPT Header structure in Sector: %"
            PRIuDADDR, abs_lba);
        return 1;
    }

    {
        /* GPT is little-endian on disk.  For the primary copy the DOS
         * magic check already established the endianness; run the guess
         * again here so it also works for a standalone backup (which has
         * no DOS safety table) and so we never rely on that side effect. */
        gpt_head *head = (gpt_head *) head_buf;
        if (tsk_vs_guessu64(vs, head->signature, GPT_HEAD_SIG)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr("GPT Header: %" PRIx64,
                tsk_getu64(vs->endian, &head->signature));
            return 1;
        }

        if (tsk_getu64(vs->endian, &head->signature) != GPT_HEAD_SIG) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr("GPT Header: %" PRIx64,
                tsk_getu64(vs->endian, &head->signature));
            return 1;
        }
    }

    return 0;
}

/*
 * Verify the header CRC of a GPT copy.  Per UEFI, the CRC is computed over
 * head_size_b bytes of the header with the head_crc field treated as zero.
 * The caller-supplied raw header bytes are not modified.
 */
static uint8_t
gpt_check_header_crc(TSK_VS_INFO * vs, const uint8_t * head_buf,
    uint32_t head_size, uint32_t stored_crc, const char *copy_name)
{
    uint8_t *tmp;
    uint32_t calc_crc;

    if (head_size < GPT_HEAD_FIXED_SIZE || head_size > vs->block_size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_CRC);
        tsk_error_set_errstr
            ("%s GPT header size %" PRIu32
            " is out of range (sector size %u)", copy_name, head_size,
            vs->block_size);
        return 1;
    }

    tmp = (uint8_t *) tsk_malloc(head_size);
    if (tmp == NULL)
        return 1;

    memcpy(tmp, head_buf, head_size);
    /* Zero the CRC field before computing the checksum. */
    memset(tmp + GPT_HEAD_CRC_OFF, 0, 4);
    calc_crc = tsk_crc32_uefi(0, tmp, head_size);
    free(tmp);

    if (calc_crc != stored_crc) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_CRC);
        tsk_error_set_errstr
            ("%s GPT header CRC mismatch: stored 0x%08" PRIx32
            ", calculated 0x%08" PRIx32
            " (tampering or corruption detected)",
            copy_name, stored_crc, calc_crc);
        return 1;
    }
    return 0;
}

/*
 * Read the partition entry array of one copy and verify its CRC.  On
 * success copy->tab holds the raw entry bytes and copy->tab_crc_ok /
 * copy->head_crc_ok describe the validation state.
 */
static uint8_t
gpt_read_and_check_table(TSK_VS_INFO * vs, gpt_copy * copy,
    TSK_DADDR_T max_addr, const char *copy_name)
{
    gpt_head *head = copy->head;
    uint64_t table_bytes;
    uint32_t stored_tab_crc;
    uint32_t calc_tab_crc;
    uint32_t a;
    size_t read_bytes = 0;

    copy->head_size = tsk_getu32(vs->endian, &head->head_size_b);
    copy->ent_size = tsk_getu32(vs->endian, &head->tab_size_b);
    copy->tab_num_ent = tsk_getu32(vs->endian, &head->tab_num_ent);
    copy->tab_start_lba = tsk_getu64(vs->endian, &head->tab_start_lba);

    /* ---- header CRC ---- */
    copy->head_crc_ok =
        (gpt_check_header_crc(vs, (const uint8_t *) head,
            copy->head_size,
            tsk_getu32(vs->endian, &head->head_crc), copy_name) == 0);
    if (!copy->head_crc_ok)
        return 1;

    /* ---- structural sanity of the header fields ---- */
    if (copy->ent_size < sizeof(gpt_entry)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr
            ("%s GPT header reports partition entry size of %" PRIu32
            " and not %" PRIuSIZE, copy_name, copy->ent_size,
            sizeof(gpt_entry));
        return 1;
    }

    if (copy->tab_start_lba > max_addr) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
        tsk_error_set_errstr
            ("gpt: %s partition table start LBA too large for image",
            copy_name);
        return 1;
    }

    if (copy->tab_num_ent == 0 || copy->tab_num_ent > GPT_MAX_ENTRIES) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_CRC);
        tsk_error_set_errstr
            ("%s GPT header reports invalid partition entry count %" PRIu32,
            copy_name, copy->tab_num_ent);
        return 1;
    }

    table_bytes =
        (uint64_t) copy->ent_size * (uint64_t) copy->tab_num_ent;
    if (table_bytes > (uint64_t) GPT_MAX_ENTRIES * 16384ULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_CRC);
        tsk_error_set_errstr
            ("%s GPT partition entry array is implausibly large (%" PRIu64
            " bytes)", copy_name, table_bytes);
        return 1;
    }

    copy->tab_size = (size_t) table_bytes;
    /* Each disk read pulls a full sector.  Allocate room for the final
     * partial sector so the last tsk_vs_read_block() cannot overflow the
     * buffer; the CRC only covers the first tab_size bytes. */
    {
        size_t read_alloc = copy->tab_size;
        size_t rem = read_alloc % vs->block_size;
        if (rem)
            read_alloc += vs->block_size - rem;
        copy->tab = (uint8_t *) tsk_malloc(read_alloc);
    }
    if (copy->tab == NULL)
        return 1;

    /* Read the (possibly multi-sector) entry array. */
    for (a = 0; read_bytes < copy->tab_size; a++) {
        ssize_t cnt;

        cnt = tsk_vs_read_block(vs, copy->tab_start_lba + a,
            (char *) (copy->tab + read_bytes), vs->block_size);
        if (cnt != (ssize_t) vs->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_READ);
            }
            tsk_error_set_errstr2
                ("Error reading %s GPT partition table sector: %"
                PRIuDADDR, copy_name, copy->tab_start_lba + a);
            return 1;
        }
        read_bytes += vs->block_size;
    }

    /* ---- partition entry array CRC ---- */
    stored_tab_crc = tsk_getu32(vs->endian, &head->tab_crc);
    calc_tab_crc = tsk_crc32_uefi(0, copy->tab, copy->tab_size);
    if (calc_tab_crc != stored_tab_crc) {
        copy->tab_crc_ok = 0;
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_CRC);
        tsk_error_set_errstr
            ("%s GPT partition entry array CRC mismatch: stored 0x%08"
            PRIx32 ", calculated 0x%08" PRIx32
            " (tampering or corruption detected)",
            copy_name, stored_tab_crc, calc_tab_crc);
        return 1;
    }
    copy->tab_crc_ok = 1;
    copy->valid = 1;
    return 0;
}

/*
 * Compare the structural header fields that UEFI requires to be identical
 * in the primary and backup headers.  Location-specific fields are
 * excluded:
 *   - head_lba / head2_lba (my LBA / alternate LBA): swapped by design;
 *   - tab_start_lba: each header points at its own local entry array, so
 *     the primary and backup values differ on a healthy disk.
 * The entry arrays themselves are compared byte-for-byte separately.
 */
static uint8_t
gpt_headers_structurally_equal(TSK_VS_INFO * vs, const gpt_head * a,
    const gpt_head * b)
{
    return (tsk_getu32(vs->endian, a->version) ==
        tsk_getu32(vs->endian, b->version))
        && (tsk_getu32(vs->endian, a->head_size_b) ==
        tsk_getu32(vs->endian, b->head_size_b))
        && (tsk_getu64(vs->endian, a->partarea_start) ==
        tsk_getu64(vs->endian, b->partarea_start))
        && (tsk_getu64(vs->endian, a->partarea_end) ==
        tsk_getu64(vs->endian, b->partarea_end))
        && (memcmp(a->guid, b->guid, sizeof(a->guid)) == 0)
        && (tsk_getu32(vs->endian, a->tab_num_ent) ==
        tsk_getu32(vs->endian, b->tab_num_ent))
        && (tsk_getu32(vs->endian, a->tab_size_b) ==
        tsk_getu32(vs->endian, b->tab_size_b))
        && (tsk_getu32(vs->endian, a->tab_crc) ==
        tsk_getu32(vs->endian, b->tab_crc));
}

/*
 * Read one complete GPT copy (header sector + entry array) and record its
 * validation state.  Any failure is captured in *copy; the function itself
 * always returns 0 so that callers can evaluate both copies before
 * deciding what to report.
 */
static uint8_t
gpt_load_copy(TSK_VS_INFO * vs, GPT_LOCATION_ENUM gpt_type,
    gpt_copy * copy, TSK_DADDR_T max_addr)
{
    uint8_t *head_buf;

    memset(copy, 0, sizeof(*copy));
    copy->location = gpt_type;

    head_buf = (uint8_t *) tsk_malloc(vs->block_size);
    if (head_buf == NULL)
        return 0;

    if (gpt_read_header(vs, gpt_type, head_buf)) {
        free(head_buf);
        return 0;
    }

    /* Keep the raw header bytes for the lifetime of the copy. */
    copy->head = (gpt_head *) head_buf;

    /* gpt_read_and_check_table sets the CRC/valid flags and leaves an
     * explanatory tsk error behind on failure. */
    gpt_read_and_check_table(vs, copy, max_addr,
        gpt_type == PRIMARY_TABLE ? "primary" : "backup");
    return 0;
}

static void
gpt_copy_free(gpt_copy * copy)
{
    if (copy->head) {
        free(copy->head);
        copy->head = NULL;
    }
    if (copy->tab) {
        free(copy->tab);
        copy->tab = NULL;
    }
    copy->valid = 0;
}

/*
 * Add the metadata ("meta") partitions describing the GPT layout.  These
 * are only created once a trustworthy table has been chosen.
 */
static uint8_t
gpt_add_meta_parts(TSK_VS_INFO * vs, const gpt_copy * trusted)
{
    char *safe_str = NULL, *head_str = NULL, *tab_str = NULL;

    if (trusted->location == PRIMARY_TABLE) {
        if ((safe_str = tsk_malloc(16)) == NULL)
            return 1;
        snprintf(safe_str, 16, "Safety Table");
        if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) 0,
                (TSK_DADDR_T) 1, TSK_VS_PART_FLAG_META, safe_str, -1, -1)) {
            free(safe_str);
            return 1;
        }
    }

    if ((head_str = tsk_malloc(16)) == NULL) {
        free(safe_str);
        return 1;
    }
    snprintf(head_str, 16, "GPT Header");
    {
        TSK_DADDR_T head_rel_lba, head_abs_lba;
        gpt_header_lba(vs, trusted->location, &head_rel_lba, &head_abs_lba);
        if (NULL == tsk_vs_part_add(vs, head_rel_lba,
                (TSK_DADDR_T) ((trusted->head_size +
                        (vs->block_size - 1)) / vs->block_size),
                TSK_VS_PART_FLAG_META, head_str, -1, -1)) {
            free(head_str);
            return 1;
        }
    }

    if ((tab_str = tsk_malloc(20)) == NULL) {
        free(head_str);
        return 1;
    }
    snprintf(tab_str, 20, "Partition Table");
    if (NULL == tsk_vs_part_add(vs, trusted->tab_start_lba,
            (TSK_DADDR_T) (((uint64_t) trusted->ent_size *
                    trusted->tab_num_ent +
                    (vs->block_size - 1)) / vs->block_size),
            TSK_VS_PART_FLAG_META, tab_str, -1, -1)) {
        free(tab_str);
        return 1;
    }

    return 0;
}

/*
 * Parse the partition entries of a validated entry array into the internal
 * sorted list.  Only called for copies whose header and table CRCs have
 * been verified, so every reported partition comes from trusted bytes.
 */
static uint8_t
gpt_parse_entries(TSK_VS_INFO * vs, const gpt_copy * trusted,
    TSK_DADDR_T max_addr)
{
    uint32_t i;

    for (i = 0; i < trusted->tab_num_ent; i++) {
        const gpt_entry *ent =
            (const gpt_entry *) (trusted->tab +
            (size_t) i * trusted->ent_size);
        char *name;
        UTF16 *name16;
        UTF8 *name8;
        int retVal;
        uint64_t start_lba, end_lba;

        start_lba = tsk_getu64(vs->endian, ent->start_lba);
        end_lba = tsk_getu64(vs->endian, ent->end_lba);

        if (start_lba == 0)
            continue;

        /* make sure the first couple are in the image bounds */
        if ((i < 2) && (start_lba > max_addr)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
            tsk_error_set_errstr
                ("gpt_parse_entries: Starting sector too large for image");
            return 1;
        }

        if ((name = tsk_malloc(256)) == NULL)
            return 1;

        name16 = (UTF16 *) ((uintptr_t) ent->name);
        name8 = (UTF8 *) name;

        retVal =
            tsk_UTF16toUTF8(vs->endian, (const UTF16 **) &name16,
            (UTF16 *) ((uintptr_t) name16 + sizeof(ent->name)),
            &name8,
            (UTF8 *) ((uintptr_t) name8 + 256), TSKlenientConversion);

        if (retVal != TSKconversionOK) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "gpt_parse_entries: Error converting name to UTF8: %d\n",
                    retVal);
            *name = '\0';
        }

        if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) start_lba,
                (TSK_DADDR_T) (end_lba - start_lba + 1),
                TSK_VS_PART_FLAG_ALLOC, name, -1, (int8_t) i)) {
            free(name);
            return 1;
        }
    }

    return 0;
}

/*
 * Core validation: read both GPT copies, verify every CRC, and compare the
 * copies against each other.  The two gpt_copy structures are owned by the
 * caller (which must zero-initialize them and eventually call
 * gpt_copy_free on each).  On success *trusted points to one of those two
 * caller-owned copies whose entry array should be parsed (the two copies
 * are identical at that point), so the pointer stays valid after return.
 *
 * Return values:
 *   0  both copies are valid and mutually consistent (normal case)
 *   1  no trustworthy partition information exists, or the copies disagree
 *      while at least one of them is individually valid (tampering risk);
 *      tsk_errno is TSK_ERR_VS_CRC in both situations
 *   2  neither on-disk copy could even be located/read (caller may retry
 *      with a different sector size, or fall back to a backup-only open)
 *   3  exactly one copy is fully CRC-valid while the other is absent or
 *      unreadable (not CRC-bad): the surviving copy may be opened in
 *      backup-only recovery mode
 */
static uint8_t
gpt_validate(TSK_VS_INFO * vs, gpt_copy * primary, gpt_copy * secondary,
    const gpt_copy ** trusted)
{
    TSK_DADDR_T max_addr =
        (vs->img_info->size - vs->offset) / vs->block_size;
    uint8_t rc = 1;

    *trusted = NULL;

    gpt_load_copy(vs, PRIMARY_TABLE, primary, max_addr);
    gpt_load_copy(vs, SECONDARY_TABLE, secondary, max_addr);

    if (!primary->valid && !secondary->valid) {
        /* Nothing structurally usable.  This is a tampering / corruption
         * signal only if at least one header was actually read but then
         * failed a CRC check.  A head pointer that is NULL means the GPT
         * signature was never present at the expected LBA (a non-GPT disk,
         * or one whose GPT area was overwritten), which is an ordinary
         * probe miss rather than a checksum failure. */
        int primary_crc_bad =
            primary->head && (!primary->head_crc_ok
                || !primary->tab_crc_ok);
        int secondary_crc_bad =
            secondary->head && (!secondary->head_crc_ok
                || !secondary->tab_crc_ok);

        if (primary_crc_bad || secondary_crc_bad) {
            /* tsk error from the failing check is already in place; make
             * sure the errno reflects the CRC/tampering category. */
            tsk_error_set_errno(TSK_ERR_VS_CRC);
            rc = 1;
        }
        else {
            /* Neither copy was read far enough to run a CRC check.
             * Clear the low-level read/magic error so the caller can
             * retry with another sector size or try backup-only mode. */
            tsk_error_reset();
            rc = 2;
        }
        return rc;
    }

    if (primary->valid && secondary->valid) {
        /* Both copies are individually CRC-valid; they must describe the
         * same disk.  Any divergence is a tampering signal. */
        if (!gpt_headers_structurally_equal(vs, primary->head,
                secondary->head)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_CRC);
            tsk_error_set_errstr
                ("Primary and backup GPT header structural fields differ "
                    "(tampering or corruption detected); no unmarked "
                    "partition information will be reported");
            return 1;
        }

        if (primary->tab_size != secondary->tab_size
            || memcmp(primary->tab, secondary->tab,
                primary->tab_size) != 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_CRC);
            tsk_error_set_errstr
                ("Primary and backup GPT partition entry arrays differ "
                    "despite valid CRCs (tampering or corruption "
                    "detected); no unmarked partition information will be "
                    "reported");
            return 1;
        }

        *trusted = primary;
        return 0;
    }

    /* Exactly one copy is CRC-valid.
     *
     * If the invalid copy was never even read (e.g. the start of the disk
     * was overwritten and there is no primary header at all), this is the
     * classic "backup-only" recovery situation rather than tampering: the
     * surviving copy's own CRCs still certify its contents.  Signal the
     * caller to fall back to backup-only mode (rc 2).
     *
     * If the invalid copy WAS read but failed a CRC check, both copies
     * existed on disk yet disagree in integrity terms.  That is a tampering
     * / corruption signal: refuse to present any partition layout as
     * trustworthy (rc 1). */
    {
        int primary_read_but_bad =
            primary->head && (!primary->head_crc_ok
                || !primary->tab_crc_ok);
        int secondary_read_but_bad =
            secondary->head && (!secondary->head_crc_ok
                || !secondary->tab_crc_ok);

        if (primary->valid && !secondary->valid && !secondary_read_but_bad) {
            /* Backup absent/unreadable, primary self-consistent. */
            tsk_error_reset();
            return 3;
        }
        if (secondary->valid && !primary->valid && !primary_read_but_bad) {
            /* Primary absent/unreadable, backup self-consistent. */
            tsk_error_reset();
            return 3;
        }
    }

    if (primary->valid)
        tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_VS_CRC);
    if (!primary->valid) {
        tsk_error_set_errstr2
            ("Primary GPT copy failed validation; backup alone is not "
                "sufficient to certify partition integrity");
    }
    else {
        tsk_error_set_errstr2
            ("Backup GPT copy failed validation; primary alone is not "
                "sufficient to certify partition integrity");
    }
    return 1;
}

/*
 * Backup-only open used when no primary GPT can be found at all (e.g. the
 * start of the disk was overwritten).  The backup header and entry array
 * CRCs are still fully verified before any partition is reported, so a
 * corrupted backup cannot inject unmarked partitions.
 */
static uint8_t
gpt_load_backup_only(TSK_VS_INFO * vs)
{
    gpt_copy backup;
    TSK_DADDR_T max_addr =
        (vs->img_info->size - vs->offset) / vs->block_size;

    gpt_load_copy(vs, SECONDARY_TABLE, &backup, max_addr);
    if (!backup.valid) {
        /* Preserve the detailed CRC error when available. */
        if (backup.head && (!backup.head_crc_ok || !backup.tab_crc_ok)) {
            gpt_copy_free(&backup);
            return 1;
        }
        gpt_copy_free(&backup);
        return 2;
    }

    if (gpt_add_meta_parts(vs, &backup)) {
        gpt_copy_free(&backup);
        return 1;
    }
    if (gpt_parse_entries(vs, &backup, max_addr)) {
        gpt_copy_free(&backup);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "gpt_open: primary table absent; loading CRC-valid backup "
            "only (partition layout is not cross-certified)\n");

    gpt_copy_free(&backup);
    return 0;
}

static void
gpt_close(TSK_VS_INFO * vs)
{
    vs->tag = 0;
    tsk_vs_part_free(vs);
    free(vs);
}

TSK_VS_INFO *
tsk_vs_gpt_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset)
{
    TSK_VS_INFO *vs;

    // clean up any errors that are lying around
    tsk_error_reset();

    if (img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_ARG);
        tsk_error_set_errstr("tsk_vs_gpt_open: sector size is 0");
        return NULL;
    }

    vs = (TSK_VS_INFO *) tsk_malloc(sizeof(*vs));
    if (vs == NULL)
        return NULL;

    vs->img_info = img_info;
    vs->vstype = TSK_VS_TYPE_GPT;
    vs->tag = TSK_VS_INFO_TAG;

    /* If an offset was given, then use that too */
    vs->offset = offset;

    /* initialize settings */
    vs->part_list = NULL;
    vs->part_count = 0;
    vs->endian = 0;
    vs->block_size = img_info->sector_size;
    vs->is_backup = 0;

    /* Assign functions */
    vs->close = gpt_close;

    {
        /* Try the native sector size first, then a range of common
         * sector sizes, mirroring the previous recovery behaviour.  The
         * CRC/cross-copy validation runs for every attempt. */
        unsigned int tried_sizes[6];
        int num_sizes = 0;
        int i;
        int found = 0;
        int saw_crc_failure = 0;
        int saw_recoverable = 0;     /* rc 3: one self-consistent copy */
        unsigned int recover_size = 0;   /* sector size of that copy */
        gpt_copy primary, secondary;
        const gpt_copy *trusted = NULL;

        memset(&primary, 0, sizeof(primary));
        memset(&secondary, 0, sizeof(secondary));

        tried_sizes[num_sizes++] = img_info->sector_size;
        {
            unsigned int s;
            for (s = 512; s <= 8192; s *= 2) {
                int dup = 0;
                for (i = 0; i < num_sizes; i++) {
                    if (tried_sizes[i] == s) {
                        dup = 1;
                        break;
                    }
                }
                if (!dup && num_sizes < 6)
                    tried_sizes[num_sizes++] = s;
            }
        }

        for (i = 0; i < num_sizes && !found; i++) {
            uint8_t vrc;

            tsk_vs_part_free(vs);
            gpt_copy_free(&primary);
            gpt_copy_free(&secondary);
            trusted = NULL;
            vs->block_size = tried_sizes[i];

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "gpt_open: validating primary+backup GPT, sector size %u\n",
                    vs->block_size);

            vrc = gpt_validate(vs, &primary, &secondary, &trusted);
            if (vrc == 0) {
                TSK_DADDR_T max_addr =
                    (img_info->size - offset) / vs->block_size;
                tsk_error_reset();
                if (gpt_add_meta_parts(vs, trusted)) {
                    gpt_copy_free(&primary);
                    gpt_copy_free(&secondary);
                    goto err;
                }
                if (gpt_parse_entries(vs, trusted, max_addr)) {
                    gpt_copy_free(&primary);
                    gpt_copy_free(&secondary);
                    goto err;
                }
                found = 1;
                break;
            }

            if (vrc == 1) {
                /* Tampering / CRC failure: this is a definitive result for
                 * this sector size, not something a different sector size
                 * can repair.  Remember it and stop probing. */
                saw_crc_failure = 1;
                break;
            }

            if (vrc == 3) {
                /* One fully-valid copy survives while the other is simply
                 * absent/unreadable.  Record the sector size that worked
                 * and stop probing: a different sector size cannot improve
                 * the situation, and probing it could misread the good
                 * copy.  The backup-only path below reuses this size. */
                saw_recoverable = 1;
                recover_size = tried_sizes[i];
                tsk_error_reset();
                break;
            }
            /* vrc == 2: no readable GPT at this sector size, try next. */
            tsk_error_reset();
        }

        /* The raw header/table buffers are no longer needed once the
         * partition list has been built (or once we give up on them). */
        gpt_copy_free(&primary);
        gpt_copy_free(&secondary);

        if (found)
            goto success;

        if (saw_crc_failure) {
            /* The detailed TSK_ERR_VS_CRC message is already set.  Do not
             * fall through to the backup-only path: an uncertified table
             * must not be presented as trustworthy. */
            gpt_close(vs);
            return NULL;
        }

        /* No primary+backup pair at any sector size.  Keep the legacy
         * recovery of opening a CRC-valid backup table alone. */
        if (tsk_verbose)
            tsk_fprintf(stderr, "gpt_open: Trying backup-only table\n");

        if (saw_recoverable) {
            /* We already know a fully CRC-valid single copy exists at this
             * sector size; open it directly rather than re-probing sizes
             * at which the disk layout cannot be read. */
            uint8_t brc;
            tsk_vs_part_free(vs);
            vs->block_size = recover_size;
            vs->is_backup = 1;
            brc = gpt_load_backup_only(vs);
            if (brc == 0)
                found = 1;
            else if (brc == 1) {
                /* CRC failure of the backup itself: definitive. */
                gpt_close(vs);
                return NULL;
            }
            tsk_error_reset();
        }

        if (!found) {
            for (i = 0; i < num_sizes; i++) {
                uint8_t brc;

                tsk_vs_part_free(vs);
                vs->block_size = tried_sizes[i];
                vs->is_backup = 1;

                brc = gpt_load_backup_only(vs);
                if (brc == 0) {
                    found = 1;
                    break;
                }
                if (brc == 1) {
                    /* CRC failure of the backup itself: definitive. */
                    gpt_close(vs);
                    return NULL;
                }
                /* brc == 2: unreadable at this sector size, keep trying. */
                tsk_error_reset();
            }
        }

        if (!found) {
            gpt_close(vs);
            return NULL;
        }
    }

  success:
    /* fill in the sorted list with the 'unknown' values */
    if (tsk_vs_part_unused(vs)) {
        gpt_close(vs);
        return NULL;
    }

    return vs;

  err:
    gpt_close(vs);
    return NULL;
}

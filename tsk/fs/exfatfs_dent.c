/*
** The Sleuth Kit
**
** Copyright (c) 2013 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/*
 * This code makes use of research presented in the following paper:
 * "Reverse Engineering the exFAT File System" by Robert Shullich
 * Retrieved May 2013 from: 
 * http://www.sans.org/reading_room/whitepapers/forensics/reverse-engineering-microsoft-exfat-file-system_33274
 *
 * Some additional details concerning TexFAT were obtained in May 2013
 * from:
 * http://msdn.microsoft.com/en-us/library/ee490643(v=winembedded.60).aspx
*/

/**
 * \file exfatfs_dent.c
 * Contains the internal TSK exFAT file system code to handle name category 
 * processing. 
 */

#include "tsk_exfatfs.h" /* Include first to make sure it stands alone. */
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include <assert.h>

/**
 * \internal
 * \struct
 * Bundles a TSK_FS_NAME object and a TSK_FS_DIR object with the directory
 * entries of the file directory entry set currently being assembled. The
 * entries are collected until the number declared by the primary entry has
 * been seen; only then is the set verified and, if it is trustworthy, turned
 * into a TSK_FS_NAME that is added to the TSK_FS_DIR.
 */
typedef struct {
    FATFS_INFO *fatfs;
    int8_t sector_is_allocated;
    EXFATFS_DENTRY_SET set;   /* The directory entries of the set being collected */
    uint8_t name_length_utf16_chars_collected;   /* Number of UTF16 name characters gathered */
    uint8_t file_name_utf16[(EXFATFS_MAX_FILE_NAME_LENGTH_UTF16_CHARS + 1) * 2];  /* The UTF16 characters gathered so far */
    size_t actual_name_length_utf8_bytes;  /* Length of the UTF8 version of the name (stored in fs_name) */
    TSK_FS_NAME *fs_name;
    TSK_FS_DIR *fs_dir;
} EXFATFS_FS_NAME_INFO;

/**
 * \internal
 * Reset the fields of a EXFATFS_FS_NAME_INFO to their initialized state. This
 * allows for reuse of the object.
 *
 * @param a_name_info The name info object.
 */
static void
exfatfs_reset_name_info(EXFATFS_FS_NAME_INFO *a_name_info)
{
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);

    memset((void*)&a_name_info->set, 0, sizeof(EXFATFS_DENTRY_SET));
    a_name_info->set.fatfs = a_name_info->fatfs;
    a_name_info->name_length_utf16_chars_collected = 0;
    a_name_info->file_name_utf16[0] = '\0';
    a_name_info->actual_name_length_utf8_bytes = 0;
    a_name_info->fs_name->name[0] = '\0';
    a_name_info->fs_name->meta_addr = 0;
    a_name_info->fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
    a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
    a_name_info->fs_name->fs_specific_flags = EXFATFS_DENTRY_SET_STATUS_NOT_APPLICABLE;
    a_name_info->fs_name->fs_specific_meta_addr = 0;
    a_name_info->fs_name->fs_specific_meta_addr2 = 0;
    a_name_info->fs_name->fs_specific_count = 0;
}

/**
 * \internal
 * Gather the UTF16 name characters of the collected file name entries into
 * the name buffer of an EXFATFS_FS_NAME_INFO, using only the number of
 * characters declared by the stream extension entry. Any characters beyond
 * the declared length are dropped.
 *
 * @param a_name_info The name info object.
 */
static void
exfatfs_gather_name_utf16(EXFATFS_FS_NAME_INFO *a_name_info)
{
    uint8_t entry_index = 0;
    uint8_t chars_remaining = 0;

    assert(a_name_info != NULL);

    a_name_info->name_length_utf16_chars_collected = 0;
    memset(a_name_info->file_name_utf16, 0, sizeof(a_name_info->file_name_utf16));

    if ((a_name_info->set.entries_count < 3) || !a_name_info->set.stream_entry_is_present) {
        return;
    }

    chars_remaining = a_name_info->set.declared_name_length_utf16_chars;

    for (entry_index = 2;
        (entry_index < a_name_info->set.entries_count) && (chars_remaining > 0);
        ++entry_index) {
        EXFATFS_FILE_NAME_DIR_ENTRY *name_dentry =
            (EXFATFS_FILE_NAME_DIR_ENTRY*)&a_name_info->set.entries[entry_index];
        uint8_t chars_to_copy = EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH_UTF16_CHARS;

        if (chars_to_copy > chars_remaining) {
            chars_to_copy = chars_remaining;
        }
        memcpy(&a_name_info->file_name_utf16[
                (size_t)a_name_info->name_length_utf16_chars_collected * 2],
            name_dentry->utf16_name_chars, (size_t)chars_to_copy * 2);
        a_name_info->name_length_utf16_chars_collected += chars_to_copy;
        chars_remaining -= chars_to_copy;
    }
}

/**
 * \internal
 * Verify the file directory entry set currently captured in an
 * EXFATFS_FS_NAME_INFO object and add a TSK_FS_NAME for it to the TSK_FS_DIR
 * object, carrying the verification status in the name's fs_specific_flags
 * field and the inode addresses of the stream and first file name entries in
 * the fs_specific_meta_addr and fs_specific_meta_addr2 fields.
 *
 * A name is only added when at least one character of name could be
 * assembled from the entries that actually belong to the set, in order.
 * Entries that do not belong to the set are never consumed into it, so a
 * truncated or damaged set does not steal the name entries of the next file.
 *
 * The name info object is reset afterwards, so it can be reused.
 *
 * @param a_name_info The name info object.
 */
static void
exfatfs_verify_set_and_add_name(EXFATFS_FS_NAME_INFO *a_name_info)
{
    EXFATFS_FILE_DIR_ENTRY *file_dentry = NULL;

    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_dir != NULL);

    /* Nothing collected since the last reset - nothing to verify. */
    if (!a_name_info->set.primary_entry_is_present) {
        exfatfs_reset_name_info(a_name_info);
        return;
    }

    file_dentry = (EXFATFS_FILE_DIR_ENTRY*)&a_name_info->set.entries[0];

    /* Compute the verification status. The sequence was complete if we
     * collected exactly the number of entries the primary entry declared, in
     * the expected order (guaranteed by the collection routines). */
    exfatfs_finalize_dentry_set(&a_name_info->set,
        (uint8_t)(a_name_info->set.entries_count ==
            (uint8_t)(a_name_info->set.stored_secondary_entry_count + 1)));

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "%s: Directory entry set at %" PRIuINUM " (check sum stored 0x%04x, calculated 0x%04x): %s\n",
            "exfatfs_verify_set_and_add_name", a_name_info->set.primary_inum,
            a_name_info->set.stored_check_sum, a_name_info->set.calculated_check_sum,
            exfatfs_dentry_set_status_to_str(a_name_info->set.status));
    }

    /* A deleted (cleaned) set is a recovery result, so it is only enumerated
     * when its check sum verified: a name taken from an unverified deleted set
     * must not be presented as recovered. An in-use set is enumerated with
     * whatever of its entries belong to it, and the status carried with the
     * name tells whether it is complete, has a check sum mismatch, or broke
     * its sequence. No set can pull in the entries of the next file, because
     * only entries that continue the declared sequence are collected. */
    if (a_name_info->set.is_deleted &&
        (a_name_info->set.status != EXFATFS_DENTRY_SET_STATUS_DELETED_RECOVERABLE)) {
        exfatfs_reset_name_info(a_name_info);
        return;
    }

    /* Assemble the name from the entries that actually belong to the set, in
     * order, bounded by the length the stream entry declares. A set that is
     * missing entries or whose sequence broke only yields the characters that
     * were present before the break, never the entries of the next file. The
     * verification status recorded with the name tells how far the name can
     * be trusted. */
    exfatfs_gather_name_utf16(a_name_info);

    /* If no name characters could be assembled there is nothing to add; the
     * verification status remains available through the metadata path. */
    if (a_name_info->name_length_utf16_chars_collected == 0) {
        exfatfs_reset_name_info(a_name_info);
        return;
    }

    if (fatfs_utf16_inode_str_2_utf8(a_name_info->fatfs,
        (UTF16*)a_name_info->file_name_utf16,
        a_name_info->name_length_utf16_chars_collected,
        (UTF8*)a_name_info->fs_name->name, a_name_info->fs_name->name_size,
        a_name_info->set.primary_inum, "file name") != TSKconversionOK) {
        /* Do not report a name that could not be converted. */
        exfatfs_reset_name_info(a_name_info);
        return;
    }

    a_name_info->actual_name_length_utf8_bytes = strlen(a_name_info->fs_name->name);
    if (a_name_info->actual_name_length_utf8_bytes == 0) {
        exfatfs_reset_name_info(a_name_info);
        return;
    }

    /* The file type comes from the primary entry. */
    if (file_dentry->attrs[0] & FATFS_ATTR_DIRECTORY) {
        a_name_info->fs_name->type = TSK_FS_NAME_TYPE_DIR;
    }
    else {
        a_name_info->fs_name->type = TSK_FS_NAME_TYPE_REG;
    }

    /* The allocation status comes from both the in-use bit of the primary
     * entry and the allocation status of the sector that contains it. Only a
     * set that is complete and verified - and is not deleted - is reported as
     * allocated; a set with a check sum mismatch or a broken sequence keeps
     * the entries but is not presented as live data. */
    if (a_name_info->set.primary_sector_is_alloc && !a_name_info->set.is_deleted &&
        (a_name_info->set.status == EXFATFS_DENTRY_SET_STATUS_COMPLETE)) {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
    }
    else {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
    }

    /* Associate the name with the entries of the set and its verification
     * status. */
    a_name_info->fs_name->meta_addr = a_name_info->set.primary_inum;
    a_name_info->fs_name->fs_specific_flags = (uint32_t)a_name_info->set.status;
    a_name_info->fs_name->fs_specific_meta_addr = a_name_info->set.stream_inum;
    a_name_info->fs_name->fs_specific_meta_addr2 = a_name_info->set.first_name_inum;
    a_name_info->fs_name->fs_specific_count = a_name_info->set.name_entries_count;

    tsk_fs_dir_add(a_name_info->fs_dir, a_name_info->fs_name);

    exfatfs_reset_name_info(a_name_info);
}

/**
 * \internal
 * Add the TSK_FS_NAME object of an EXFATFS_FS_NAME_INFO object to its
 * TSK_FS_DIR object, if it has a name, and reset the fields of the
 * EXFATFS_FS_NAME_INFO to their initialized state. This is used for
 * directory entries that stand alone rather than being part of a file
 * directory entry set, such as volume labels and the special files.
 *
 * @param a_name_info The name info object.
 */
static void
exfatfs_add_simple_name_to_dir_and_reset_info(EXFATFS_FS_NAME_INFO *a_name_info)
{
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_dir != NULL);

    if (strlen(a_name_info->fs_name->name) > 0) {
        tsk_fs_dir_add(a_name_info->fs_dir, a_name_info->fs_name);
    }

    exfatfs_reset_name_info(a_name_info);
}

/**
 * \internal
 * Save the name assembled from the current directory entry set, if any, and
 * reset the fields of an EXFATFS_FS_NAME_INFO to their initialized state.
 * This is the point where the set is verified.
 *
 * @param a_name_info The name info object.
 */
static void
exfatfs_add_name_to_dir_and_reset_info(EXFATFS_FS_NAME_INFO *a_name_info)
{
    exfatfs_verify_set_and_add_name(a_name_info);
}

/**
 * \internal
 * Start collecting a new file directory entry set from a file directory
 * entry. Any set that was being assembled is verified and saved first.
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a file directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_file_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_FILE_DIR_ENTRY *dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry;
    EXFATFS_DENTRY_SET *set = NULL;

    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(dentry != NULL);
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    /* Starting parse of a new set, so verify and save the current set, if any. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);

    set = &a_name_info->set;
    set->primary_entry_is_present = 1;
    set->primary_inum = a_inum;
    set->first_name_inum = 0;
    set->stream_inum = 0;
    set->last_inum = a_inum;
    set->is_deleted = (uint8_t)(exfatfs_get_alloc_status_from_type(dentry->entry_type) == 0);
    set->primary_sector_is_alloc =
        (uint8_t)(a_name_info->sector_is_allocated > 0);
    set->stored_secondary_entry_count = dentry->secondary_entries_count;
    set->stored_check_sum =
        tsk_getu16(a_name_info->fatfs->fs_info.endian, dentry->check_sum);
    set->status = EXFATFS_DENTRY_SET_STATUS_UNKNOWN_SOURCE;

    memcpy(&set->entries[set->entries_count], a_dentry, sizeof(FATFS_DENTRY));
    set->entries_count = 1;
}

/**
 * \internal
 * Add a file stream directory entry to the set being collected. A stream entry
 * is only accepted as the first secondary entry of an open set whose primary
 * entry has the same in-use state. Otherwise the set is finalized as
 * unconfirmable and the stream entry is ignored - it must not be attached to
 * some other file, nor may it cause the entries that follow to be attached to
 * the current file.
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a file stream directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_file_stream_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_FILE_STREAM_DIR_ENTRY *dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)a_dentry;
    EXFATFS_DENTRY_SET *set = NULL;
    uint8_t belongs = 0;

    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(dentry != NULL);
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    set = &a_name_info->set;

    /* A stream entry is only meaningful as the first secondary entry of a set
     * that has an open primary entry, with a matching in-use state, and only
     * while there is room in the set buffer. */
    if (set->primary_entry_is_present && !set->stream_entry_is_present &&
        (set->entries_count == 1) &&
        (set->stored_secondary_entry_count >= EXFATFS_MIN_FILE_SECONDARY_DENTRIES_COUNT) &&
        (set->stored_secondary_entry_count <= EXFATFS_MAX_FILE_SECONDARY_DENTRIES_COUNT) &&
        (set->entries_count < EXFATFS_MAX_FILE_DENTRY_SET_ENTRIES) &&
        (exfatfs_get_alloc_status_from_type(
            set->entries[0].data[0]) == exfatfs_get_alloc_status_from_type(dentry->entry_type))) {
        belongs = 1;
    }

    if (!belongs) {
        /* Save the current set, if any, and ignore this buffer. */
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
        return;
    }

    set->stream_entry_is_present = 1;
    set->stream_inum = a_inum;
    set->last_inum = a_inum;
    memcpy(&set->entries[set->entries_count], a_dentry, sizeof(FATFS_DENTRY));
    ++set->entries_count;

    /* If the primary entry declared no file name entries, the set is complete
     * (and structurally invalid) as soon as the stream entry is seen. */
    if (set->entries_count == (uint8_t)(set->stored_secondary_entry_count + 1)) {
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
    }
}

/**
 * \internal
 * Add a file name directory entry to the set being collected. A name entry is
 * only accepted after the stream entry of an open set, with a matching in-use
 * state, and only while the number of entries declared by the primary entry
 * has not been reached. Otherwise the set is finalized as unconfirmable and
 * the name entry is ignored.
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a file name directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_file_name_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)a_dentry;
    EXFATFS_DENTRY_SET *set = NULL;
    uint8_t belongs = 0;

    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(dentry != NULL);
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE_NAME);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    set = &a_name_info->set;

    /* A file name entry must follow the stream entry (or another name entry)
     * and stay within the number of entries declared by the primary entry and
     * the size of the set buffer. */
    if (set->primary_entry_is_present && set->stream_entry_is_present &&
        (set->entries_count > 1) &&
        (set->stored_secondary_entry_count <= EXFATFS_MAX_FILE_SECONDARY_DENTRIES_COUNT) &&
        (set->entries_count < (uint8_t)(set->stored_secondary_entry_count + 1)) &&
        (set->entries_count < EXFATFS_MAX_FILE_DENTRY_SET_ENTRIES) &&
        (exfatfs_get_alloc_status_from_type(
            set->entries[set->entries_count - 1].data[0]) ==
            exfatfs_get_alloc_status_from_type(dentry->entry_type))) {
        belongs = 1;
    }

    if (!belongs) {
        /* Save the current set, if any, and ignore this buffer. */
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
        return;
    }

    if (set->first_name_inum == 0) {
        set->first_name_inum = a_inum;
    }
    set->last_inum = a_inum;
    memcpy(&set->entries[set->entries_count], a_dentry, sizeof(FATFS_DENTRY));
    ++set->entries_count;

    /* If all of the secondary entries for the set are present, verify and
     * save the name, if any. */
    if (set->entries_count == (uint8_t)(set->stored_secondary_entry_count + 1)) {
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
    }
}


/**
 * \internal
 * Populates an EXFATFS_FS_NAME_INFO object with data parsed from a volume
 * label directory entry. 
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a volume label directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_vol_label_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;
    const char *tag = " (Volume Label Entry)";
    size_t tag_length = 0;

    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(dentry != NULL);
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    /* Starting parse of a new name, verify and save any open set, then save
     * the previous name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);

    /* The volume label is supposed to be a max of 11 characters. In practice it is
     * sometimes possible to extend the name into the reserved area, making the
     * maximum 15 characters, which is what is stored in EXFATFS_MAX_VOLUME_LABEL_LEN_CHAR. */
    if (dentry->volume_label_length_chars > EXFATFS_MAX_VOLUME_LABEL_LEN_CHAR) {
        dentry->volume_label_length_chars = EXFATFS_MAX_VOLUME_LABEL_LEN_CHAR;
    }

    if(exfatfs_get_alloc_status_from_type(dentry->entry_type) == 1){
        if (fatfs_utf16_inode_str_2_utf8(a_name_info->fatfs,
            (UTF16*)dentry->volume_label, (size_t)dentry->volume_label_length_chars,
            (UTF8*)a_name_info->fs_name->name, a_name_info->fs_name->name_size,
            a_inum, "volume label") != TSKconversionOK) {
            /* Discard whatever was written by the failed conversion. */
            exfatfs_reset_name_info(a_name_info);
            return;
        }
    }
    else {
        strcpy(a_name_info->fs_name->name, EXFATFS_EMPTY_VOLUME_LABEL_DENTRY_NAME);
    }

    a_name_info->actual_name_length_utf8_bytes = strlen(a_name_info->fs_name->name);

    tag_length = strlen(tag);
    if (a_name_info->actual_name_length_utf8_bytes + tag_length <
        FATFS_MAXNAMLEN_UTF8) {
        strcat(a_name_info->fs_name->name, tag);
    }

    /* Record the inum associated with this name. */
    a_name_info->fs_name->meta_addr =  a_inum;

    /* Not a directory. */
    a_name_info->fs_name->type = TSK_FS_NAME_TYPE_REG;

    if (a_name_info->sector_is_allocated) {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
    }

    /* Save the volume label. */
    exfatfs_add_simple_name_to_dir_and_reset_info(a_name_info);
}

/**
 * \internal
 * Populates an EXFATFS_FS_NAME_INFO object with data parsed from a 
 * special file directory entry. 
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a special file directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_special_file_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(a_dentry != NULL);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    /* Starting parse of a new name, verify and save any open set, then save
     * the previous name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);

    /* Record the inum associated with this name. */
    a_name_info->fs_name->meta_addr = a_inum;

    switch (exfatfs_get_enum_from_type(a_dentry->data[0])) {
        case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
            strcpy(a_name_info->fs_name->name, EXFATFS_VOLUME_GUID_DENTRY_NAME);
            break;
        case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
            strcpy(a_name_info->fs_name->name, EXFATFS_ALLOC_BITMAP_DENTRY_NAME);
            break;
        case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
            strcpy(a_name_info->fs_name->name, EXFATFS_UPCASE_TABLE_DENTRY_NAME);
            break;
        case EXFATFS_DIR_ENTRY_TYPE_TEXFAT:
            strcpy(a_name_info->fs_name->name, EXFATFS_TEX_FAT_DENTRY_NAME);
            break;
        case EXFATFS_DIR_ENTRY_TYPE_ACT:
            strcpy(a_name_info->fs_name->name, EXFATFS_ACT_DENTRY_NAME);
            break;

        // listed so that we don't get compile warnings
        case EXFATFS_DIR_ENTRY_TYPE_NONE:
        case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
        case EXFATFS_DIR_ENTRY_TYPE_FILE:
        case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
        case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
        default:
            a_name_info->fs_name->name[0] = '\0';
            break;
    }

    /* Not a directory. */
    a_name_info->fs_name->type = TSK_FS_NAME_TYPE_REG;

    if (a_name_info->sector_is_allocated) {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
    }

    /* Save the virtual file name. */
    exfatfs_add_simple_name_to_dir_and_reset_info(a_name_info);
}

/**
 * \internal
 * Parse a buffer containing the contents of a directory and add TSK_FS_NAME 
 * objects for each named file found to the TSK_FS_DIR representation of the 
 * directory.
 *
 * @param a_fatfs File system information structure for file system that
 * contains the directory.
 * @param a_fs_dir Directory structure into to which parsed file metadata will
 * be added.
 * @param a_buf Buffer that contains the directory contents.
 * @param a_buf_len Length of buffer in bytes (must be a multiple of sector
 *  size).
 * @param a_sector_addrs Array where each element is the original address of
 * the corresponding sector in a_buf (size of array is number of sectors in
 * the directory).
 * @param recursion_depth Recursion depth to limit the number of self-calls
 * @return TSK_RETVAL_ENUM
*/
TSK_RETVAL_ENUM
exfatfs_dent_parse_buf(FATFS_INFO *a_fatfs, TSK_FS_DIR *a_fs_dir, char *a_buf,
    TSK_OFF_T a_buf_len, TSK_DADDR_T *a_sector_addrs, int recursion_depth)
{
    const char *func_name = "exfatfs_parse_directory_buf";
    TSK_FS_INFO *fs = NULL;
    TSK_OFF_T num_sectors = 0;
    TSK_OFF_T sector_index = 0;
    TSK_INUM_T base_inum_of_sector = 0;
    EXFATFS_FS_NAME_INFO name_info;
    TSK_OFF_T dentry_index = 0;
    FATFS_DENTRY *dentry = NULL;
    int entries_count = 0;
    int invalid_entries_count = 0;
    uint8_t is_corrupt_dir = 0;

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_dir, "a_fs_dir", func_name) ||
        fatfs_ptr_arg_is_null(a_buf, "a_buf", func_name) ||
        fatfs_ptr_arg_is_null(a_sector_addrs, "a_sector_addrs", func_name)) {
        return TSK_ERR; 
    }

    assert(a_buf_len > 0);
    if (a_buf_len < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: invalid buffer length", func_name);
        return TSK_ERR; 
    }

    fs = (TSK_FS_INFO*)a_fatfs;

    memset((void*)&name_info, 0, sizeof(EXFATFS_FS_NAME_INFO));
    name_info.fatfs = a_fatfs;
    if ((name_info.fs_name = tsk_fs_name_alloc(FATFS_MAXNAMLEN_UTF8, 0)) == NULL) {
        return TSK_ERR;
    }
    name_info.fs_name->name[0] = '\0';
    name_info.fs_dir = a_fs_dir;

    /* Loop through the sectors in the buffer. */ 
    dentry = (FATFS_DENTRY*)a_buf;
    num_sectors = a_buf_len / a_fatfs->ssize;
    for (sector_index = 0; sector_index < num_sectors; ++sector_index) {
        /* Convert the address of the current sector into an inode address. */
        base_inum_of_sector = 
            FATFS_SECT_2_INODE(a_fatfs, a_sector_addrs[sector_index]);
        if (base_inum_of_sector > fs->last_inum) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr("%s: inode address for sector address %" 
                PRIuDADDR " at addresses array index %" PRIuDADDR 
                " is too large", func_name, base_inum_of_sector, sector_index);
            tsk_fs_name_free(name_info.fs_name);
            return TSK_COR;
        }

        if (tsk_verbose) {
            tsk_fprintf(stderr,"%s: Parsing sector %" PRIuDADDR " for dir %" 
                PRIuINUM "\n", func_name, a_sector_addrs[sector_index], a_fs_dir->addr);
        }

        /* Get the allocation status of the current sector. */
        if ((name_info.sector_is_allocated = 
            fatfs_is_sectalloc(a_fatfs, a_sector_addrs[sector_index])) == -1) {
            if (tsk_verbose) {
                tsk_fprintf(stderr, 
                    "%s: Error looking up allocation status of sector : %"
                    PRIuDADDR "\n", func_name, a_sector_addrs[sector_index]);
                tsk_error_print(stderr);
            }
            tsk_error_reset();
            continue;
        }

        /* Loop through the putative directory entries in the current sector. */
        for (dentry_index = 0; dentry_index < a_fatfs->dentry_cnt_se; ++dentry_index, ++dentry) {
            FATFS_DENTRY *current_dentry = dentry;
            TSK_INUM_T current_inum = base_inum_of_sector + dentry_index;
            EXFATFS_DIR_ENTRY_TYPE dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;

            ++entries_count;

            if (!fatfs_inum_is_in_range(a_fatfs, current_inum)) {
                tsk_fs_name_free(name_info.fs_name);
                return TSK_ERR;
            }

            if (exfatfs_is_dentry(a_fatfs, current_dentry, 
                (FATFS_DATA_UNIT_ALLOC_STATUS_ENUM)name_info.sector_is_allocated, 
                (uint8_t)(!is_corrupt_dir && name_info.sector_is_allocated))) {
                dentry_type = (EXFATFS_DIR_ENTRY_TYPE)current_dentry->data[0];
            }
            else {
                dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;
            }

            switch(exfatfs_get_enum_from_type(dentry_type)) {
            case EXFATFS_DIR_ENTRY_TYPE_FILE:
                exfats_parse_file_dentry(&name_info, current_dentry, current_inum);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
                exfats_parse_file_stream_dentry(&name_info, current_dentry, current_inum);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
                exfats_parse_file_name_dentry(&name_info, current_dentry, current_inum);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
                exfats_parse_vol_label_dentry(&name_info, current_dentry, current_inum);
                break;
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
            case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
            case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
            case EXFATFS_DIR_ENTRY_TYPE_TEXFAT:
            case EXFATFS_DIR_ENTRY_TYPE_ACT:
                exfats_parse_special_file_dentry(&name_info, current_dentry, current_inum);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_NONE:
            default:
                ++invalid_entries_count;
                if (entries_count == 4 && invalid_entries_count == 4) {
                    /* If the first four putative entries in the buffer are not
                     * entries, set the corrupt directory flag to make entry tests
                     * more in-depth, even for allocated sectors. */
                    is_corrupt_dir = 1;
                }

                /* An entry that is not recognized cannot belong to the set
                 * being collected. Verify and save the set with only the
                 * entries that were actually present, so the entries that
                 * follow are not consumed into it. */
                exfatfs_add_name_to_dir_and_reset_info(&name_info);

                break;
            }
        }
    }

     /* Save the last parsed name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(&name_info);
    tsk_fs_name_free(name_info.fs_name);

    return TSK_OK;
}

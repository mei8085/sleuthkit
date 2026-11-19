/*
 * exfat_dentry_set_test.cpp
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Unit tests for exFAT file directory entry set verification and the
 * association of a primary (file) entry, its stream extension entry, its file
 * name entries, and the verification status with the parsed result.
 *
 * Every fixture is a synthetic image built by exfat_synthetic_image.cpp; no
 * external images, network services, or fuzzing are used.
 */

#include "exfat_dentry_set_test.h"
#include "exfat_synthetic_image.h"

#include <libtsk.h>
#include <tsk/fs/tsk_fs_i.h>
#include <tsk/fs/tsk_exfatfs.h>

#include <cstring>
#include <string>
#include <vector>

namespace {

/* The status values the library stores in TSK_FS_NAME::fs_specific_flags. */
constexpr uint32_t kStatusNotApplicable =
    (uint32_t)EXFATFS_DENTRY_SET_STATUS_NOT_APPLICABLE;
constexpr uint32_t kStatusUnknownSource =
    (uint32_t)EXFATFS_DENTRY_SET_STATUS_UNKNOWN_SOURCE;
constexpr uint32_t kStatusComplete =
    (uint32_t)EXFATFS_DENTRY_SET_STATUS_COMPLETE;
constexpr uint32_t kStatusChecksumMismatch =
    (uint32_t)EXFATFS_DENTRY_SET_STATUS_CHECKSUM_MISMATCH;
constexpr uint32_t kStatusSequenceError =
    (uint32_t)EXFATFS_DENTRY_SET_STATUS_SEQUENCE_ERROR;
constexpr uint32_t kStatusDeletedRecoverable =
    (uint32_t)EXFATFS_DENTRY_SET_STATUS_DELETED_RECOVERABLE;

/* Open an image and the root directory through the public TSK API. */
struct OpenFs {
    TSK_IMG_INFO * img;
    TSK_FS_INFO * fs;
    TSK_FS_DIR * dir;

    OpenFs() : img(NULL), fs(NULL), dir(NULL) {
    }

    ~OpenFs() {
        if (dir != NULL)
            tsk_fs_dir_close(dir);
        if (fs != NULL)
            tsk_fs_close(fs);
        if (img != NULL)
            tsk_img_close(img);
    }
};

bool
openExfat(ExfatSyntheticImage & a_image, OpenFs & a_open)
{
    a_open.img = a_image.openImage();
    if (a_open.img == NULL)
        return false;

    a_open.fs = tsk_fs_open_img(a_open.img, 0, TSK_FS_TYPE_EXFAT);
    if (a_open.fs == NULL)
        return false;

    a_open.dir = tsk_fs_dir_open_meta(a_open.fs, a_open.fs->root_inum);
    return a_open.dir != NULL;
}

/* Find a name in the open root directory. Returns the index or -1. */
int
findName(const TSK_FS_DIR * a_dir, const char * a_name)
{
    size_t count = tsk_fs_dir_getsize(a_dir);

    for (size_t i = 0; i < count; ++i) {
        const TSK_FS_NAME * name = tsk_fs_dir_get_name(a_dir, i);
        if ((name != NULL) && (name->name != NULL) &&
            (strcmp(name->name, a_name) == 0)) {
            return (int)i;
        }
    }
    return -1;
}

}  // namespace

CPPUNIT_TEST_SUITE_REGISTRATION(ExfatDentrySetTest);

void
ExfatDentrySetTest::setUp()
{
}

void
ExfatDentrySetTest::tearDown()
{
}

/*
 * A well formed, in-use file directory entry set must be enumerated with its
 * name, its length, and a status that marks it complete and verified. The
 * status must be associated with the primary, stream, and name entries.
 */
void
ExfatDentrySetTest::testCompleteSetIsVerified()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet set;

    image.buildBase();
    set.name = "complete.txt";
    set.is_directory = false;
    set.deleted = false;
    set.corrupt_checksum = false;
    set.first_cluster = 5;
    set.data_length = 0x1234;
    TSK_INUM_T primary_inum = image.addFileSet(set);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    int idx = findName(open_fs.dir, "complete.txt");
    CPPUNIT_ASSERT(idx >= 0);

    const TSK_FS_NAME * name = tsk_fs_dir_get_name(open_fs.dir, idx);
    CPPUNIT_ASSERT(name != NULL);
    CPPUNIT_ASSERT_EQUAL((TSK_INUM_T)primary_inum, name->meta_addr);
    CPPUNIT_ASSERT_EQUAL(kStatusComplete, name->fs_specific_flags);
    CPPUNIT_ASSERT(name->flags & TSK_FS_NAME_FLAG_ALLOC);
    CPPUNIT_ASSERT_EQUAL((TSK_INUM_T)(primary_inum + 1), name->fs_specific_meta_addr);
    CPPUNIT_ASSERT_EQUAL((TSK_INUM_T)(primary_inum + 2), name->fs_specific_meta_addr2);
    CPPUNIT_ASSERT_EQUAL((uint8_t)1, name->fs_specific_count);

    /* The metadata of the primary entry must also carry the verified set. */
    TSK_FS_FILE * file = tsk_fs_file_open_meta(open_fs.fs, NULL, primary_inum);
    CPPUNIT_ASSERT(file != NULL);
    CPPUNIT_ASSERT(file->meta != NULL);
    CPPUNIT_ASSERT(file->meta->content_len >= EXFATFS_FILE_CONTENT_LEN);

    EXFATFS_META_CONTENT * content =
        (EXFATFS_META_CONTENT*)file->meta->content_ptr;
    CPPUNIT_ASSERT_EQUAL((int)EXFATFS_DENTRY_SET_STATUS_COMPLETE,
        (int)content->dentry_set_status);
    CPPUNIT_ASSERT_EQUAL((TSK_INUM_T)primary_inum, content->primary_inum);
    CPPUNIT_ASSERT_EQUAL((TSK_INUM_T)(primary_inum + 1), content->stream_inum);
    CPPUNIT_ASSERT_EQUAL((TSK_INUM_T)(primary_inum + 2), content->first_name_inum);
    CPPUNIT_ASSERT_EQUAL((uint16_t)0x1234, (uint16_t)file->meta->size);
    CPPUNIT_ASSERT_EQUAL((TSK_DADDR_T)5, content->first_cluster);
    CPPUNIT_ASSERT_EQUAL((uint8_t)2, content->declared_secondary_entry_count);
    CPPUNIT_ASSERT_EQUAL((uint8_t)2, content->actual_secondary_entry_count);

    tsk_fs_file_close(file);
}

/*
 * A set whose check sum does not match must be reported as such. The name is
 * still enumerated - with the mismatch status attached - but the length,
 * location, and time stamps it carries are not presented as verified data.
 */
void
ExfatDentrySetTest::testChecksumMismatchIsFlagged()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet set;

    image.buildBase();
    set.name = "mismatch.txt";
    set.is_directory = false;
    set.deleted = false;
    set.corrupt_checksum = true;
    set.first_cluster = 5;
    set.data_length = 0x99;
    TSK_INUM_T primary_inum = image.addFileSet(set);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    /* The name is enumerated, carrying the mismatch status. */
    int idx = findName(open_fs.dir, "mismatch.txt");
    CPPUNIT_ASSERT(idx >= 0);
    const TSK_FS_NAME * name = tsk_fs_dir_get_name(open_fs.dir, idx);
    CPPUNIT_ASSERT_EQUAL(kStatusChecksumMismatch, name->fs_specific_flags);
    CPPUNIT_ASSERT_EQUAL((TSK_INUM_T)primary_inum, name->meta_addr);

    TSK_FS_FILE * file = tsk_fs_file_open_meta(open_fs.fs, NULL, primary_inum);
    CPPUNIT_ASSERT(file != NULL);
    EXFATFS_META_CONTENT * content =
        (EXFATFS_META_CONTENT*)file->meta->content_ptr;
    CPPUNIT_ASSERT_EQUAL((int)EXFATFS_DENTRY_SET_STATUS_CHECKSUM_MISMATCH,
        (int)content->dentry_set_status);
    CPPUNIT_ASSERT(content->stored_check_sum != content->calculated_check_sum);

    /* The unverified length, location, name, and times are not reported. */
    CPPUNIT_ASSERT_EQUAL((TSK_OFF_T)0, file->meta->size);
    CPPUNIT_ASSERT_EQUAL((TSK_DADDR_T)0, content->first_cluster);
    CPPUNIT_ASSERT_EQUAL((time_t)0, file->meta->mtime);
    CPPUNIT_ASSERT_EQUAL((time_t)0, file->meta->crtime);
    CPPUNIT_ASSERT_EQUAL((time_t)0, file->meta->atime);
    CPPUNIT_ASSERT(file->meta->name2 != NULL);
    CPPUNIT_ASSERT_EQUAL(std::string(""), std::string(file->meta->name2->name));

    tsk_fs_file_close(file);
}

/*
 * A deleted set whose check sum still matches is a cleaned object that can be
 * recovered: its name and length must be reported, with the recoverable
 * status and an unallocated name.
 */
void
ExfatDentrySetTest::testDeletedSetIsRecoverable()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet set;

    image.buildBase();
    set.name = "deleted.txt";
    set.is_directory = false;
    set.deleted = true;
    set.corrupt_checksum = false;
    set.first_cluster = 6;
    set.data_length = 0x77;
    TSK_INUM_T primary_inum = image.addFileSet(set);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    int idx = findName(open_fs.dir, "deleted.txt");
    CPPUNIT_ASSERT(idx >= 0);

    const TSK_FS_NAME * name = tsk_fs_dir_get_name(open_fs.dir, idx);
    CPPUNIT_ASSERT_EQUAL(kStatusDeletedRecoverable, name->fs_specific_flags);
    CPPUNIT_ASSERT(name->flags & TSK_FS_NAME_FLAG_UNALLOC);

    TSK_FS_FILE * file = tsk_fs_file_open_meta(open_fs.fs, NULL, primary_inum);
    CPPUNIT_ASSERT(file != NULL);
    EXFATFS_META_CONTENT * content =
        (EXFATFS_META_CONTENT*)file->meta->content_ptr;
    CPPUNIT_ASSERT_EQUAL((int)EXFATFS_DENTRY_SET_STATUS_DELETED_RECOVERABLE,
        (int)content->dentry_set_status);
    CPPUNIT_ASSERT_EQUAL((uint16_t)0x77, (uint16_t)file->meta->size);
    CPPUNIT_ASSERT(file->meta->flags & TSK_FS_META_FLAG_UNALLOC);

    tsk_fs_file_close(file);
}

/*
 * A deleted set whose check sum cannot be confirmed must be reported as an
 * unknown source, and none of its unverified length, name, or time stamps may
 * be reported as a recovery result.
 */
void
ExfatDentrySetTest::testDeletedSetWithBadChecksumIsUnconfirmed()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet set;

    image.buildBase();
    set.name = "unconfirmed.txt";
    set.is_directory = false;
    set.deleted = true;
    set.corrupt_checksum = true;
    set.first_cluster = 7;
    set.data_length = 0x4321;
    TSK_INUM_T primary_inum = image.addFileSet(set);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    /* The name must not appear at all: it cannot be confirmed. */
    CPPUNIT_ASSERT_EQUAL(-1, findName(open_fs.dir, "unconfirmed.txt"));

    TSK_FS_FILE * file = tsk_fs_file_open_meta(open_fs.fs, NULL, primary_inum);
    CPPUNIT_ASSERT(file != NULL);
    EXFATFS_META_CONTENT * content =
        (EXFATFS_META_CONTENT*)file->meta->content_ptr;
    CPPUNIT_ASSERT_EQUAL((int)EXFATFS_DENTRY_SET_STATUS_UNKNOWN_SOURCE,
        (int)content->dentry_set_status);

    /* No unverified length, name, or time may reach the recovery result. */
    CPPUNIT_ASSERT_EQUAL((TSK_OFF_T)0, file->meta->size);
    CPPUNIT_ASSERT_EQUAL((TSK_DADDR_T)0, content->first_cluster);
    CPPUNIT_ASSERT_EQUAL((time_t)0, file->meta->mtime);
    CPPUNIT_ASSERT_EQUAL((time_t)0, file->meta->crtime);
    CPPUNIT_ASSERT_EQUAL((time_t)0, file->meta->atime);
    CPPUNIT_ASSERT(file->meta->name2 != NULL);
    CPPUNIT_ASSERT_EQUAL(std::string(""), std::string(file->meta->name2->name));

    tsk_fs_file_close(file);
}

/*
 * A set that declares more name entries than it has must stop at the point
 * where the sequence breaks. The entries of the following file must not be
 * consumed into the damaged set, and the following file must still be
 * enumerated with its own verified name and status.
 */
void
ExfatDentrySetTest::testMissingNameEntryDoesNotStealNextFile()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet damaged;
    ExfatFileSet good;

    image.buildBase();

    damaged.name = "damaged_first_file.txt";
    damaged.is_directory = false;
    damaged.deleted = false;
    damaged.corrupt_checksum = false;
    damaged.omit_last_name_entry = true;
    damaged.first_cluster = 5;
    damaged.data_length = 0x10;
    TSK_INUM_T damaged_inum = image.addFileSet(damaged);

    good.name = "second.txt";
    good.is_directory = false;
    good.deleted = false;
    good.corrupt_checksum = false;
    good.first_cluster = 6;
    good.data_length = 0x20;
    TSK_INUM_T good_inum = image.addFileSet(good);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    /* The second file must be enumerated with its own complete name. */
    int good_idx = findName(open_fs.dir, "second.txt");
    CPPUNIT_ASSERT(good_idx >= 0);
    const TSK_FS_NAME * good_name = tsk_fs_dir_get_name(open_fs.dir, good_idx);
    CPPUNIT_ASSERT_EQUAL(good_inum, good_name->meta_addr);
    CPPUNIT_ASSERT_EQUAL(kStatusComplete, good_name->fs_specific_flags);

    /* The damaged set must not have absorbed the second file's entries: it
     * stops at the primary, stream, and the one name entry actually present. */
    TSK_FS_FILE * damaged_file =
        tsk_fs_file_open_meta(open_fs.fs, NULL, damaged_inum);
    CPPUNIT_ASSERT(damaged_file != NULL);
    EXFATFS_META_CONTENT * content =
        (EXFATFS_META_CONTENT*)damaged_file->meta->content_ptr;
    CPPUNIT_ASSERT(content->last_inum < good_inum);
    CPPUNIT_ASSERT_EQUAL((TSK_INUM_T)(damaged_inum + 2), content->last_inum);
    CPPUNIT_ASSERT_EQUAL((uint8_t)3, content->entries_count);
    CPPUNIT_ASSERT_EQUAL((uint8_t)2, content->actual_secondary_entry_count);
    CPPUNIT_ASSERT_EQUAL((int)EXFATFS_DENTRY_SET_STATUS_SEQUENCE_ERROR,
        (int)content->dentry_set_status);

    /* The name reported for the damaged set is only the characters that were
     * actually present before the break, never characters from the next
     * file's entries, and it carries the sequence error status. */
    int damaged_idx = findName(open_fs.dir, "damaged_first_f");
    CPPUNIT_ASSERT(damaged_idx >= 0);
    CPPUNIT_ASSERT_EQUAL(-1, findName(open_fs.dir, "damaged_first_file.txt"));
    const TSK_FS_NAME * damaged_name =
        tsk_fs_dir_get_name(open_fs.dir, damaged_idx);
    CPPUNIT_ASSERT_EQUAL(kStatusSequenceError, damaged_name->fs_specific_flags);

    tsk_fs_file_close(damaged_file);
}

/*
 * A set that is missing its stream extension entry cannot be tied to an
 * unverified length or name. The following complete set must keep its own
 * entries.
 */
void
ExfatDentrySetTest::testMissingStreamDoesNotStealNextFile()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet damaged;
    ExfatFileSet good;

    image.buildBase();

    damaged.name = "no_stream.txt";
    damaged.is_directory = false;
    damaged.deleted = false;
    damaged.corrupt_checksum = false;
    damaged.omit_stream = true;
    damaged.first_cluster = 5;
    damaged.data_length = 0x10;
    TSK_INUM_T damaged_inum = image.addFileSet(damaged);

    good.name = "after_no_stream.txt";
    good.is_directory = false;
    good.deleted = false;
    good.corrupt_checksum = false;
    good.first_cluster = 6;
    good.data_length = 0x20;
    TSK_INUM_T good_inum = image.addFileSet(good);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    int good_idx = findName(open_fs.dir, "after_no_stream.txt");
    CPPUNIT_ASSERT(good_idx >= 0);
    const TSK_FS_NAME * good_name = tsk_fs_dir_get_name(open_fs.dir, good_idx);
    CPPUNIT_ASSERT_EQUAL(good_inum, good_name->meta_addr);
    CPPUNIT_ASSERT_EQUAL(kStatusComplete, good_name->fs_specific_flags);

    TSK_FS_FILE * damaged_file =
        tsk_fs_file_open_meta(open_fs.fs, NULL, damaged_inum);
    CPPUNIT_ASSERT(damaged_file != NULL);
    EXFATFS_META_CONTENT * content =
        (EXFATFS_META_CONTENT*)damaged_file->meta->content_ptr;
    CPPUNIT_ASSERT_EQUAL((int)EXFATFS_DENTRY_SET_STATUS_SEQUENCE_ERROR,
        (int)content->dentry_set_status);
    CPPUNIT_ASSERT_EQUAL((TSK_OFF_T)0, damaged_file->meta->size);
    CPPUNIT_ASSERT(content->last_inum < good_inum);

    tsk_fs_file_close(damaged_file);
}

/*
 * An unrecognized entry inside a set must break the sequence. The entries
 * after the break must not be joined to the set, and the entry set that
 * follows must still verify as its own.
 */
void
ExfatDentrySetTest::testOutOfOrderEntriesDoNotJoinSet()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet damaged;
    ExfatFileSet good;

    image.buildBase();

    damaged.name = "gap_set.txt";
    damaged.is_directory = false;
    damaged.deleted = false;
    damaged.corrupt_checksum = false;
    damaged.inserted_gap = true;
    damaged.first_cluster = 5;
    damaged.data_length = 0x10;
    TSK_INUM_T damaged_inum = image.addFileSet(damaged);

    good.name = "after_gap.txt";
    good.is_directory = false;
    good.deleted = false;
    good.corrupt_checksum = false;
    good.first_cluster = 6;
    good.data_length = 0x20;
    TSK_INUM_T good_inum = image.addFileSet(good);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    int good_idx = findName(open_fs.dir, "after_gap.txt");
    CPPUNIT_ASSERT(good_idx >= 0);
    const TSK_FS_NAME * good_name = tsk_fs_dir_get_name(open_fs.dir, good_idx);
    CPPUNIT_ASSERT_EQUAL(good_inum, good_name->meta_addr);
    CPPUNIT_ASSERT_EQUAL(kStatusComplete, good_name->fs_specific_flags);

    TSK_FS_FILE * damaged_file =
        tsk_fs_file_open_meta(open_fs.fs, NULL, damaged_inum);
    CPPUNIT_ASSERT(damaged_file != NULL);
    EXFATFS_META_CONTENT * content =
        (EXFATFS_META_CONTENT*)damaged_file->meta->content_ptr;
    CPPUNIT_ASSERT_EQUAL((int)EXFATFS_DENTRY_SET_STATUS_SEQUENCE_ERROR,
        (int)content->dentry_set_status);
    CPPUNIT_ASSERT(content->last_inum < good_inum);

    tsk_fs_file_close(damaged_file);
}

/*
 * A set at the very end of the directory whose declared entries run past the
 * end of the directory data must be reported as a sequence error, and must
 * not read or invent entries beyond the directory.
 */
void
ExfatDentrySetTest::testTruncatedAtEndOfDirectory()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet set;

    image.buildBase();

    set.name = "end_of_dir.txt";
    set.is_directory = false;
    set.deleted = false;
    set.corrupt_checksum = false;
    set.omit_last_name_entry = true;
    set.first_cluster = 5;
    set.data_length = 0x10;
    TSK_INUM_T primary_inum = image.addFileSet(set);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    TSK_FS_FILE * file = tsk_fs_file_open_meta(open_fs.fs, NULL, primary_inum);
    CPPUNIT_ASSERT(file != NULL);
    EXFATFS_META_CONTENT * content =
        (EXFATFS_META_CONTENT*)file->meta->content_ptr;
    CPPUNIT_ASSERT_EQUAL((int)EXFATFS_DENTRY_SET_STATUS_SEQUENCE_ERROR,
        (int)content->dentry_set_status);
    CPPUNIT_ASSERT_EQUAL((TSK_OFF_T)0, file->meta->size);
    CPPUNIT_ASSERT_EQUAL((TSK_DADDR_T)0, content->first_cluster);

    tsk_fs_file_close(file);
}

/*
 * Ordinary, well formed files must keep enumerating exactly as before: their
 * names, their sizes, their locations, their allocated state, and their
 * special-file virtual entries must all still be present.
 */
void
ExfatDentrySetTest::testOrdinaryFilesStillEnumerate()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet first;
    ExfatFileSet second;

    image.buildBase();

    first.name = "alpha.txt";
    first.first_cluster = 5;
    first.data_length = 100;
    image.addFileSet(first);

    second.name = "a_much_longer_file_name_that_spans_two_name_entries.dat";
    second.first_cluster = 6;
    second.data_length = 4096;
    TSK_INUM_T second_inum = image.addFileSet(second);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    int idx = findName(open_fs.dir, "alpha.txt");
    CPPUNIT_ASSERT(idx >= 0);

    int long_idx = findName(open_fs.dir,
        "a_much_longer_file_name_that_spans_two_name_entries.dat");
    CPPUNIT_ASSERT(long_idx >= 0);

    const TSK_FS_NAME * long_name = tsk_fs_dir_get_name(open_fs.dir, long_idx);
    CPPUNIT_ASSERT_EQUAL(second_inum, long_name->meta_addr);
    CPPUNIT_ASSERT_EQUAL(kStatusComplete, long_name->fs_specific_flags);
    /* This 55-character name occupies four file name entries. */
    CPPUNIT_ASSERT_EQUAL((uint8_t)4, long_name->fs_specific_count);

    TSK_FS_FILE * file = tsk_fs_file_open_meta(open_fs.fs, NULL, second_inum);
    CPPUNIT_ASSERT(file != NULL);
    CPPUNIT_ASSERT_EQUAL((TSK_OFF_T)4096, file->meta->size);
    CPPUNIT_ASSERT(file->meta->flags & TSK_FS_META_FLAG_ALLOC);
    CPPUNIT_ASSERT_EQUAL(std::string(
        "a_much_longer_file_name_that_spans_two_name_entries.dat"),
        std::string(file->meta->name2->name));

    tsk_fs_file_close(file);

    /* The special file entries must still be enumerated in the root. */
    CPPUNIT_ASSERT(findName(open_fs.dir, "$ALLOC_BITMAP") >= 0);
    CPPUNIT_ASSERT(findName(open_fs.dir, "$MBR") >= 0);
    CPPUNIT_ASSERT(findName(open_fs.dir, "$FAT1") >= 0);
    CPPUNIT_ASSERT(findName(open_fs.dir, "$OrphanFiles") >= 0);
}

/*
 * A verified directory entry set must still be reported as a directory, and
 * the directory-walk of the root must still return it with the directory
 * name type.
 */
void
ExfatDentrySetTest::testDirectoryTypeAndRecursion()
{
    ExfatSyntheticImage image;
    OpenFs open_fs;
    ExfatFileSet dir;

    image.buildBase();
    dir.name = "folder";
    dir.is_directory = true;
    dir.first_cluster = 5;
    dir.data_length = 0;
    TSK_INUM_T dir_inum = image.addFileSet(dir);

    CPPUNIT_ASSERT(openExfat(image, open_fs));

    int idx = findName(open_fs.dir, "folder");
    CPPUNIT_ASSERT(idx >= 0);
    const TSK_FS_NAME * name = tsk_fs_dir_get_name(open_fs.dir, idx);
    CPPUNIT_ASSERT_EQUAL(TSK_FS_NAME_TYPE_DIR, name->type);
    CPPUNIT_ASSERT_EQUAL(kStatusComplete, name->fs_specific_flags);

    TSK_FS_FILE * file = tsk_fs_file_open_meta(open_fs.fs, NULL, dir_inum);
    CPPUNIT_ASSERT(file != NULL);
    CPPUNIT_ASSERT_EQUAL(TSK_FS_META_TYPE_DIR, file->meta->type);
    tsk_fs_file_close(file);
}

/*
 * The library's check sum calculation must agree with an independent
 * implementation of the exFAT algorithm, both for the bytes as stored and
 * with the in-use bits restored.
 */void
ExfatDentrySetTest::testChecksumHelperMatchesFixtures()
{
    std::vector<FATFS_DENTRY> entries;
    std::vector<ExfatDentry> fixture_entries;

    /* Two simple entries with recognizable content. */
    for (int e = 0; e < 3; ++e) {
        FATFS_DENTRY dentry;
        ExfatDentry fixture;

        memset(&dentry, 0, sizeof(dentry));
        memset(&fixture, 0, sizeof(fixture));

        for (int b = 0; b < 32; ++b) {
            uint8_t value = (uint8_t)(e * 37 + b * 11 + 1);
            dentry.data[b] = value;
            fixture.bytes[b] = value;
        }
        /* Make the first byte a plausible type byte. */
        dentry.data[0] = (uint8_t)((e == 0) ? 0x85 : 0xC0);
        fixture.bytes[0] = dentry.data[0];

        entries.push_back(dentry);
        fixture_entries.push_back(fixture);
    }

    CPPUNIT_ASSERT_EQUAL(
        ExfatSyntheticImage::calcCheckSum(fixture_entries, false),
        exfatfs_calc_dentry_set_checksum(entries.data(),
            (uint8_t)entries.size(), 0));
    CPPUNIT_ASSERT_EQUAL(
        ExfatSyntheticImage::calcCheckSum(fixture_entries, true),
        exfatfs_calc_dentry_set_checksum(entries.data(),
            (uint8_t)entries.size(), 1));
}

/*
 * The status of each case must have a distinct, non-empty description so the
 * evidence can be reported unambiguously.
 */
void
ExfatDentrySetTest::testStatusStringsAreDistinct()
{
    std::vector<std::string> seen;
    EXFATFS_DENTRY_SET_STATUS_ENUM statuses[] = {
        EXFATFS_DENTRY_SET_STATUS_NOT_APPLICABLE,
        EXFATFS_DENTRY_SET_STATUS_UNKNOWN_SOURCE,
        EXFATFS_DENTRY_SET_STATUS_COMPLETE,
        EXFATFS_DENTRY_SET_STATUS_CHECKSUM_MISMATCH,
        EXFATFS_DENTRY_SET_STATUS_SEQUENCE_ERROR,
        EXFATFS_DENTRY_SET_STATUS_DELETED_RECOVERABLE
    };

    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        const char * str = exfatfs_dentry_set_status_to_str(statuses[i]);
        CPPUNIT_ASSERT(str != NULL);
        CPPUNIT_ASSERT(strlen(str) > 0);

        for (size_t j = 0; j < seen.size(); ++j)
            CPPUNIT_ASSERT(seen[j] != std::string(str));
        seen.push_back(std::string(str));
    }
}

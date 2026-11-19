/*
 * exfat_synthetic_image.cpp
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "exfat_synthetic_image.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace {

/* File directory entry (primary), 32 bytes. */
constexpr size_t kFileEntryType = 0x00;
constexpr size_t kFileEntrySecondaryCount = 0x01;
constexpr size_t kFileEntryCheckSum = 0x02;
constexpr size_t kFileEntryAttrs = 0x04;
constexpr size_t kFileEntryCreateTime = 0x08;
constexpr size_t kFileEntryCreateDate = 0x0A;
constexpr size_t kFileEntryModifyTime = 0x0C;
constexpr size_t kFileEntryModifyDate = 0x0E;
constexpr size_t kFileEntryAccessTime = 0x10;
constexpr size_t kFileEntryAccessDate = 0x12;

/* Stream extension entry, 32 bytes. */
constexpr size_t kStreamEntryType = 0x00;
constexpr size_t kStreamEntryFlags = 0x01;
constexpr size_t kStreamEntryNameLength = 0x03;
constexpr size_t kStreamEntryNameHash = 0x04;
constexpr size_t kStreamEntryValidDataLength = 0x08;
constexpr size_t kStreamEntryFirstCluster = 0x14;
constexpr size_t kStreamEntryDataLength = 0x18;

/* Name entry, 32 bytes. */
constexpr size_t kNameEntryType = 0x00;
constexpr size_t kNameEntryChars = 0x02;

/* DOS date 2024-01-02 03:04:06 (valid, non-zero). */
constexpr uint16_t kTestDate = (uint16_t)(((2024 - 1980) << 9) | (1 << 5) | 2);
constexpr uint16_t kTestTime = (uint16_t)((3 << 11) | (4 << 5) | (6 / 2));

constexpr uint16_t kDosMagic = 0xaa55;

void putLe64At(uint8_t * a_buf, uint64_t a_value)
{
    for (int i = 0; i < 8; ++i)
        a_buf[i] = (uint8_t)((a_value >> (8 * i)) & 0xff);
}

void putLe32At(uint8_t * a_buf, uint32_t a_value)
{
    for (int i = 0; i < 4; ++i)
        a_buf[i] = (uint8_t)((a_value >> (8 * i)) & 0xff);
}

void putLe16At(uint8_t * a_buf, uint16_t a_value)
{
    a_buf[0] = (uint8_t)(a_value & 0xff);
    a_buf[1] = (uint8_t)((a_value >> 8) & 0xff);
}

}  // namespace

ExfatSyntheticImage::ExfatSyntheticImage()
    : bytes_(kExfatMaxImageBytes, 0), root_entries_(0), written_(false)
{
}

ExfatSyntheticImage::~ExfatSyntheticImage() {
    if (!path_.empty())
        unlink(path_.c_str());
}

void
ExfatSyntheticImage::putLe16(size_t a_off, uint16_t a_value)
{
    assert(a_off + 2 <= bytes_.size());
    bytes_[a_off] = (uint8_t)(a_value & 0xff);
    bytes_[a_off + 1] = (uint8_t)((a_value >> 8) & 0xff);
}

void
ExfatSyntheticImage::putLe32(size_t a_off, uint32_t a_value)
{
    assert(a_off + 4 <= bytes_.size());
    for (int i = 0; i < 4; ++i)
        bytes_[a_off + i] = (uint8_t)((a_value >> (8 * i)) & 0xff);
}

void
ExfatSyntheticImage::putLe64(size_t a_off, uint64_t a_value)
{
    assert(a_off + 8 <= bytes_.size());
    for (int i = 0; i < 8; ++i)
        bytes_[a_off + i] = (uint8_t)((a_value >> (8 * i)) & 0xff);
}

size_t
ExfatSyntheticImage::rootEntryOffset(size_t a_index) const
{
    return kExfatClusterHeapSector * kExfatSectorSize +
        (kExfatRootCluster - 2) * kExfatClusterSize +
        a_index * sizeof(ExfatDentry);
}

uint16_t
ExfatSyntheticImage::calcCheckSum(const std::vector<ExfatDentry> & a_entries,
    bool a_restore_in_use_bits)
{
    uint16_t check_sum = 0;

    for (size_t e = 0; e < a_entries.size(); ++e) {
        for (size_t b = 0; b < sizeof(ExfatDentry); ++b) {
            uint8_t byte_value = a_entries[e].bytes[b];

            /* The check sum field of the primary entry is not covered. */
            if ((e == 0) && ((b == kFileEntryCheckSum) ||
                (b == kFileEntryCheckSum + 1))) {
                continue;
            }
            if ((b == 0) && a_restore_in_use_bits) {
                byte_value |= 0x80;
            }

            check_sum = (uint16_t)(((check_sum << 15) | (check_sum >> 1)) +
                byte_value);
        }
    }

    return check_sum;
}

TSK_INUM_T
ExfatSyntheticImage::inumForRootIndex(size_t a_index) const
{
    /* The root directory occupies cluster 2, whose first sector is
     * kExfatClusterHeapSector. The TSK inode address of the first entry of
     * that sector is 3, and the formula advances by one per 32-byte entry. */
    TSK_DADDR_T sector = kExfatClusterHeapSector +
        (kExfatRootCluster - 2) * kExfatSectorsPerCluster;
    return (TSK_INUM_T)((sector - kExfatClusterHeapSector) *
        (kExfatSectorSize / sizeof(ExfatDentry)) + 3) + a_index;
}

void
ExfatSyntheticImage::buildBase()
{
    bytes_.assign(kExfatMaxImageBytes, 0);
    root_entries_ = 0;

    /* Volume boot record at sector 0. */
    bytes_[0] = 0xeb;
    bytes_[1] = 0x76;
    bytes_[2] = 0x90;
    memcpy(&bytes_[3], "EXFAT   ", 8);
    /* Partition offset (0x40) and volume length (0x48). */
    putLe64(0x40, 0);
    putLe64(0x48, (uint64_t)kExfatMaxImageSectors);
    /* FAT offset (0x50) and length (0x54). */
    putLe32(0x50, (uint32_t)kExfatFatSector);
    putLe32(0x54, 1);
    /* Cluster heap offset (0x58) and cluster count (0x5C). */
    putLe32(0x58, (uint32_t)kExfatClusterHeapSector);
    putLe32(0x5C, (uint32_t)kExfatClusterCount);
    /* Root directory cluster (0x60) and volume serial (0x64). */
    putLe32(0x60, kExfatRootCluster);
    putLe32(0x64, 0x12345678);
    /* File system revision (0x68). */
    bytes_[0x68] = 1;
    bytes_[0x69] = 0;
    /* Volume flags (0x6A). */
    putLe16(0x6A, 0);
    /* Bytes per sector log (0x6C), sectors per cluster log (0x6D). */
    bytes_[0x6C] = 9;
    bytes_[0x6D] = 0; /* log2(1) */
    /* Number of FATs (0x6E), drive select (0x6F). */
    bytes_[0x6E] = 1;
    bytes_[0x6F] = 0x80;
    /* Boot signature. */
    putLe16(0x1FE, kDosMagic);

    /* The backup boot sector at sector 12 is a copy of sector 0. */
    memcpy(&bytes_[12 * kExfatSectorSize], &bytes_[0], kExfatSectorSize);

    /* FAT: clusters 0 and 1 are reserved; the root directory, bitmap, and
     * upcase table each get an end-of-chain marker. */
    {
        size_t fat = kExfatFatSector * kExfatSectorSize;
        putLe32(fat + 0 * 4, 0xFFFFFFF8u);
        putLe32(fat + 1 * 4, 0xFFFFFFFFu);
        putLe32(fat + kExfatRootCluster * 4, 0xFFFFFFFFu);
        putLe32(fat + kExfatBitmapCluster * 4, 0xFFFFFFFFu);
        putLe32(fat + kExfatUpcaseCluster * 4, 0xFFFFFFFFu);
    }

    /* The allocation bitmap occupies cluster 3 and must be exactly
     * (cluster_count + 7) / 8 bytes long. Mark clusters 2, 3, and 4 as
     * allocated, and every cluster used by test files later. */
    {
        size_t bitmap_bytes = (kExfatClusterCount + 7) / 8;
        size_t bitmap_off = kExfatClusterHeapSector * kExfatSectorSize +
            (kExfatBitmapCluster - 2) * kExfatClusterSize;
        /* Bits are numbered from cluster 2. Set bits 0, 1, 2 (clusters 2..4). */
        bytes_[bitmap_off] = 0x07;

        /* Root directory: allocation bitmap entry first. */
        ExfatDentry dentry;
        memset(&dentry, 0, sizeof(dentry));
        dentry.bytes[0x00] = 0x81;    /* in-use alloc bitmap */
        dentry.bytes[0x01] = 0x00;    /* first bitmap */
        /* First cluster at 0x14, length at 0x18 (little endian). */
        dentry.bytes[0x14] = (uint8_t)(kExfatBitmapCluster & 0xff);
        for (int i = 0; i < 8; ++i) {
            dentry.bytes[0x18 + i] =
                (uint8_t)(((uint64_t)bitmap_bytes >> (8 * i)) & 0xff);
        }
        memcpy(&bytes_[rootEntryOffset(0)], dentry.bytes, sizeof(dentry));
        root_entries_ = 1;

        /* Upcase table entry. */
        memset(&dentry, 0, sizeof(dentry));
        dentry.bytes[0x00] = 0x82;    /* in-use upcase table */
        /* Table check sum at 0x04; a table of 0x1000 bytes in cluster 4. */
        dentry.bytes[0x14] = (uint8_t)(kExfatUpcaseCluster & 0xff);
        putLe64(rootEntryOffset(1) + 0x18, 0x1000);
        memcpy(&bytes_[rootEntryOffset(1)], dentry.bytes, sizeof(dentry));
        root_entries_ = 2;

        /* Volume label entry. An in-use label must have a non-zero length, so
         * emit a one character label. */
        memset(&dentry, 0, sizeof(dentry));
        dentry.bytes[0x00] = 0x83;
        dentry.bytes[0x01] = 1;
        dentry.bytes[0x02] = 'T';
        memcpy(&bytes_[rootEntryOffset(2)], dentry.bytes, sizeof(dentry));
        root_entries_ = 3;
    }

    written_ = false;
}

TSK_INUM_T
ExfatSyntheticImage::addFileSet(const ExfatFileSet & a_set)
{
    std::vector<ExfatDentry> entries;
    ExfatDentry primary;
    ExfatDentry stream;
    ExfatDentry name_dentry;
    std::vector<uint16_t> utf16_name;

    memset(&primary, 0, sizeof(primary));
    memset(&stream, 0, sizeof(stream));
    memset(&name_dentry, 0, sizeof(name_dentry));

    for (size_t i = 0; i < a_set.name.size() && i < 255; ++i)
        utf16_name.push_back((uint16_t)(uint8_t)a_set.name[i]);

    /* Work out how many name entries are needed for the name. */
    size_t name_entry_count = (utf16_name.size() + 14) / 15;
    if (name_entry_count == 0)
        name_entry_count = 1;
    size_t secondary_count = name_entry_count + 1; /* stream + names */

    /* Primary file entry. */
    primary.bytes[kFileEntryType] = (uint8_t)(a_set.deleted ? 0x05 : 0x85);
    primary.bytes[kFileEntrySecondaryCount] = (uint8_t)secondary_count;
    if (a_set.is_directory)
        primary.bytes[kFileEntryAttrs] = 0x10;
    /* Time stamps, so the entry passes the in-depth tests. */
    primary.bytes[kFileEntryCreateTime] = (uint8_t)(kTestTime & 0xff);
    primary.bytes[kFileEntryCreateTime + 1] = (uint8_t)(kTestTime >> 8);
    primary.bytes[kFileEntryCreateDate] = (uint8_t)(kTestDate & 0xff);
    primary.bytes[kFileEntryCreateDate + 1] = (uint8_t)(kTestDate >> 8);
    memcpy(&primary.bytes[kFileEntryModifyTime], &primary.bytes[kFileEntryCreateTime], 2);
    memcpy(&primary.bytes[kFileEntryModifyDate], &primary.bytes[kFileEntryCreateDate], 2);
    memcpy(&primary.bytes[kFileEntryAccessTime], &primary.bytes[kFileEntryCreateTime], 2);
    memcpy(&primary.bytes[kFileEntryAccessDate], &primary.bytes[kFileEntryCreateDate], 2);
    entries.push_back(primary);

    /* Stream extension entry. */
    stream.bytes[kStreamEntryType] = (uint8_t)(a_set.deleted ? 0x40 : 0xC0);
    stream.bytes[kStreamEntryFlags] = 0x03; /* allocation possible, no FAT chain */
    stream.bytes[kStreamEntryNameLength] = (uint8_t)utf16_name.size();
    putLe64At(&stream.bytes[kStreamEntryValidDataLength], a_set.data_length);
    putLe32At(&stream.bytes[kStreamEntryFirstCluster], a_set.first_cluster);
    putLe64At(&stream.bytes[kStreamEntryDataLength], a_set.data_length);

    if (!a_set.omit_stream) {
        entries.push_back(stream);
    }

    /* Name entries. */
    for (size_t e = 0; e < name_entry_count; ++e) {
        memset(&name_dentry, 0, sizeof(name_dentry));
        name_dentry.bytes[kNameEntryType] = (uint8_t)(a_set.deleted ? 0x41 : 0xC1);
        for (size_t c = 0; c < 15; ++c) {
            size_t idx = e * 15 + c;
            if (idx < utf16_name.size()) {
                name_dentry.bytes[kNameEntryChars + c * 2] =
                    (uint8_t)(utf16_name[idx] & 0xff);
                name_dentry.bytes[kNameEntryChars + c * 2 + 1] =
                    (uint8_t)(utf16_name[idx] >> 8);
            }
        }
        entries.push_back(name_dentry);
    }

    /* Optionally drop the last name entry, leaving the declared count
     * short of what is present. */
    std::vector<ExfatDentry> emitted;
    if (a_set.omit_last_name_entry && (entries.size() > 2)) {
        for (size_t i = 0; i + 1 < entries.size(); ++i)
            emitted.push_back(entries[i]);
    }
    else {
        emitted = entries;
    }

    /* If the test wants a gap, insert an unrecognized entry before the last
     * name entry so a broken set is followed by another set. */
    if (a_set.inserted_gap && (emitted.size() > 2)) {
        ExfatDentry filler;
        memset(&filler, 0, sizeof(filler));
        filler.bytes[0] = 0xAA; /* not a recognized exFAT entry type */
        emitted.insert(emitted.end() - 1, filler);
    }

    /* Compute and store the check sum, unless the test wants it broken. */
    {
        uint16_t check_sum = calcCheckSum(emitted, a_set.deleted);
        if (a_set.corrupt_checksum)
            check_sum = (uint16_t)(check_sum ^ 0x5a5a);
        putLe16At(&emitted[0].bytes[kFileEntryCheckSum], check_sum);
    }

    TSK_INUM_T primary_inum = inumForRootIndex(root_entries_);

    for (size_t i = 0; i < emitted.size(); ++i) {
        memcpy(&bytes_[rootEntryOffset(root_entries_)], emitted[i].bytes,
            sizeof(ExfatDentry));
        ++root_entries_;
    }

    /* Mark the file's data cluster allocated in the bitmap, if it has one. */
    if (a_set.first_cluster >= 2) {
        size_t bitmap_off = kExfatClusterHeapSector * kExfatSectorSize +
            (kExfatBitmapCluster - 2) * kExfatClusterSize;
        size_t bit = a_set.first_cluster - 2;
        bytes_[bitmap_off + bit / 8] |= (uint8_t)(1 << (bit % 8));
    }

    written_ = false;
    return primary_inum;
}

void
ExfatSyntheticImage::overwriteRootDentry(size_t a_index, const ExfatDentry & a_dentry)
{
    assert(a_index < root_entries_);
    memcpy(&bytes_[rootEntryOffset(a_index)], a_dentry.bytes, sizeof(ExfatDentry));
    written_ = false;
}

ExfatDentry
ExfatSyntheticImage::rootDentry(size_t a_index) const
{
    ExfatDentry dentry;

    assert(a_index < root_entries_);
    memcpy(dentry.bytes, &bytes_[rootEntryOffset(a_index)], sizeof(ExfatDentry));
    return dentry;
}

void
ExfatSyntheticImage::flush()
{
    if (written_)
        return;

    if (path_.empty()) {
        char tmpl[] = "/tmp/tsk_exfat_set_XXXXXX";
        int fd = mkstemp(tmpl);
        assert(fd >= 0);
        path_ = tmpl;
        close(fd);
    }

    FILE * f = fopen(path_.c_str(), "wb");
    assert(f != NULL);
    size_t n = fwrite(bytes_.data(), 1, bytes_.size(), f);
    assert(n == bytes_.size());
    fclose(f);
    written_ = true;
}

TSK_IMG_INFO *
ExfatSyntheticImage::openImage()
{
    flush();
    assert(bytes_.size() <= kExfatMaxImageBytes);
    return tsk_img_open_utf8_sing(path_.c_str(), TSK_IMG_TYPE_RAW,
        static_cast<unsigned int>(kExfatSectorSize));
}

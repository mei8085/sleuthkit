/*
 * vs_synthetic_image.cpp
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "vs_synthetic_image.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace {

void putLe16(std::vector<uint8_t> & b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v & 0xff);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
}

void putLe32(std::vector<uint8_t> & b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        b[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
}

void putLe64(std::vector<uint8_t> & b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        b[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
}

constexpr uint16_t kDosMagic = 0xaa55;
constexpr uint8_t kGptDosType = 0xee;
const uint64_t kGptSignature = 0x5452415020494645ULL;  /* "EFI PART" */
constexpr uint32_t kGptEntrySize = 128;
constexpr uint32_t kGptNumEntries = 4;
constexpr uint64_t kGptTableLba = 2;
constexpr uint64_t kGptPartAreaStart = 34;

/* Linux filesystem data GUID, used only to make entries non-empty. */
const uint8_t kLinuxTypeGuid[16] = {
    0x0d, 0xa0, 0x70, 0xfc, 0x2b, 0xb1, 0x49, 0x7d,
    0x80, 0x77, 0x50, 0x4e, 0xa8, 0x92, 0x19, 0x69
};

}  // namespace

SyntheticImage::SyntheticImage(): sectors_(0), written_(false) {
}

SyntheticImage::~SyntheticImage() {
    if (!path_.empty())
        unlink(path_.c_str());
}

void
SyntheticImage::checkSize(size_t totalSectors) const {
    assert(totalSectors > 0 && totalSectors <= kMaxImageSectors);
}

void
SyntheticImage::markRange(std::vector<uint8_t> & buf, size_t sectors,
    uint64_t start, uint64_t len, uint8_t marker)
{
    assert(start + len <= sectors);
    for (uint64_t s = start; s < start + len; ++s) {
        size_t base = static_cast<size_t>(s) * kSectorSize;
        for (size_t j = 0; j < kSectorSize; ++j)
            buf[base + j] = marker;
    }
}

void
SyntheticImage::buildDos(size_t totalSectors,
    const std::vector<RawEntry> & entries)
{
    checkSize(totalSectors);
    assert(entries.size() <= 4);

    sectors_ = totalSectors;
    bytes_.assign(totalSectors * kSectorSize, 0);

    /* Primary table lives in sector 0; entries start at offset 446. */
    const size_t kTableOff = 446;
    const size_t kEntrySize = 16;
    for (size_t i = 0; i < entries.size(); ++i) {
        const size_t e = kTableOff + i * kEntrySize;
        bytes_[e] = (i == 0) ? 0x80 : 0x00;  /* boot flag, harmless */
        bytes_[e + 4] = entries[i].ptype;
        putLe32(bytes_, e + 8, static_cast<uint32_t>(entries[i].start));
        putLe32(bytes_, e + 12, static_cast<uint32_t>(entries[i].len));
    }
    putLe16(bytes_, 510, kDosMagic);
}

void
SyntheticImage::buildGpt(size_t totalSectors,
    const std::vector<RawEntry> & entries)
{
    checkSize(totalSectors);
    assert(entries.size() <= kGptNumEntries);

    sectors_ = totalSectors;
    bytes_.assign(totalSectors * kSectorSize, 0);

    /* 1. Protective MBR in sector 0 (type 0xEE). */
    const size_t kTableOff = 446;
    bytes_[kTableOff + 4] = kGptDosType;
    putLe32(bytes_, kTableOff + 8, 1);
    putLe32(bytes_, kTableOff + 12,
        static_cast<uint32_t>(totalSectors - 1));
    putLe16(bytes_, 510, kDosMagic);

    /* 2. GPT header in sector 1 (gpt_head layout, little endian). */
    const size_t h = kSectorSize;
    putLe64(bytes_, h + 0, kGptSignature);
    putLe32(bytes_, h + 8, 0x00010000);             /* revision 1.0 */
    putLe32(bytes_, h + 12, 92);                   /* header size */
    /* header CRC (h+16) and current LBA (h+24) are not validated by TSK */
    putLe64(bytes_, h + 24, 1);                    /* head_lba */
    putLe64(bytes_, h + 32, totalSectors - 1);     /* backup header LBA */
    putLe64(bytes_, h + 40, kGptPartAreaStart);    /* partition area start */
    putLe64(bytes_, h + 48, totalSectors - 1);     /* partition area end */
    putLe64(bytes_, h + 72, kGptTableLba);         /* table start LBA */
    putLe32(bytes_, h + 80, kGptNumEntries);       /* number of entries */
    putLe32(bytes_, h + 84, kGptEntrySize);        /* entry size */

    /* 3. Partition entry array starting at LBA 2 (gpt_entry layout). */
    for (size_t i = 0; i < entries.size(); ++i) {
        const size_t e = kGptTableLba * kSectorSize + i * kGptEntrySize;
        memcpy(&bytes_[e], kLinuxTypeGuid, 16);
        /* unique partition GUID (e+16) stays zero: TSK does not require it */
        putLe64(bytes_, e + 32, entries[i].start);
        /* end_lba is inclusive.  A normal entry ends at start+len-1; a
         * zero-length entry is encoded with end_lba one sector before
         * start_lba so the parser sees end < start and rejects it. */
        const uint64_t endLba =
            (entries[i].len == 0)
            ? (entries[i].start == 0 ? 0 : entries[i].start - 1)
            : entries[i].start + entries[i].len - 1;
        putLe64(bytes_, e + 40, endLba);
        /* flags (e+48) and UTF-16 name (e+56..127) remain zero */
    }
}

void
SyntheticImage::overwriteSector(size_t lba,
    const std::vector<uint8_t> & sector)
{
    assert(sector.size() == kSectorSize);
    assert(lba < sectors_);
    memcpy(&bytes_[lba * kSectorSize], sector.data(), kSectorSize);
    written_ = false;  /* force a re-flush on next openImage() */
}

const uint8_t *
SyntheticImage::sectorData(size_t lba) const
{
    assert(lba < sectors_);
    return &bytes_[lba * kSectorSize];
}

void
SyntheticImage::flush()
{
    if (written_)
        return;

    if (path_.empty()) {
        char tmpl[] = "/tmp/tsk_vs_boundary_XXXXXX";
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
SyntheticImage::openImage()
{
    flush();
    assert(bytes_.size() <= kMaxImageBytes);
    return tsk_img_open_utf8_sing(path_.c_str(), TSK_IMG_TYPE_RAW,
        static_cast<unsigned int>(kSectorSize));
}

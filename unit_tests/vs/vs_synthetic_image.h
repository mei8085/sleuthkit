/*
 * vs_synthetic_image.h
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Builders for small, fully local, synthetic DOS/MBR and GPT disk images.
 * No external downloads, no network services and no fuzzing: every image
 * is assembled in memory from explicit byte layouts, written to a
 * temporary file and bounded by kMaxImageBytes (1 MiB).
 */

#ifndef VS_SYNTHETIC_IMAGE_H
#define VS_SYNTHETIC_IMAGE_H

#include <cstdint>
#include <string>
#include <vector>

#include <libtsk.h>

/* Hard upper bound for every synthesized image (1 MiB). */
constexpr size_t kSectorSize = 512;
constexpr size_t kMaxImageSectors = 2048;
constexpr size_t kMaxImageBytes = kMaxImageSectors * kSectorSize;

/* One raw partition table entry as authored by a test case. */
struct RawEntry {
    uint64_t start;         /* raw starting sector (LBA) */
    uint64_t len;           /* raw sector count (0 means zero-length) */
    unsigned char ptype;    /* DOS partition type (0x83 Linux etc.) */
};

/* One expected interval after parsing.  Intervals are half-open
 * [start, start+len) and the table is checked in sorted order. */
struct ExpectedPart {
    TSK_DADDR_T start;
    TSK_DADDR_T len;
    TSK_VS_PART_FLAG_ENUM flags;
};

/* Build a raw image buffer in memory and manage its on-disk temp file. */
class SyntheticImage {
  public:
    SyntheticImage();
    ~SyntheticImage();

    /* Total size of the image in sectors (always <= kMaxImageSectors). */
    size_t sectorCount() const {
        return sectors_;
    }

    const std::string & path() const {
        return path_;
    }

    /* In-memory image bytes (size is sectorCount() * kSectorSize). */
    const std::vector<uint8_t> & buffer() const {
        return bytes_;
    }
    std::vector<uint8_t> & mutableBuffer() {
        written_ = false;
        return bytes_;
    }

    /* Write the in-memory buffer to a unique temp file and open it through
     * the TSK raw image backend.  Returns the TSK_IMG_INFO handle, or NULL
     * (test asserts on it).  Caller closes via tsk_img_close(). */
    TSK_IMG_INFO * openImage();

    /* DOS/MBR layouts: four primary slots; unused slots are zero filled.
     * The magic 0xAA55 is always written. */
    void buildDos(size_t totalSectors, const std::vector<RawEntry> & entries);

    /* GPT layouts: protective MBR + header at LBA 1 + entry array at LBA 2.
     * malformed entries are written verbatim so the parser must reject
     * them; valid entries use end_lba = start + len - 1. */
    void buildGpt(size_t totalSectors, const std::vector<RawEntry> & entries);

    /* Overwrite one sector of an existing image (used to place a second,
     * valid layout at a non-zero offset inside the same input stream). */
    void overwriteSector(size_t lba, const std::vector<uint8_t> & sector);

    /* Read-only access to one in-memory sector, allowing another builder
     * to embed an already built layout without touching the filesystem. */
    const uint8_t * sectorData(size_t lba) const;

    /* Distinct marker byte stored in every sector of a given range so a
     * test can prove a logical volume maps back to the raw sectors. */
    static void markRange(std::vector<uint8_t> & buf, size_t sectors,
        uint64_t start, uint64_t len, uint8_t marker);

  private:
    void checkSize(size_t totalSectors) const;
    void flush();

    std::vector<uint8_t> bytes_;
    size_t sectors_;
    std::string path_;
    bool written_;
};

#endif

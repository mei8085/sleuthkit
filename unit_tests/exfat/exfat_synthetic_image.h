/*
 * exfat_synthetic_image.h
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Builders for small, fully local, synthetic exFAT images. No external
 * downloads, no network services and no fuzzing: every image is assembled in
 * memory from explicit byte layouts, written to a temporary file and bounded
 * by kMaxImageBytes (1 MiB). The builder is deliberately independent of the
 * library code under test so that the expected bytes are not derived from the
 * implementation being verified.
 */

#ifndef EXFAT_SYNTHETIC_IMAGE_H
#define EXFAT_SYNTHETIC_IMAGE_H

#include <cstdint>
#include <string>
#include <vector>

#include <libtsk.h>

constexpr size_t kExfatSectorSize = 512;
constexpr size_t kExfatSectorsPerCluster = 1;
constexpr size_t kExfatClusterSize = kExfatSectorSize * kExfatSectorsPerCluster;
constexpr size_t kExfatMaxImageSectors = 2048;
constexpr size_t kExfatMaxImageBytes = kExfatMaxImageSectors * kExfatSectorSize;

/* First sector of the cluster heap (cluster 2) in the images built below. */
constexpr size_t kExfatClusterHeapSector = 24;
/* First sector of the FAT. */
constexpr size_t kExfatFatSector = 1;
/* Number of clusters in the cluster heap. */
constexpr size_t kExfatClusterCount = 400;
/* Root directory lives in cluster 2. */
constexpr uint32_t kExfatRootCluster = 2;
/* Allocation bitmap lives in cluster 3. */
constexpr uint32_t kExfatBitmapCluster = 3;
/* Upcase table lives in cluster 4. */
constexpr uint32_t kExfatUpcaseCluster = 4;

/* One 32-byte directory entry of a synthetic image. */
struct ExfatDentry {
    uint8_t bytes[32];
};

/* Description of a file directory entry set to emit. All optional
 * distortions default to "none", so a fixture only sets what it exercises. */
struct ExfatFileSet {
    std::string name;            /* UTF-8 ASCII name; must fit in 255 chars */
    bool is_directory = false;   /* directory attribute */
    bool deleted = false;        /* clear in-use bit of every entry */
    bool corrupt_checksum = false; /* store a wrong check sum */
    bool omit_stream = false;    /* skip the stream entry entirely */
    bool omit_last_name_entry = false; /* emit one fewer name entry than declared */
    bool inserted_gap = false;   /* emit an unknown filler entry before the set completes */
    uint32_t first_cluster = 0;  /* file data cluster (0 for empty) */
    uint64_t data_length = 0;    /* file size in bytes */
};

/* Builds a minimal but valid exFAT file system and lets a test place
 * directory entry sets and small file data. */
class ExfatSyntheticImage {
  public:
    ExfatSyntheticImage();

    /* Build the base file system (VBR, FAT, bitmap, upcase table, root
     * directory with the required special entries). */
    void buildBase();

    /* Append a file directory entry set to the root directory. Returns the
     * inode address of the primary entry. The stream and name entries are
     * emitted in that order. */
    TSK_INUM_T addFileSet(const ExfatFileSet & a_set);

    /* Overwrite a single 32-byte directory entry of the root directory.
     * a_index is the root-directory entry index (0-based). */
    void overwriteRootDentry(size_t a_index, const ExfatDentry & a_dentry);

    /* Read back one 32-byte root-directory entry. */
    ExfatDentry rootDentry(size_t a_index) const;

    /* Number of root directory entry slots used so far. */
    size_t rootDentryCount() const {
        return root_entries_;
    }

    /* Convert a root-directory entry index into the inode address used by
     * TSK for it (the root directory is the first cluster). */
    TSK_INUM_T inumForRootIndex(size_t a_index) const;

    /* Write the image to a unique temp file and open it through the TSK raw
     * image backend. Caller closes via tsk_img_close(). */
    TSK_IMG_INFO * openImage();

    ~ExfatSyntheticImage();

    /* Compute the exFAT directory entry set check sum the way the
     * specification defines it: over every byte of every entry except the
     * two check sum bytes of the primary entry. When a_restore_in_use_bits is
     * set the in-use bit of each type byte is set before it is added. This is
     * an independent implementation used to build fixtures. */
    static uint16_t calcCheckSum(const std::vector<ExfatDentry> & a_entries,
        bool a_restore_in_use_bits);

  private:
    void putLe16(size_t a_off, uint16_t a_value);
    void putLe32(size_t a_off, uint32_t a_value);
    void putLe64(size_t a_off, uint64_t a_value);
    size_t rootEntryOffset(size_t a_index) const;
    void flush();

    std::vector<uint8_t> bytes_;
    size_t root_entries_;
    std::string path_;
    bool written_;
};

#endif

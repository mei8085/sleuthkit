/*
 * vs_partition_boundary_test.cpp
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Partition boundary tests.  The same locally synthesized images are fed
 * through two call chains:
 *
 *   1. the partition parsing / unallocated-space entry point
 *      tsk_vs_open() (C) and TskVsInfo::open() (C++), which invokes
 *      tsk_vs_part_unused() to synthesize the Unallocated intervals;
 *   2. the volume interval query entry points tsk_vs_part_get() and
 *      tsk_vs_part_walk() (C) and TskVsInfo::vsPartWalk() (C++).
 *
 * Every logical volume interval is checked against the raw sectors with
 * table-driven expectations for ordering, half-open bounds and sector
 * counts.  Malformed tables must fail with structured, locatable errors
 * before any truncated free region or out-of-bounds read is possible.
 */

#include "vs_partition_boundary_test.h"
#include "vs_synthetic_image.h"

#include <cstring>
#include <sstream>
#include <string>
#include <vector>

CPPUNIT_TEST_SUITE_REGISTRATION(VsPartitionBoundaryTest);

namespace {

/* Structured failure categories asserted by the malformed-table tests. */
enum FailureCategory {
    FC_NONE = 0,
    FC_ZERO_LENGTH,
    FC_BEYOND_END,
    FC_OVERLAP,
    FC_OTHER
};

struct CollectedPart {
    TSK_DADDR_T start;
    TSK_DADDR_T len;
    TSK_VS_PART_FLAG_ENUM flags;
    int8_t slot;

    bool operator==(const CollectedPart & rhs) const {
        return start == rhs.start && len == rhs.len &&
            flags == rhs.flags && slot == rhs.slot;
    }
};

/* Walk callback for the C entry point: tsk_vs_part_walk(). */
TSK_WALK_RET_ENUM
collectWalkCb(TSK_VS_INFO *, const TSK_VS_PART_INFO * part, void *ptr)
{
    std::vector<CollectedPart> *out =
        static_cast<std::vector<CollectedPart> *>(ptr);
    out->push_back({ part->start, part->len, part->flags,
        part->slot_num });
    return TSK_WALK_CONT;
}

/* Walk callback for the C++ entry point: TskVsInfo::vsPartWalk(). */
TSK_WALK_RET_ENUM
collectWalkCppCb(TskVsInfo *, const TskVsPartInfo * part, void *ptr)
{
    std::vector<CollectedPart> *out =
        static_cast<std::vector<CollectedPart> *>(ptr);
    out->push_back({ part->getStart(), part->getLen(), part->getFlags(),
        part->getSlotNum() });
    return TSK_WALK_CONT;
}

/* Collect every interval through the C walk entry point. */
std::vector<CollectedPart>
collectViaCWalk(TSK_VS_INFO * vs)
{
    std::vector<CollectedPart> out;
    uint8_t rc = tsk_vs_part_walk(vs, 0, vs->part_count - 1,
        (TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC |
            TSK_VS_PART_FLAG_UNALLOC | TSK_VS_PART_FLAG_META),
        collectWalkCb, &out);
    CPPUNIT_ASSERT_EQUAL(0, (int) rc);
    return out;
}

/* Collect every interval through the C++ walk entry point. */
std::vector<CollectedPart>
collectViaCppWalk(TskVsInfo & vs)
{
    std::vector<CollectedPart> out;
    uint8_t rc = vs.vsPartWalk(0, vs.getPartCount() - 1,
        (TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC |
            TSK_VS_PART_FLAG_UNALLOC | TSK_VS_PART_FLAG_META),
        collectWalkCppCb, &out);
    CPPUNIT_ASSERT_EQUAL(0, (int) rc);
    return out;
}

/* Collect every interval through the random-access get() entry point.
 * This exercises the second query entry independently of the walk. */
std::vector<CollectedPart>
collectViaGet(TSK_VS_INFO * vs)
{
    std::vector<CollectedPart> out;
    for (TSK_PNUM_T i = 0; i < vs->part_count; ++i) {
        const TSK_VS_PART_INFO *p = tsk_vs_part_get(vs, i);
        CPPUNIT_ASSERT(p != NULL);
        out.push_back({ p->start, p->len, p->flags, p->slot_num });
    }
    return out;
}

/* Table-driven check: exact interval sequence, sorted order, half-open
 * bounds, and per-entry sector counts. */
void
assertExpectedParts(const char *tag,
    const std::vector<CollectedPart> & got,
    const std::vector<ExpectedPart> & want)
{
    std::ostringstream oss;
    oss << tag << ": interval count";
    CPPUNIT_ASSERT_EQUAL_MESSAGE(oss.str(), want.size(), got.size());

    TSK_DADDR_T prevStart = 0;
    for (size_t i = 0; i < want.size(); ++i) {
        std::ostringstream m;
        m << tag << " [" << i << "]";
        CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(), want[i].start, got[i].start);
        CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(), want[i].len, got[i].len);
        CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(),
            (int) want[i].flags, (int) got[i].flags);

        /* Sorted linked list: start sectors are non-decreasing.  Equal
         * starts occur in legacy TSK output where a leading Unallocated
         * region shares the table sector with a META entry. */
        CPPUNIT_ASSERT_MESSAGE(m.str(), got[i].start >= prevStart);
        /* Half-open interval invariant: the end is start + len. */
        CPPUNIT_ASSERT_MESSAGE(m.str(),
            got[i].start + got[i].len > got[i].start || got[i].len == 0);
        prevStart = got[i].start;
    }
}

/* Prove every logical sector of an ALLOC interval maps back to the same
 * raw sector of the image, through both read entry points.  markers maps
 * each collected interval index to the byte its raw sectors were filled
 * with (0 means "do not check the fill byte"). */
void
assertSectorCorrespondence(const char *tag, TSK_IMG_INFO * img,
    TSK_VS_INFO * vs, const std::vector<CollectedPart> & parts,
    const std::vector<uint8_t> & markers)
{
    std::vector<char> raw(kSectorSize);
    std::vector<char> viaPart(kSectorSize);
    std::vector<char> viaBlock(kSectorSize);

    for (size_t pi = 0; pi < parts.size(); ++pi) {
        if (!(parts[pi].flags & TSK_VS_PART_FLAG_ALLOC))
            continue;

        const TSK_VS_PART_INFO *p =
            tsk_vs_part_get(vs, (TSK_PNUM_T) pi);
        CPPUNIT_ASSERT(p != NULL);

        for (TSK_DADDR_T s = 0; s < parts[pi].len; ++s) {
            /* start is relative to the volume system; the absolute image
             * LBA adds the VS byte offset expressed in sectors. */
            TSK_DADDR_T vsLba = parts[pi].start + s;
            TSK_DADDR_T imgLba =
                vs->offset / vs->block_size + vsLba;

            ssize_t r1 = tsk_img_read(img,
                imgLba * kSectorSize, raw.data(), kSectorSize);
            CPPUNIT_ASSERT_EQUAL_MESSAGE(tag, (ssize_t) kSectorSize, r1);

            /* Entry point A: tsk_vs_part_read_block() takes a partition-
             * relative sector and maps it through start + VS offset. */
            ssize_t r2 = tsk_vs_part_read_block(p, s,
                viaPart.data(), kSectorSize);
            CPPUNIT_ASSERT_EQUAL_MESSAGE(tag, (ssize_t) kSectorSize, r2);

            /* Entry point B: tsk_vs_read_block() takes a sector relative
             * to the volume system and adds the VS offset internally. */
            ssize_t r3 = tsk_vs_read_block(vs, vsLba,
                viaBlock.data(), kSectorSize);
            CPPUNIT_ASSERT_EQUAL_MESSAGE(tag, (ssize_t) kSectorSize, r3);

            CPPUNIT_ASSERT_EQUAL_MESSAGE(tag, 0,
                memcmp(raw.data(), viaPart.data(), kSectorSize));
            CPPUNIT_ASSERT_EQUAL_MESSAGE(tag, 0,
                memcmp(raw.data(), viaBlock.data(), kSectorSize));
            if (markers[pi] != 0)
                CPPUNIT_ASSERT_EQUAL_MESSAGE(tag,
                    (char) markers[pi], raw[0]);
        }
    }
}

/* Classify the structured TSK error left by a failed parse.  The message
 * anchors (table/slot, start/end sectors, category keyword) are checked
 * separately by the caller. */
FailureCategory
classifyError(uint32_t errnum, const std::string & msg)
{
    if (errnum == 0)
        return FC_NONE;
    if (errnum != TSK_ERR_VS_BLK_NUM)
        return FC_OTHER;
    if (msg.find("zero-length") != std::string::npos)
        return FC_ZERO_LENGTH;
    if (msg.find("beyond end") != std::string::npos
        || msg.find("too large for image") != std::string::npos)
        return FC_BEYOND_END;
    if (msg.find("overlap") != std::string::npos)
        return FC_OVERLAP;
    return FC_OTHER;
}

struct Rejection {
    bool failed;
    uint32_t errnum;
    FailureCategory category;
    std::string message;
};

Rejection
parseViaC(TSK_IMG_INFO * img, TSK_DADDR_T offset, TSK_VS_TYPE_ENUM type)
{
    tsk_error_reset();
    TSK_VS_INFO *vs = tsk_vs_open(img, offset, type);
    Rejection r;
    r.failed = (vs == NULL);
    r.errnum = tsk_error_get_errno();
    r.message = tsk_error_get_errstr() ? tsk_error_get_errstr() : "";
    r.category = classifyError(r.errnum, r.message);
    if (vs)
        tsk_vs_close(vs);
    return r;
}

/*
 * C++ open entry.  The TskImgInfo wrapper is provided by the caller and
 * must outlive this call: upstream's ~TskImgInfo() unconditionally closes
 * the underlying handle, so a stack-local wrapper would invalidate img
 * on scope exit.  Nothing here owns or closes the TSK_IMG_INFO.
 */
Rejection
parseViaCpp(TskImgInfo * imgWrap, TSK_DADDR_T offset,
    TSK_VS_TYPE_ENUM type)
{
    tsk_error_reset();
    TskVsInfo vs;
    uint8_t rc = vs.open(imgWrap, offset, type);
    Rejection r;
    r.failed = (rc != 0);
    r.errnum = tsk_error_get_errno();
    r.message = tsk_error_get_errstr() ? tsk_error_get_errstr() : "";
    r.category = classifyError(r.errnum, r.message);
    return r;
}

/* Assert the structured error anchors: failure category plus, when the
 * rejection came from the new tsk_vs_part_entry_validate() path, the
 * partition slot and raw start/end sectors.  When detailedAnchors is
 * false the rejection was produced by an upstream parser check (which
 * carries the same BLK_NUM category but no slot/end anchors); the
 * raw values are still verified against the image independently. */
void
assertStructuredError(const char *tag, const Rejection & r,
    FailureCategory wantCategory, int wantSlot, uint64_t wantStart,
    uint64_t wantEnd, bool detailedAnchors = true)
{
    std::ostringstream m;
    m << tag << ": " << r.message;
    CPPUNIT_ASSERT_MESSAGE(m.str(), r.failed);
    CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(),
        (uint32_t) TSK_ERR_VS_BLK_NUM, r.errnum);
    CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(),
        (int) wantCategory, (int) r.category);

    if (!detailedAnchors)
        return;

    /* Slot anchor: "slot %d" */
    std::ostringstream slotPat;
    slotPat << "slot " << wantSlot;
    CPPUNIT_ASSERT_MESSAGE(m.str(),
        r.message.find(slotPat.str()) != std::string::npos);

    /* Raw start/end sector anchors. */
    std::ostringstream startPat;
    startPat << "start " << wantStart;
    CPPUNIT_ASSERT_MESSAGE(m.str(),
        r.message.find(startPat.str()) != std::string::npos);
    std::ostringstream endPat;
    endPat << "end " << wantEnd;
    CPPUNIT_ASSERT_MESSAGE(m.str(),
        r.message.find(endPat.str()) != std::string::npos);
}

}  // namespace

void
VsPartitionBoundaryTest::setUp()
{
    tsk_error_reset();
}

void
VsPartitionBoundaryTest::tearDown()
{
    tsk_error_reset();
}

/*
 * Valid GPT layout: protective MBR, header and entry-array META intervals
 * plus two ALLOC volumes with Unallocated gaps between them.  The first
 * allocation is the minimum representable range (one sector); the second
 * spans the largest range the bounded image can represent.
 */
void
VsPartitionBoundaryTest::testValidGptLayoutIntervals()
{
    const size_t kSectors = 256;
    SyntheticImage img;
    img.buildGpt(kSectors, {
        { 34, 1, 0x00 },                       /* minimum: 1 sector */
        { 40, kSectors - 41, 0x00 }            /* maximum: to LBA 254 */
    });
    /* Distinct markers on the raw sectors backing each allocation so the
     * logical-to-raw correspondence can be proven sector by sector. */
    SyntheticImage::markRange(img.mutableBuffer(), kSectors, 34, 1, 0xA1);
    SyntheticImage::markRange(img.mutableBuffer(), kSectors, 40,
        kSectors - 41, 0xB2);

    TSK_IMG_INFO *ti = img.openImage();
    CPPUNIT_ASSERT(ti != NULL);

    tsk_error_reset();
    TSK_VS_INFO *vs = tsk_vs_open(ti, 0, TSK_VS_TYPE_GPT);
    CPPUNIT_ASSERT_MESSAGE(tsk_error_get_errstr() ?
        tsk_error_get_errstr() : "gpt open", vs != NULL);

    const std::vector<CollectedPart> walked = collectViaCWalk(vs);
    const std::vector<CollectedPart> got = collectViaGet(vs);
    CPPUNIT_ASSERT(walked == got);

    /* Expected sorted sequence (half-open intervals, sectors).  Note the
     * leading Unallocated region [0,34): tsk_vs_part_unused() skips the
     * META entries when locating the previous ALLOC end, so its first gap
     * starts at sector 0 and overlaps the metadata entries (legacy TSK
     * behavior, kept unchanged):
     *  [0,1)   META Safety Table
     *  [0,34)  Unallocated leading gap (34 sectors, overlaps META)
     *  [1,2)   META GPT Header
     *  [2,3)   META Partition Table (1 sector: 4 x 128 B = 512 B)
     *  [34,35) ALLOC p0 (minimum range, 1 sector)
     *  [35,40) Unallocated gap (5 sectors)
     *  [40,255) ALLOC p1 (maximum range, 215 sectors)
     *  [255,256) Unallocated tail (1 sector, backup GPT area) */
    const std::vector<ExpectedPart> want = {
        { 0, 1, TSK_VS_PART_FLAG_META },
        { 0, 34, TSK_VS_PART_FLAG_UNALLOC },
        { 1, 1, TSK_VS_PART_FLAG_META },
        { 2, 1, TSK_VS_PART_FLAG_META },
        { 34, 1, TSK_VS_PART_FLAG_ALLOC },
        { 35, 5, TSK_VS_PART_FLAG_UNALLOC },
        { 40, 215, TSK_VS_PART_FLAG_ALLOC },
        { 255, 1, TSK_VS_PART_FLAG_UNALLOC },
    };
    assertExpectedParts("gpt-valid", got, want);

    /* The non-META intervals cover every sector of the image: the leading
     * [0,34) gap (which overlaps the META entries) plus the two ALLOC
     * volumes, the inter-volume gap and the backup-area tail. */
    TSK_DADDR_T covered = 0;
    for (const auto & p : got)
        if (!(p.flags & TSK_VS_PART_FLAG_META))
            covered += p.len;
    CPPUNIT_ASSERT_EQUAL((TSK_DADDR_T) kSectors, covered);

    /* Every logical sector maps back to the same raw sector via both read
     * entry points (tsk_vs_part_read_block and tsk_vs_read_block).
     * ALLOC volumes are interval indices 4 and 6. */
    const std::vector<uint8_t> gptMarkers =
    { 0, 0, 0, 0, 0xA1, 0, 0xB2, 0 };
    assertSectorCorrespondence("gpt-valid", ti, vs, got, gptMarkers);

    tsk_vs_close(vs);
    tsk_img_close(ti);
}

/*
 * Valid DOS/MBR layout: primary-table META sector, a minimum one-sector
 * primary partition, a gap, a maximum-range primary partition, and the
 * trailing Unallocated region.
 */
void
VsPartitionBoundaryTest::testValidDosLayoutIntervals()
{
    const size_t kSectors = 128;
    SyntheticImage img;
    img.buildDos(kSectors, {
        { 2, 1, 0x83 },                        /* minimum: 1 sector */
        { 8, kSectors - 9, 0x83 }              /* maximum: LBA 8..126 */
    });
    SyntheticImage::markRange(img.mutableBuffer(), kSectors, 2, 1, 0xC3);
    SyntheticImage::markRange(img.mutableBuffer(), kSectors, 8,
        kSectors - 9, 0xD4);

    TSK_IMG_INFO *ti = img.openImage();
    CPPUNIT_ASSERT(ti != NULL);

    tsk_error_reset();
    TSK_VS_INFO *vs = tsk_vs_open(ti, 0, TSK_VS_TYPE_DOS);
    CPPUNIT_ASSERT_MESSAGE(tsk_error_get_errstr() ?
        tsk_error_get_errstr() : "dos open", vs != NULL);

    const std::vector<CollectedPart> walked = collectViaCWalk(vs);
    const std::vector<CollectedPart> got = collectViaGet(vs);
    CPPUNIT_ASSERT(walked == got);

    /* Expected sorted sequence (half-open, sectors).  As with GPT, the
     * first Unallocated region starts at sector 0 (META entries are
     * skipped by tsk_vs_part_unused()), so it overlaps the table sector:
     *  [0,1)   META Primary Table
     *  [0,2)   Unallocated leading gap (2 sectors, overlaps META)
     *  [2,3)   ALLOC p0 minimum (1)
     *  [3,8)   Unallocated gap (5)
     *  [8,127) ALLOC p1 maximum (119)
     *  [127,128) Unallocated tail (1) */
    const std::vector<ExpectedPart> want = {
        { 0, 1, TSK_VS_PART_FLAG_META },
        { 0, 2, TSK_VS_PART_FLAG_UNALLOC },
        { 2, 1, TSK_VS_PART_FLAG_ALLOC },
        { 3, 5, TSK_VS_PART_FLAG_UNALLOC },
        { 8, 119, TSK_VS_PART_FLAG_ALLOC },
        { 127, 1, TSK_VS_PART_FLAG_UNALLOC },
    };
    assertExpectedParts("dos-valid", got, want);

    /* Non-META intervals cover the image: the leading [0,2) gap overlaps
     * the table sector, and the two ALLOC volumes plus the gaps account
     * for every remaining sector. */
    TSK_DADDR_T covered = 0;
    for (const auto & p : got)
        if (!(p.flags & TSK_VS_PART_FLAG_META))
            covered += p.len;
    CPPUNIT_ASSERT_EQUAL((TSK_DADDR_T) kSectors, covered);

    /* ALLOC volumes are interval indices 2 and 4. */
    const std::vector<uint8_t> dosMarkers = { 0, 0, 0xC3, 0, 0xD4, 0 };
    assertSectorCorrespondence("dos-valid", ti, vs, got, dosMarkers);

    tsk_vs_close(vs);
    tsk_img_close(ti);
}

/* Overlapping partitions must be rejected on both GPT and MBR. */
void
VsPartitionBoundaryTest::testMalformedOverlapRejected()
{
    {
        SyntheticImage img;
        img.buildGpt(256, { { 40, 20, 0x00 }, { 50, 10, 0x00 } });
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_GPT);
        assertStructuredError("gpt-overlap", c, FC_OVERLAP, 1, 50, 60);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_GPT);
        assertStructuredError("gpt-overlap-cpp", cpp, FC_OVERLAP, 1, 50, 60);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
    {
        SyntheticImage img;
        img.buildDos(128, { { 10, 20, 0x83 }, { 20, 10, 0x83 },
            { 0, 0, 0 }, { 0, 0, 0 } });
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-overlap", c, FC_OVERLAP, 1, 20, 30);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-overlap-cpp", cpp, FC_OVERLAP, 1, 20, 30);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
}

/* Partitions extending past the end of the device must be rejected. */
void
VsPartitionBoundaryTest::testMalformedBeyondEndRejected()
{
    {
        SyntheticImage img;
        img.buildGpt(128, { { 120, 20, 0x00 } });   /* ends at LBA 139 */
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_GPT);
        assertStructuredError("gpt-beyond", c, FC_BEYOND_END, 0, 120, 140);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_GPT);
        assertStructuredError("gpt-beyond-cpp", cpp, FC_BEYOND_END, 0,
            120, 140);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
    {
        SyntheticImage img;
        /* Start inside the image but with a length that runs past the
         * device: the native start check passes and the new boundary
         * validator rejects the half-open end (start+len > max sector). */
        img.buildDos(128, { { 120, 20, 0x83 }, { 0, 0, 0 },
            { 0, 0, 0 }, { 0, 0, 0 } });
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-beyond", c, FC_BEYOND_END, 0, 120, 140);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-beyond-cpp", cpp, FC_BEYOND_END, 0,
            120, 140);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
    {
        SyntheticImage img;
        /* Start itself beyond the device: rejected by the upstream native
         * primary-table check (same BLK_NUM / beyond-end category, native
         * message), still before any truncated free region is created. */
        img.buildDos(128, { { 200, 5, 0x83 }, { 0, 0, 0 },
            { 0, 0, 0 }, { 0, 0, 0 } });
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-beyond-native", c, FC_BEYOND_END,
            0, 200, 205, false);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-beyond-native-cpp", cpp, FC_BEYOND_END,
            0, 200, 205, false);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
}

/* Zero-length entries must be rejected rather than silently skipped. */
void
VsPartitionBoundaryTest::testMalformedZeroLengthRejected()
{
    {
        SyntheticImage img;
        img.buildGpt(128, { { 40, 0, 0x00 }, { 60, 10, 0x00 } });
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_GPT);
        /* GPT encodes zero length as end_lba = start_lba - 1, so the raw
         * inclusive end anchor is 39; the validator still reports a
         * zero-length category rather than a truncated interval. */
        assertStructuredError("gpt-zero", c, FC_ZERO_LENGTH, 0, 40, 39);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_GPT);
        assertStructuredError("gpt-zero-cpp", cpp, FC_ZERO_LENGTH, 0,
            40, 39);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
    {
        SyntheticImage img;
        /* Typed DOS entry with a zero sector count. */
        img.buildDos(128, { { 40, 0, 0x83 }, { 0, 0, 0 },
            { 0, 0, 0 }, { 0, 0, 0 } });
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-zero", c, FC_ZERO_LENGTH, 0, 40, 40);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-zero-cpp", cpp, FC_ZERO_LENGTH, 0,
            40, 40);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
}

/* A non-corresponding start: a partition whose starting sector does not
 * correspond to a distinct, non-overlapping volume interval.  Both tables
 * must reject it with a locatable overlap error before any Unallocated
 * gap is derived from the inconsistent layout. */
void
VsPartitionBoundaryTest::testMalformedMismatchedStartRejected()
{
    {
        SyntheticImage img;
        /* GPT: entry 0 claims [34,54).  Entry 1 has a start that does not
         * correspond to a distinct interval because it begins inside
         * entry 0's range ([40,50)); the half-open intervals overlap. */
        img.buildGpt(256, { { 34, 20, 0x00 }, { 40, 10, 0x00 } });
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_GPT);
        assertStructuredError("gpt-mismatch", c, FC_OVERLAP, 1, 40, 50);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_GPT);
        assertStructuredError("gpt-mismatch-cpp", cpp, FC_OVERLAP, 1,
            40, 50);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
    {
        SyntheticImage img;
        /* DOS: entry 0 claims [0,10); entry 1 starts inside it at sector 5
         * ([5,15)), so its start does not correspond to a distinct volume. */
        img.buildDos(128, { { 0, 10, 0x83 }, { 5, 10, 0x83 },
            { 0, 0, 0 }, { 0, 0, 0 } });
        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);

        Rejection c = parseViaC(ti, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-mismatch", c, FC_OVERLAP, 1, 5, 15);
        Rejection cpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_DOS);
        assertStructuredError("dos-mismatch-cpp", cpp, FC_OVERLAP, 1,
            5, 15);

        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
}

/*
 * A failed parse of one region of an input stream must not pollute the
 * TSK error state, image read cursor or any cached interval when a valid
 * layout at another offset in the SAME stream is parsed immediately
 * afterwards.  Both entry points must return the identical rejection
 * category and the identical interval set on the reuse.
 */
void
VsPartitionBoundaryTest::testFailureDoesNotPolluteReuse()
{
    /* One image file (single input stream): a malformed MBR at byte
     * offset 0 and a separate, valid MBR layout beginning at sector 128.
     * The whole file is bounded by kMaxImageBytes (1 MiB cap). */
    const size_t kValidBase = 128;
    const size_t kValidSectors = 64;

    SyntheticImage img;
    /* Start inside the image but a half-open end past the device, so the
     * boundary validator rejects it deterministically (256 sectors). */
    img.buildDos(256, { { 240, 40, 0x83 }, { 0, 0, 0 },
        { 0, 0, 0 }, { 0, 0, 0 } });

    SyntheticImage valid;
    valid.buildDos(kValidSectors, { { 2, 10, 0x83 }, { 0, 0, 0 },
        { 0, 0, 0 }, { 0, 0, 0 } });
    SyntheticImage::markRange(valid.mutableBuffer(), kValidSectors, 2, 10,
        0xE5);

    /* Embed the valid layout's sectors into the same stream in memory,
     * without a second file or any network access. */
    for (size_t s = 0; s < kValidSectors; ++s) {
        std::vector<uint8_t> one(valid.sectorData(s),
            valid.sectorData(s) + kSectorSize);
        img.overwriteSector(kValidBase + s, one);
    }

    TSK_IMG_INFO *ti = img.openImage();
    CPPUNIT_ASSERT(ti != NULL);
    TskImgInfo imgWrap(ti);

    /* 1. Malformed parse at offset 0 must fail cleanly (both open
     * entry points), before any truncated Unallocated region exists. */
    Rejection badC = parseViaC(ti, 0, TSK_VS_TYPE_DOS);
    CPPUNIT_ASSERT(badC.failed);
    CPPUNIT_ASSERT_EQUAL((int) FC_BEYOND_END, (int) badC.category);
    Rejection badCpp = parseViaCpp(&imgWrap, 0, TSK_VS_TYPE_DOS);
    CPPUNIT_ASSERT(badCpp.failed);
    CPPUNIT_ASSERT_EQUAL(badC.category, badCpp.category);

    /* The failure leaves no sticky TSK error and the image handle is
     * still readable: the cursor/cache was not poisoned. */
    tsk_error_reset();
    CPPUNIT_ASSERT_EQUAL(0u, tsk_error_get_errno());
    {
        char probe[kSectorSize];
        ssize_t rn = tsk_img_read(ti, kValidBase * kSectorSize, probe,
            kSectorSize);
        CPPUNIT_ASSERT_EQUAL((ssize_t) kSectorSize, rn);
        uint16_t magic = static_cast<uint16_t>(probe[510]) |
            (static_cast<uint16_t>(probe[511]) << 8);
        CPPUNIT_ASSERT_EQUAL((uint16_t) 0xaa55, magic);
    }

    /* 2. Reuse the same stream: parse the valid layout at sector 128,
     * once through the C entry and once through the C++ entry. */
    tsk_error_reset();
    TSK_VS_INFO *vs = tsk_vs_open(ti, kValidBase * kSectorSize,
        TSK_VS_TYPE_DOS);
    CPPUNIT_ASSERT_MESSAGE(tsk_error_get_errstr() ?
        tsk_error_get_errstr() : "reuse open", vs != NULL);

    const std::vector<CollectedPart> cParts = collectViaCWalk(vs);
    TskVsInfo cppVs;
    CPPUNIT_ASSERT_EQUAL(0, (int) cppVs.open(&imgWrap,
        kValidBase * kSectorSize, TSK_VS_TYPE_DOS));
    const std::vector<CollectedPart> cppParts = collectViaCppWalk(cppVs);

    /* Both entry points return the identical cached interval sequence. */
    CPPUNIT_ASSERT_EQUAL(cParts.size(), cppParts.size());
    for (size_t i = 0; i < cParts.size(); ++i) {
        CPPUNIT_ASSERT_EQUAL(cParts[i].start, cppParts[i].start);
        CPPUNIT_ASSERT_EQUAL(cParts[i].len, cppParts[i].len);
        CPPUNIT_ASSERT_EQUAL((int) cParts[i].flags,
            (int) cppParts[i].flags);
    }

    /* Intervals are relative to the embedded layout's start (offset
     * stripped).  The leading Unallocated starts at 0 and overlaps the
     * table META.  The trailing gap runs to the END OF THE WHOLE STREAM:
     * tsk_vs_part_unused() sizes it from the image size, so at offset 128
     * it spans sectors 12..256 of the stream (244 sectors) rather than
     * stopping at the embedded 64-sector boundary. */
    const std::vector<ExpectedPart> want = {
        { 0, 1, TSK_VS_PART_FLAG_META },
        { 0, 2, TSK_VS_PART_FLAG_UNALLOC },
        { 2, 10, TSK_VS_PART_FLAG_ALLOC },
        { 12, 244, TSK_VS_PART_FLAG_UNALLOC },
    };
    assertExpectedParts("reuse", cParts, want);

    /* Raw-sector correspondence still holds after the earlier failure:
     * the embedded allocation (interval index 2) reads back its marker. */
    const std::vector<uint8_t> reuseMarkers = { 0, 0, 0xE5, 0 };
    assertSectorCorrespondence("reuse", ti, vs, cParts, reuseMarkers);

    tsk_vs_close(vs);
    /* TskImgInfo imgWrap owns the close */
}

/* Both open entry points (C and C++) and both query entry points (walk
 * and get) must agree on every valid image and every rejection. */
void
VsPartitionBoundaryTest::testEntryPointsConsistent()
{
    struct Case {
        bool gpt;
        size_t sectors;
        std::vector<RawEntry> entries;
        bool expectFail;
    };
    const std::vector<Case> cases = {
        { true, 256, { { 34, 1, 0 }, { 40, 10, 0 } }, false },
        { false, 128, { { 2, 10, 0x83 }, { 20, 10, 0x83 },
            { 0, 0, 0 }, { 0, 0, 0 } }, false },
        { true, 128, { { 40, 0, 0 } }, true },
        { false, 128, { { 40, 0, 0x83 }, { 0, 0, 0 },
            { 0, 0, 0 }, { 0, 0, 0 } }, true },
        { true, 128, { { 120, 20, 0 } }, true },
        { false, 128, { { 200, 5, 0x83 }, { 0, 0, 0 },
            { 0, 0, 0 }, { 0, 0, 0 } }, true },
    };

    for (size_t ci = 0; ci < cases.size(); ++ci) {
        const Case & cs = cases[ci];
        SyntheticImage img;
        if (cs.gpt)
            img.buildGpt(cs.sectors, cs.entries);
        else
            img.buildDos(cs.sectors, cs.entries);

        TSK_IMG_INFO *ti = img.openImage();
        CPPUNIT_ASSERT(ti != NULL);
        TskImgInfo imgWrap(ti);
        const TSK_VS_TYPE_ENUM vt =
            cs.gpt ? TSK_VS_TYPE_GPT : TSK_VS_TYPE_DOS;

        Rejection rc = parseViaC(ti, 0, vt);
        Rejection rcpp = parseViaCpp(&imgWrap, 0, vt);
        std::ostringstream m;
        m << "case " << ci;
        CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(), rc.failed, rcpp.failed);
        CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(),
            (int) rc.category, (int) rcpp.category);
        CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(), cs.expectFail, rc.failed);

        if (!cs.expectFail) {
            tsk_error_reset();
            TSK_VS_INFO *vs = tsk_vs_open(ti, 0, vt);
            CPPUNIT_ASSERT(vs != NULL);

            const std::vector<CollectedPart> walked = collectViaCWalk(vs);
            const std::vector<CollectedPart> got = collectViaGet(vs);
            CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(), got.size(),
                walked.size());
            for (size_t i = 0; i < got.size(); ++i) {
                CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(),
                    walked[i].start, got[i].start);
                CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(),
                    walked[i].len, got[i].len);
                CPPUNIT_ASSERT_EQUAL_MESSAGE(m.str(),
                    (int) walked[i].flags, (int) got[i].flags);
            }
            tsk_vs_close(vs);
        }
        /* TskImgInfo imgWrap owns the close (upstream ~TskImgInfo unconditionally closes) */
    }
}

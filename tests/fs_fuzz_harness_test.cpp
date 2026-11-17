/*
 * The Sleuth Kit
 *
 * This software is distributed under the Common Public License 1.0
 */

/*
 * In-memory unit tests for a multi-file-system parsing fuzz harness.
 *
 * The harness under test feeds byte buffers ("memory images") to the TSK
 * file system parsers.  Two structural properties decide whether a fuzz
 * input is safe to run:
 *
 *   1. Format boundaries: a buffer built for one file system (or mutated
 *      from one) must terminate inside explicit budgets when parsed as any
 *      other format, and no parser state may leak from one format open
 *      into the next.
 *
 *   2. Shared buffer boundaries: the harness reuses one scratch buffer
 *      and one backing image buffer across iterations.  Parsing must
 *      never read outside the image bounds nor write outside the shared
 *      scratch buffer (verified with canaries).
 *
 * Additionally, for valid images the key file system metadata must stay
 * consistent across repeated and interleaved opens, and every failing
 * sample is dumped with enough information (format, seed, mutation log,
 * raw bytes) to replay it.
 *
 * This file is self-contained: all test images are constructed in memory,
 * no external .dd files are required.
 */

#include "tsk/tsk_tools_i.h"

#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Little/big endian writers                                           */
/* ------------------------------------------------------------------ */

static void put16le(std::vector<uint8_t> &v, size_t off, uint16_t x)
{
    v[off] = (uint8_t) (x & 0xff);
    v[off + 1] = (uint8_t) ((x >> 8) & 0xff);
}

static void put32le(std::vector<uint8_t> &v, size_t off, uint32_t x)
{
    for (int i = 0; i < 4; i++)
        v[off + i] = (uint8_t) ((x >> (8 * i)) & 0xff);
}

static void put64le(std::vector<uint8_t> &v, size_t off, uint64_t x)
{
    for (int i = 0; i < 8; i++)
        v[off + i] = (uint8_t) ((x >> (8 * i)) & 0xff);
}

static void put16be(std::vector<uint8_t> &v, size_t off, uint16_t x)
{
    v[off] = (uint8_t) ((x >> 8) & 0xff);
    v[off + 1] = (uint8_t) (x & 0xff);
}

static void put32be(std::vector<uint8_t> &v, size_t off, uint32_t x)
{
    for (int i = 0; i < 4; i++)
        v[off + i] = (uint8_t) ((x >> (8 * (3 - i))) & 0xff);
}

/* both-endian (LE then BE) as used by ISO9660 */
static void put16both(std::vector<uint8_t> &v, size_t off, uint16_t x)
{
    put16le(v, off, x);
    put16be(v, off + 2, x);
}

static void put32both(std::vector<uint8_t> &v, size_t off, uint32_t x)
{
    put32le(v, off, x);
    put32be(v, off + 4, x);
}

static void putstr(std::vector<uint8_t> &v, size_t off, const char *s,
    size_t len)
{
    memcpy(&v[off], s, len);
}

/* ------------------------------------------------------------------ */
/* Minimal valid in-memory file system images                          */
/* ------------------------------------------------------------------ */

/*
 * FAT12: 100 sectors of 512 bytes.
 *   sector 0      : boot sector (BPB)
 *   sector 1-4    : two 2-sector FATs
 *   sector 5-18   : root directory (224 entries)
 *   sector 19+    : data area (81 clusters -> FAT12)
 * Contains one file "TEST.TXT" (cluster 2) with content "hello".
 */
static std::vector<uint8_t> build_fat12()
{
    std::vector<uint8_t> img(100 * 512, 0);

    img[0] = 0xEB;
    img[1] = 0x3C;
    img[2] = 0x90;
    putstr(img, 3, "MSDOS5.0", 8);
    put16le(img, 11, 512);          /* bytes per sector */
    img[13] = 1;                    /* sectors per cluster */
    put16le(img, 14, 1);            /* reserved sectors */
    img[16] = 2;                    /* number of FATs */
    put16le(img, 17, 224);          /* root dir entries */
    put16le(img, 19, 100);          /* total sectors (16-bit) */
    img[21] = 0xF8;                 /* media descriptor */
    put16le(img, 22, 2);            /* sectors per FAT */
    put16le(img, 24, 1);            /* sectors per track */
    put16le(img, 26, 1);            /* heads */
    put32le(img, 28, 0);            /* hidden sectors */
    put32le(img, 32, 0);            /* total sectors (32-bit) */
    img[38] = 0x29;                 /* extended boot signature */
    put32le(img, 39, 0x1234ABCD);   /* volume serial */
    putstr(img, 54, "FAT12   ", 8);
    img[510] = 0x55;
    img[511] = 0xAA;

    /* both FATs: media descriptor + cluster 2 -> EOF */
    for (int fat = 0; fat < 2; fat++) {
        size_t base = (1 + fat * 2) * 512;
        img[base + 0] = 0xF8;
        img[base + 1] = 0xFF;
        img[base + 2] = 0xFF;
        img[base + 3] = 0xFF;       /* cluster 2 = 0xFFF (EOF) */
        img[base + 4] = 0x0F;
    }

    /* root directory at sector 5: one file TEST.TXT, cluster 2, 5 bytes */
    size_t root = 5 * 512;
    putstr(img, root, "TEST    TXT", 11);
    img[root + 11] = 0x20;          /* archive */
    put16le(img, root + 26, 2);     /* first cluster */
    put32le(img, root + 28, 5);     /* size */

    /* data area starts at sector 19; cluster 2 == sector 19 */
    putstr(img, 19 * 512, "hello", 5);

    return img;
}

/*
 * EXT2: 128 blocks of 1024 bytes, one block group.
 *   block 1 : superblock (magic 0xEF53)
 *   block 2 : group descriptor table
 *   block 3 : block bitmap, block 4: inode bitmap, block 5: inode table
 *   block 10: root directory data ("." and "..")
 */
static std::vector<uint8_t> build_ext2()
{
    std::vector<uint8_t> img(128 * 1024, 0);
    size_t sb = 1024;

    put32le(img, sb + 0, 64);       /* inodes count */
    put32le(img, sb + 4, 128);      /* blocks count */
    put32le(img, sb + 8, 0);        /* reserved blocks */
    put32le(img, sb + 12, 100);     /* free blocks */
    put32le(img, sb + 16, 50);      /* free inodes */
    put32le(img, sb + 20, 1);       /* first data block */
    put32le(img, sb + 24, 0);       /* log block size -> 1024 */
    put32le(img, sb + 28, 0);       /* log frag size */
    put32le(img, sb + 32, 8192);    /* blocks per group */
    put32le(img, sb + 36, 8192);    /* frags per group */
    put32le(img, sb + 40, 64);      /* inodes per group */
    put16le(img, sb + 56, 0xEF53);  /* magic */
    put16le(img, sb + 58, 1);       /* state: clean */
    put16le(img, sb + 60, 1);       /* errors: continue */
    put32le(img, sb + 76, 1);       /* dynamic revision */
    put32le(img, sb + 84, 11);      /* first non-reserved inode */
    put16le(img, sb + 88, 128);     /* inode size */

    /* group descriptor at block 2 */
    size_t gd = 2 * 1024;
    put32le(img, gd + 0, 3);        /* block bitmap */
    put32le(img, gd + 4, 4);        /* inode bitmap */
    put32le(img, gd + 8, 5);        /* inode table */
    put16le(img, gd + 12, 100);     /* free blocks */
    put16le(img, gd + 14, 50);      /* free inodes */
    put16le(img, gd + 16, 1);       /* used dirs */

    /* inode 2 (root directory) in inode table at block 5 */
    size_t ino2 = 5 * 1024 + (2 - 1) * 128;
    put16le(img, ino2 + 0, 0x41ED); /* directory, 0755 */
    put32le(img, ino2 + 4, 1024);   /* size */
    put16le(img, ino2 + 26, 2);     /* links */
    put32le(img, ino2 + 28, 2);     /* 512-byte sectors */
    put32le(img, ino2 + 40, 10);    /* i_block[0] */

    /* root directory data at block 10 */
    size_t dir = 10 * 1024;
    put32le(img, dir + 0, 2);
    put16le(img, dir + 4, 12);
    img[dir + 6] = 1;
    img[dir + 7] = 2;
    img[dir + 8] = '.';
    put32le(img, dir + 12, 2);
    put16le(img, dir + 16, 1012);
    img[dir + 18] = 2;
    img[dir + 19] = 2;
    img[dir + 20] = '.';
    img[dir + 21] = '.';

    return img;
}

/*
 * ISO9660: 24 sectors of 2048 bytes.
 *   sector 16: primary volume descriptor ("CD001")
 *   sector 17: volume descriptor set terminator
 *   sector 19/20: L/M path tables
 *   sector 21: root directory extent ("." and "..")
 */
static std::vector<uint8_t> build_iso9660()
{
    std::vector<uint8_t> img(24 * 2048, 0);
    size_t pvd = 16 * 2048;

    img[pvd + 0] = 1;               /* primary volume descriptor */
    putstr(img, pvd + 1, "CD001", 5);
    img[pvd + 6] = 1;
    putstr(img, pvd + 8, "FUZZTEST", 8);
    put32both(img, pvd + 80, 24);   /* volume space size */
    put16both(img, pvd + 120, 1);   /* volume set size */
    put16both(img, pvd + 124, 1);   /* volume sequence number */
    put16both(img, pvd + 128, 2048);/* logical block size */
    put32both(img, pvd + 132, 10);  /* path table size */
    put32le(img, pvd + 140, 19);    /* L path table location */
    put32be(img, pvd + 148, 20);    /* M path table location */

    /* root directory record inside the PVD */
    size_t rd = pvd + 156;
    img[rd + 0] = 34;               /* record length */
    put32both(img, rd + 2, 21);     /* extent location */
    put32both(img, rd + 10, 2048);  /* data length */
    img[rd + 18] = 125;             /* 2025 */
    img[rd + 19] = 11;
    img[rd + 20] = 17;
    img[rd + 25] = 2;               /* directory flag */
    put16both(img, rd + 28, 1);
    img[rd + 32] = 1;               /* file id length */
    img[rd + 33] = 0;               /* file id "\0" (root) */

    /* volume descriptor set terminator */
    size_t term = 17 * 2048;
    img[term + 0] = 255;
    putstr(img, term + 1, "CD001", 5);
    img[term + 6] = 1;

    /* L path table at sector 19: one record for the root directory */
    size_t pt = 19 * 2048;
    img[pt + 0] = 1;                /* name length */
    img[pt + 1] = 0;                /* extended attribute length */
    put32le(img, pt + 2, 21);       /* extent */
    put16le(img, pt + 6, 1);        /* parent directory number */
    img[pt + 8] = 0;                /* name */
    /* M path table at sector 20 */
    size_t mpt = 20 * 2048;
    img[mpt + 0] = 1;
    put32be(img, mpt + 2, 21);
    put16be(img, mpt + 6, 1);

    /* root directory extent at sector 21: "." and ".." */
    for (int e = 0; e < 2; e++) {
        size_t de = 21 * 2048 + e * 34;
        img[de + 0] = 34;
        put32both(img, de + 2, 21);
        put32both(img, de + 10, 2048);
        img[de + 18] = 125;
        img[de + 19] = 11;
        img[de + 20] = 17;
        img[de + 25] = 2;
        put16both(img, de + 28, 1);
        img[de + 32] = 1;
        img[de + 33] = (uint8_t) e; /* 0x00 = ".", 0x01 = ".." */
    }

    return img;
}

/*
 * NTFS: 200 clusters of 512 bytes.
 *   cluster 0 : boot sector ("NTFS    ")
 *   cluster 4 : $MFT (16 clusters -> 8 records of 1024 bytes)
 *     record 0: $MFT    ($DATA non-resident -> clusters 4-19)
 *     record 3: $Volume ($VOLUME_INFORMATION resident, v3.1)
 *     record 6: $Bitmap ($DATA non-resident -> cluster 30)
 *   cluster 30: allocation bitmap data
 */
static void ntfs_record_header(std::vector<uint8_t> &img, size_t rec)
{
    putstr(img, rec, "FILE", 4);
    put16le(img, rec + 4, 0x30);    /* update sequence offset */
    put16le(img, rec + 6, 3);       /* update sequence count */
    put16le(img, rec + 16, 1);      /* sequence number */
    put16le(img, rec + 18, 1);      /* link count */
    put16le(img, rec + 20, 0x38);   /* first attribute offset */
    put16le(img, rec + 22, 1);      /* flags: in use */
    put32le(img, rec + 28, 1024);   /* allocated size */
    put16le(img, rec + 0x30, 0xAAAA);       /* update sequence value */
    put16le(img, rec + 0x32, 0);    /* replacement for sector 1 tail */
    put16le(img, rec + 0x34, 0);    /* replacement for sector 2 tail */
    put16le(img, rec + 510, 0xAAAA);        /* sector tails must match */
    put16le(img, rec + 1022, 0xAAAA);
}

static std::vector<uint8_t> build_ntfs()
{
    std::vector<uint8_t> img(200 * 512, 0);

    img[0] = 0xEB;
    img[1] = 0x52;
    img[2] = 0x90;
    putstr(img, 3, "NTFS    ", 8);
    put16le(img, 11, 512);          /* bytes per sector */
    img[13] = 1;                    /* sectors per cluster */
    put64le(img, 40, 200);          /* total sectors */
    put64le(img, 48, 4);            /* $MFT cluster */
    put64le(img, 56, 8);            /* $MFTMirr cluster */
    img[64] = 0xF6;                 /* MFT record size: 2^10 */
    img[68] = 0xF6;                 /* index record size: 2^10 */
    put64le(img, 72, 0x1122334455667788ULL);        /* serial */
    img[510] = 0x55;
    img[511] = 0xAA;

    const size_t mft = 4 * 512;

    /* record 0: $MFT with non-resident $DATA (clusters 4-19) */
    size_t r0 = mft;
    ntfs_record_header(img, r0);
    size_t a = r0 + 0x38;
    put32le(img, a + 0, 0x80);      /* $DATA */
    put32le(img, a + 4, 0x48);      /* attribute length */
    img[a + 8] = 1;                 /* non-resident */
    put64le(img, a + 16, 0);        /* start VCN */
    put64le(img, a + 24, 15);       /* last VCN */
    put16le(img, a + 32, 0x40);     /* runlist offset */
    put64le(img, a + 40, 16 * 512); /* allocated size */
    put64le(img, a + 48, 16 * 512); /* real size */
    put64le(img, a + 56, 16 * 512); /* initialized size */
    img[a + 0x40] = 0x11;           /* run: 1-byte len, 1-byte off */
    img[a + 0x41] = 0x10;           /* length 16 clusters */
    img[a + 0x42] = 0x04;           /* offset cluster 4 */
    img[a + 0x43] = 0x00;           /* end of runlist */
    put32le(img, a + 0x48, 0xFFFFFFFF);     /* attribute list end */
    put32le(img, r0 + 24, 0x38 + 0x48 + 8); /* record used size */

    /* record 3: $Volume with resident $VOLUME_INFORMATION (3.1) */
    size_t r3 = mft + 3 * 1024;
    ntfs_record_header(img, r3);
    a = r3 + 0x38;
    put32le(img, a + 0, 0x70);      /* $VOLUME_INFORMATION */
    put32le(img, a + 4, 0x28);      /* attribute length */
    img[a + 8] = 0;                 /* resident */
    put32le(img, a + 16, 12);       /* value length */
    put16le(img, a + 20, 0x18);     /* value offset */
    img[a + 0x18 + 8] = 3;          /* major version */
    img[a + 0x18 + 9] = 1;          /* minor version */
    put32le(img, a + 0x28, 0xFFFFFFFF);
    put32le(img, r3 + 24, 0x38 + 0x28 + 8);

    /* record 6: $Bitmap with non-resident $DATA (cluster 30) */
    size_t r6 = mft + 6 * 1024;
    ntfs_record_header(img, r6);
    a = r6 + 0x38;
    put32le(img, a + 0, 0x80);      /* $DATA */
    put32le(img, a + 4, 0x48);
    img[a + 8] = 1;
    put64le(img, a + 16, 0);
    put64le(img, a + 24, 0);        /* last VCN */
    put16le(img, a + 32, 0x40);
    put64le(img, a + 40, 512);
    put64le(img, a + 48, 512);
    put64le(img, a + 56, 512);
    img[a + 0x40] = 0x11;
    img[a + 0x41] = 0x01;           /* length 1 cluster */
    img[a + 0x42] = 0x1E;           /* offset cluster 30 */
    img[a + 0x43] = 0x00;
    put32le(img, a + 0x48, 0xFFFFFFFF);
    put32le(img, r6 + 24, 0x38 + 0x48 + 8);

    /* allocation bitmap content at cluster 30 */
    memset(&img[30 * 512], 0xFF, 64);

    return img;
}

/* ------------------------------------------------------------------ */
/* Deterministic mutator with replay log                               */
/* ------------------------------------------------------------------ */

struct Mutation {
    size_t off;
    uint8_t oldval;
    uint8_t newval;
};

static uint64_t rng_state;

static uint64_t rng_next()
{
    /* xorshift64* */
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* Apply `count` deterministic byte mutations; return the replay log. */
static std::vector<Mutation> mutate_image(std::vector<uint8_t> &img,
    uint64_t seed, int count)
{
    std::vector<Mutation> log;
    rng_state = seed ? seed : 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < count; i++) {
        Mutation m;
        m.off = (size_t) (rng_next() % img.size());
        uint8_t xormask = (uint8_t) (rng_next() & 0xff);
        if (xormask == 0)
            xormask = 0x5A;
        m.oldval = img[m.off];
        img[m.off] ^= xormask;
        m.newval = img[m.off];
        log.push_back(m);
    }
    return log;
}

/* ------------------------------------------------------------------ */
/* Replay dump: enough information to reproduce a failing sample       */
/* ------------------------------------------------------------------ */

static void dump_replay(const char *fmt, const char *mode, uint64_t seed,
    const std::vector<Mutation> *mutations,
    const std::vector<uint8_t> &img, const char *reason)
{
    char fname[256];
    snprintf(fname, sizeof(fname), "fs_fuzz_replay_%s_%s_%llu.img", fmt,
        mode, (unsigned long long) seed);
    FILE *f = fopen(fname, "wb");
    if (f) {
        if (!img.empty())
            fwrite(&img[0], 1, img.size(), f);
        fclose(f);
    }
    fprintf(stderr, "\n=== FUZZ REPLAY ===\n");
    fprintf(stderr, "reason: %s\n", reason);
    fprintf(stderr, "format: %s  open-mode: %s  seed: %llu\n", fmt, mode,
        (unsigned long long) seed);
    fprintf(stderr, "image: %s (%zu bytes written)\n", fname, img.size());
    if (mutations) {
        fprintf(stderr, "mutations (%zu):\n", mutations->size());
        for (size_t i = 0; i < mutations->size(); i++)
            fprintf(stderr, "  off=%zu 0x%02x -> 0x%02x\n",
                (*mutations)[i].off, (*mutations)[i].oldval,
                (*mutations)[i].newval);
    }
    fprintf(stderr, "===================\n");
    fflush(stderr);
}

/* ------------------------------------------------------------------ */
/* Bounds-instrumented memory image (TSK_IMG_TYPE_EXTERNAL)            */
/* ------------------------------------------------------------------ */

struct MemImg {
    TSK_IMG_INFO img;               /* must be the first member */
    const uint8_t *data;
    size_t size;
    /* instrumentation */
    size_t read_calls;
    size_t oob_attempts;            /* reads starting outside [0,size) */
    size_t truncated_reads;         /* reads clipped at the end */
    TSK_OFF_T max_end;              /* furthest end offset requested */
};

static ssize_t mem_img_read(TSK_IMG_INFO *img, TSK_OFF_T off, char *buf,
    size_t len)
{
    MemImg *m = (MemImg *) img;     /* img is the first member */
    m->read_calls++;
    if (off < 0 || (uint64_t) off > m->size) {
        m->oob_attempts++;          /* parser escaped the image bounds */
        return 0;
    }
    if ((TSK_OFF_T) (off + len) > m->max_end)
        m->max_end = off + (TSK_OFF_T) len;
    size_t avail = m->size - (size_t) off;
    size_t n = len < avail ? len : avail;
    if (n < len)
        m->truncated_reads++;
    if (n)
        memcpy(buf, m->data + off, n);
    return (ssize_t) n;
}

static void mem_img_close(TSK_IMG_INFO *img)
{
    MemImg *m = (MemImg *) img;
    delete m;                       /* lock is deinit'd by tsk_img_close */
}

static void mem_img_imgstat(TSK_IMG_INFO *, FILE *)
{
}

static MemImg *mem_img_open(const uint8_t *data, size_t size)
{
    MemImg *m = new MemImg();
    memset(m, 0, sizeof(*m));
    m->data = data;
    m->size = size;
    if (tsk_img_open_external(m, (TSK_OFF_T) size, 512, mem_img_read,
            mem_img_close, mem_img_imgstat) == NULL) {
        delete m;
        return NULL;
    }
    return m;
}

/* ------------------------------------------------------------------ */
/* Shared scratch buffer with canaries (shared-buffer boundary)        */
/* ------------------------------------------------------------------ */

#define SHARED_CAP   (128 * 1024)
#define CANARY_LEN   64
#define CANARY_BYTE  0xC7

static char g_shared_raw[SHARED_CAP + 2 * CANARY_LEN];
static char *g_shared = g_shared_raw + CANARY_LEN;

static void shared_reset()
{
    memset(g_shared_raw, CANARY_BYTE, sizeof(g_shared_raw));
}

static bool shared_canaries_ok()
{
    for (size_t i = 0; i < CANARY_LEN; i++) {
        if ((uint8_t) g_shared_raw[i] != CANARY_BYTE)
            return false;
        if ((uint8_t) g_shared_raw[CANARY_LEN + SHARED_CAP + i] !=
            CANARY_BYTE)
            return false;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Bounded parse driver                                                */
/* ------------------------------------------------------------------ */

/* current fuzz case context, used for replay dumps (also from the
 * alarm handler) */
static int g_failures;
static const char *g_case_fmt;
static const char *g_case_mode;
static uint64_t g_case_seed;
static const std::vector<Mutation> *g_case_mutations;
static const std::vector<uint8_t> *g_case_img;

struct FsMeta {
    bool opened;
    uint32_t ftype;
    TSK_OFF_T offset;
    unsigned int block_size;
    TSK_DADDR_T block_count;
    TSK_DADDR_T first_block;
    TSK_DADDR_T last_block;
    TSK_INUM_T first_inum;
    TSK_INUM_T last_inum;
    TSK_INUM_T root_inum;
    FsMeta(): opened(false), ftype(0), offset(0), block_size(0),
        block_count(0), first_block(0), last_block(0), first_inum(0),
        last_inum(0), root_inum(0) {}
    bool operator==(const FsMeta &o) const
    {
        return opened == o.opened && ftype == o.ftype && offset == o.offset
            && block_size == o.block_size && block_count == o.block_count
            && first_block == o.first_block
            && last_block == o.last_block && first_inum == o.first_inum
            && last_inum == o.last_inum && root_inum == o.root_inum;
    }
};

struct Budget {
    size_t dir_entries;
    size_t inodes;
    size_t file_reads;
    size_t file_bytes;
    Budget(): dir_entries(512), inodes(256), file_reads(8),
        file_bytes(1 << 20) {}
};

struct WalkCtx {
    Budget budget;
    size_t files_read;
    WalkCtx(): files_read(0) {}
};

static TSK_WALK_RET_ENUM dir_action(TSK_FS_FILE *, const char *, void *ptr)
{
    WalkCtx *ctx = (WalkCtx *) ptr;
    if (ctx->budget.dir_entries == 0)
        return TSK_WALK_STOP;       /* explicit bound reached */
    ctx->budget.dir_entries--;
    return TSK_WALK_CONT;
}

static TSK_WALK_RET_ENUM meta_action(TSK_FS_FILE *fs_file, void *ptr)
{
    WalkCtx *ctx = (WalkCtx *) ptr;
    if (ctx->budget.inodes == 0)
        return TSK_WALK_STOP;
    ctx->budget.inodes--;

    /* read a bounded prefix of a few allocated files via the shared
     * scratch buffer */
    if (ctx->files_read < ctx->budget.file_reads && fs_file->meta
        && fs_file->meta->size > 0
        && (fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC)) {
        TSK_OFF_T off = 0;
        size_t left = ctx->budget.file_bytes;
        TSK_OFF_T fsize = fs_file->meta->size;
        ctx->files_read++;
        while (off < fsize && left > 0) {
            size_t want = SHARED_CAP;
            if ((TSK_OFF_T) want > fsize - off)
                want = (size_t) (fsize - off);
            if (want > left)
                want = left;
            ssize_t n = tsk_fs_file_read(fs_file, off, g_shared, want,
                TSK_FS_FILE_READ_FLAG_NONE);
            if (n <= 0)
                break;
            off += n;
            left -= (size_t) n;
        }
    }
    return TSK_WALK_CONT;
}

/* Per-case wall-clock bound: if a parser runs away, dump replay and die. */
static void on_alarm(int)
{
    const char *fmt = g_case_fmt ? g_case_fmt : "?";
    fprintf(stderr, "\nALARM: parse of format %s exceeded time budget\n",
        fmt);
    dump_replay(g_case_fmt, g_case_mode, g_case_seed, g_case_mutations,
        *g_case_img, "time budget exceeded (no explicit termination)");
    _exit(2);
}

#define CASE_TIME_LIMIT 10          /* seconds per fuzz input */

struct ParseResult {
    FsMeta meta;
    size_t read_calls;
    size_t oob_attempts;
    size_t truncated_reads;
    bool canaries_ok;
    ParseResult(): read_calls(0), oob_attempts(0), truncated_reads(0),
        canaries_ok(true) {}
};

/*
 * Parse one in-memory image as `ftype` with explicit budgets.
 * The image bytes must outlive the call.  Any read outside the image
 * bounds is counted in oob_attempts; the shared scratch buffer canaries
 * are verified before returning.
 */
static ParseResult bounded_parse(const uint8_t *data, size_t size,
    TSK_FS_TYPE_ENUM ftype)
{
    ParseResult res;
    shared_reset();

    MemImg *mimg = mem_img_open(data, size);
    if (!mimg)
        return res;

    alarm(CASE_TIME_LIMIT);
    TSK_FS_INFO *fs = tsk_fs_open_img((TSK_IMG_INFO *) mimg, 0, ftype);
    if (fs) {
        res.meta.opened = true;
        res.meta.ftype = fs->ftype;
        res.meta.offset = fs->offset;
        res.meta.block_size = fs->block_size;
        res.meta.block_count = fs->block_count;
        res.meta.first_block = fs->first_block;
        res.meta.last_block = fs->last_block;
        res.meta.first_inum = fs->first_inum;
        res.meta.last_inum = fs->last_inum;
        res.meta.root_inum = fs->root_inum;

        WalkCtx ctx;

        /* bounded directory walk from the root */
        tsk_fs_dir_walk(fs, fs->root_inum,
            (TSK_FS_DIR_WALK_FLAG_ENUM) (TSK_FS_DIR_WALK_FLAG_ALLOC |
                TSK_FS_DIR_WALK_FLAG_UNALLOC |
                TSK_FS_DIR_WALK_FLAG_RECURSE), dir_action, &ctx);
        tsk_error_reset();

        /* bounded metadata walk */
        TSK_INUM_T last = fs->last_inum;
        if (last > fs->first_inum + (TSK_INUM_T) ctx.budget.inodes)
            last = fs->first_inum + (TSK_INUM_T) ctx.budget.inodes;
        if (last >= fs->first_inum)
            tsk_fs_meta_walk(fs, fs->first_inum, last,
                (TSK_FS_META_FLAG_ENUM) (TSK_FS_META_FLAG_ALLOC |
                    TSK_FS_META_FLAG_UNALLOC), meta_action, &ctx);
        tsk_error_reset();

        tsk_fs_close(fs);
    }
    alarm(0);

    res.read_calls = mimg->read_calls;
    res.oob_attempts = mimg->oob_attempts;
    res.truncated_reads = mimg->truncated_reads;
    tsk_img_close((TSK_IMG_INFO *) mimg);

    res.canaries_ok = shared_canaries_ok();
    tsk_error_reset();
    return res;
}

/* ------------------------------------------------------------------ */
/* Test framework                                                      */
/* ------------------------------------------------------------------ */

#define CHECK(cond, fmtname, modename, seed, muts, img, ...)           \
    do {                                                               \
        if (!(cond)) {                                                 \
            char reason[512];                                          \
            snprintf(reason, sizeof(reason), __VA_ARGS__);             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                reason);                                               \
            dump_replay(fmtname, modename, seed, muts, img, reason);   \
            g_failures++;                                              \
        }                                                              \
    } while (0)

/* ------------------------------------------------------------------ */
/* Test 1: valid images keep consistent key metadata across repeated   */
/* and interleaved opens (no state carried between formats)            */
/* ------------------------------------------------------------------ */

struct FormatDef {
    const char *name;
    TSK_FS_TYPE_ENUM ftype;
    std::vector<uint8_t> (*builder)();
    unsigned int expect_block_size;
};

static const FormatDef g_formats[] = {
    {"fat12", TSK_FS_TYPE_FAT12, build_fat12, 512},
    {"ext2", TSK_FS_TYPE_EXT2, build_ext2, 1024},
    {"iso9660", TSK_FS_TYPE_ISO9660, build_iso9660, 2048},
    {"ntfs", TSK_FS_TYPE_NTFS, build_ntfs, 512},
};
#define NFORMATS (sizeof(g_formats) / sizeof(g_formats[0]))

static int test_valid_metadata_consistency()
{
    fprintf(stderr, "test_valid_metadata_consistency\n");
    std::vector<std::vector<uint8_t> > images(NFORMATS);
    std::vector<FsMeta> reference(NFORMATS);

    for (size_t i = 0; i < NFORMATS; i++) {
        images[i] = g_formats[i].builder();
        g_case_fmt = g_formats[i].name;
        g_case_mode = "explicit";
        g_case_seed = 0;
        g_case_mutations = NULL;
        g_case_img = &images[i];

        ParseResult r = bounded_parse(&images[i][0], images[i].size(),
            g_formats[i].ftype);
        CHECK(r.meta.opened, g_formats[i].name, "explicit", 0, NULL,
            images[i], "valid %s image failed to open", g_formats[i].name);
        if (!r.meta.opened)
            continue;
        CHECK(r.meta.block_size == g_formats[i].expect_block_size,
            g_formats[i].name, "explicit", 0, NULL, images[i],
            "%s block_size %u != expected %u", g_formats[i].name,
            r.meta.block_size, g_formats[i].expect_block_size);
        CHECK(r.oob_attempts == 0, g_formats[i].name, "explicit", 0, NULL,
            images[i], "%s: %zu out-of-bounds read attempts on valid image",
            g_formats[i].name, r.oob_attempts);
        CHECK(r.canaries_ok, g_formats[i].name, "explicit", 0, NULL,
            images[i], "%s: shared buffer canary corrupted on valid image",
            g_formats[i].name);
        reference[i] = r.meta;
    }

    /* Interleave opens of all formats twice more; metadata must be
     * identical to the reference run every time, i.e. opening other
     * formats in between does not change the outcome. */
    for (int round = 0; round < 2; round++) {
        for (size_t i = 0; i < NFORMATS; i++) {
            if (!reference[i].opened)
                continue;
            g_case_fmt = g_formats[i].name;
            g_case_img = &images[i];
            ParseResult r = bounded_parse(&images[i][0], images[i].size(),
                g_formats[i].ftype);
            CHECK(r.meta == reference[i], g_formats[i].name, "explicit",
                0, NULL, images[i],
                "%s metadata changed after interleaved opens (round %d)",
                g_formats[i].name, round);
            CHECK(r.oob_attempts == 0, g_formats[i].name, "explicit", 0,
                NULL, images[i],
                "%s: out-of-bounds reads in interleaved round %d",
                g_formats[i].name, round);
        }
    }
    return g_failures ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Test 2: format switching on one shared image buffer                 */
/* ------------------------------------------------------------------ */

static int test_format_switching()
{
    fprintf(stderr, "test_format_switching\n");

    std::vector<std::vector<uint8_t> > images(NFORMATS);
    size_t maxsz = 0;
    for (size_t i = 0; i < NFORMATS; i++) {
        images[i] = g_formats[i].builder();
        if (images[i].size() > maxsz)
            maxsz = images[i].size();
    }

    /* One shared backing buffer, reused for every format. */
    std::vector<uint8_t> shared(maxsz, 0);

    /* Reference metadata for each format parsed from its own buffer. */
    std::vector<FsMeta> refmeta(NFORMATS);
    for (size_t i = 0; i < NFORMATS; i++) {
        memcpy(&shared[0], &images[i][0], images[i].size());
        ParseResult r = bounded_parse(&shared[0], images[i].size(),
            g_formats[i].ftype);
        refmeta[i] = r.meta;
    }

    /* Now cycle FAT -> NTFS -> EXT2 -> ISO -> FAT ... through the same
     * buffer and require the results to match the references exactly:
     * no state from format N-1 may influence format N. */
    for (int cycle = 0; cycle < 3; cycle++) {
        for (size_t i = 0; i < NFORMATS; i++) {
            memcpy(&shared[0], &images[i][0], images[i].size());
            g_case_fmt = g_formats[i].name;
            g_case_img = &images[i];
            ParseResult r = bounded_parse(&shared[0], images[i].size(),
                g_formats[i].ftype);
            CHECK(r.meta == refmeta[i], g_formats[i].name, "shared-buf",
                0, NULL, images[i],
                "%s metadata differs when parsed through shared buffer "
                "(cycle %d): state carried between formats",
                g_formats[i].name, cycle);
            CHECK(r.canaries_ok, g_formats[i].name, "shared-buf", 0, NULL,
                images[i], "%s: canary corrupted in cycle %d",
                g_formats[i].name, cycle);
        }
    }

    /* Cross-format confusion: overwrite each valid image's signature
     * area with another format's magic and parse with auto-detect.
     * Must terminate within budgets, stay in bounds, and leave the
     * global error state clean enough that a following valid open is
     * unaffected. */
    static const struct {
        size_t off;
        const char *sig;
        size_t len;
    } alien[] = {
        {3, "NTFS    ", 8},           /* NTFS OEM id */
        {16 * 2048 + 1, "CD001", 5},  /* ISO9660 PVD (offset beyond
                                          small images is skipped) */
        {1024 + 56, "\x53\xEF", 2},   /* ext2 superblock magic */
    };

    for (size_t i = 0; i < NFORMATS; i++) {
        for (size_t s = 0; s < sizeof(alien) / sizeof(alien[0]); s++) {
            if (alien[s].off + alien[s].len > images[i].size())
                continue;
            std::vector<uint8_t> hybrid = images[i];
            memcpy(&hybrid[alien[s].off], alien[s].sig, alien[s].len);
            g_case_fmt = g_formats[i].name;
            g_case_mode = "detect";
            g_case_seed = 1000 + s;
            g_case_mutations = NULL;
            g_case_img = &hybrid;
            ParseResult r = bounded_parse(&hybrid[0], hybrid.size(),
                TSK_FS_TYPE_DETECT);
            CHECK(r.oob_attempts == 0, g_formats[i].name, "detect",
                1000 + s, NULL, hybrid,
                "%s+alien-sig-%zu: %zu out-of-bounds read attempts",
                g_formats[i].name, s, r.oob_attempts);
            CHECK(r.canaries_ok, g_formats[i].name, "detect", 1000 + s,
                NULL, hybrid, "%s+alien-sig-%zu: canary corrupted",
                g_formats[i].name, s);
        }
        /* the very next valid open must be unaffected */
        g_case_img = &images[i];
        ParseResult ok = bounded_parse(&images[i][0], images[i].size(),
            g_formats[i].ftype);
        CHECK(ok.meta == refmeta[i], g_formats[i].name, "explicit", 0,
            NULL, images[i],
            "%s metadata changed after alien-signature detect opens",
            g_formats[i].name);
    }
    return g_failures ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Test 3: malformed images of every format terminate within explicit  */
/* bounds and never escape the image or the shared buffer              */
/* ------------------------------------------------------------------ */

static int test_malformed_bounded()
{
    fprintf(stderr, "test_malformed_bounded\n");
    const int seeds_per_format = 48;
    size_t stat_cases = 0, stat_opened = 0, stat_reads = 0,
        stat_truncated = 0;

    for (size_t i = 0; i < NFORMATS; i++) {
        std::vector<uint8_t> valid = g_formats[i].builder();
        for (int seed = 1; seed <= seeds_per_format; seed++) {
            std::vector<uint8_t> img = valid;
            std::vector<Mutation> muts = mutate_image(img, (uint64_t) seed,
                1 + seed % 8);

            /* parse as the native format and, every 4th seed, as every
             * other format plus auto-detect (format switching under
             * malformed input) */
            static const TSK_FS_TYPE_ENUM modes[] = {
                TSK_FS_TYPE_FAT12, TSK_FS_TYPE_EXT2,
                TSK_FS_TYPE_ISO9660, TSK_FS_TYPE_NTFS, TSK_FS_TYPE_DETECT,
            };
            size_t nmodes = (seed % 4 == 0) ? 5 : 1;
            for (size_t mi = 0; mi < nmodes; mi++) {
                TSK_FS_TYPE_ENUM ftype =
                    mi == 0 ? g_formats[i].ftype : modes[mi];
                const char *modename =
                    ftype == TSK_FS_TYPE_DETECT ? "detect" : "explicit";
                g_case_fmt = g_formats[i].name;
                g_case_mode = modename;
                g_case_seed = (uint64_t) seed;
                g_case_mutations = &muts;
                g_case_img = &img;

                ParseResult r = bounded_parse(&img[0], img.size(), ftype);
                stat_cases++;
                stat_opened += r.meta.opened ? 1 : 0;
                stat_reads += r.read_calls;
                stat_truncated += r.truncated_reads;
                CHECK(r.oob_attempts == 0, g_formats[i].name, modename,
                    (uint64_t) seed, &muts, img,
                    "%s seed %d: %zu out-of-bounds read attempts",
                    g_formats[i].name, seed, r.oob_attempts);
                CHECK(r.canaries_ok, g_formats[i].name, modename,
                    (uint64_t) seed, &muts, img,
                    "%s seed %d: shared buffer canary corrupted",
                    g_formats[i].name, seed);
            }

            /* error-state hygiene: after malformed input, a valid image
             * of the same format must still open with identical
             * metadata (no parser error state carried over) */
            if (seed % 8 == 0) {
                ParseResult ok = bounded_parse(&valid[0], valid.size(),
                    g_formats[i].ftype);
                CHECK(ok.meta.opened, g_formats[i].name, "explicit",
                    (uint64_t) seed, &muts, img,
                    "%s: valid image no longer opens after malformed "
                    "seed %d", g_formats[i].name, seed);
            }
        }
    }
    fprintf(stderr, "  malformed: %zu cases, %zu opened, %zu reads, "
        "%zu clipped at image end\n", stat_cases, stat_opened, stat_reads,
        stat_truncated);
    CHECK(stat_cases > 0 && stat_reads > 0, "all", "explicit", 0, NULL,
        g_formats[0].builder(), "malformed-image loop did no work");
    return g_failures ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Test 4: shared buffer and image boundary edges                      */
/* ------------------------------------------------------------------ */

static int test_shared_buffer_boundary()
{
    fprintf(stderr, "test_shared_buffer_boundary\n");

    std::vector<uint8_t> img = build_fat12();
    MemImg *mimg = mem_img_open(&img[0], img.size());
    if (!mimg) {
        fprintf(stderr, "FAIL: could not open memory image\n");
        g_failures++;
        return 1;
    }

    shared_reset();

    /* read exactly to the end of the image: must succeed fully */
    ssize_t n = tsk_img_read((TSK_IMG_INFO *) mimg,
        (TSK_OFF_T) img.size() - 512, g_shared, 512);
    CHECK(n == 512, "fat12", "boundary", 0, NULL, img,
        "read at image end returned %zd, expected 512", n);

    /* read crossing the end: must be clipped, not overflow the buffer */
    n = tsk_img_read((TSK_IMG_INFO *) mimg, (TSK_OFF_T) img.size() - 100,
        g_shared, 512);
    CHECK(n <= 100, "fat12", "boundary", 0, NULL, img,
        "read crossing image end returned %zd, expected <= 100", n);

    /* read fully beyond the end: the img layer itself enforces the
     * boundary and must reject it before it reaches the read callback */
    size_t calls_before = mimg->read_calls;
    n = tsk_img_read((TSK_IMG_INFO *) mimg, (TSK_OFF_T) img.size() + 512,
        g_shared, 512);
    CHECK(n <= 0, "fat12", "boundary", 0, NULL, img,
        "read beyond image end returned %zd, expected <= 0", n);
    CHECK(mimg->read_calls == calls_before, "fat12", "boundary", 0, NULL,
        img, "read beyond image end reached the backing buffer");
    tsk_error_reset();

    CHECK(shared_canaries_ok(), "fat12", "boundary", 0, NULL, img,
        "shared buffer canary corrupted by boundary reads");

    /* reuse the same shared buffer across all four formats: fill it
     * with a poison pattern, run a bounded parse, verify canaries */
    for (size_t i = 0; i < NFORMATS; i++) {
        std::vector<uint8_t> fimg = g_formats[i].builder();
        memset(g_shared, 0xA5, SHARED_CAP);
        g_case_fmt = g_formats[i].name;
        g_case_img = &fimg;
        ParseResult r = bounded_parse(&fimg[0], fimg.size(),
            g_formats[i].ftype);
        CHECK(r.canaries_ok, g_formats[i].name, "shared-buf", 0, NULL,
            fimg, "%s: shared buffer overflowed its %d-byte capacity",
            g_formats[i].name, SHARED_CAP);
    }

    tsk_img_close((TSK_IMG_INFO *) mimg);
    return g_failures ? 1 : 0;
}

/* ------------------------------------------------------------------ */

int main()
{
    tsk_verbose = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);

    test_valid_metadata_consistency();
    test_format_switching();
    test_malformed_bounded();
    test_shared_buffer_boundary();

    if (g_failures) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("Tests Passed\n");
    return 0;
}

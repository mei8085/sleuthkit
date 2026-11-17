/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2004-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

 /*
  * C header file with GPT and internal data structures.
  */

#ifndef _TSK_GPT_H
#define _TSK_GPT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Partition type in the safety DOS partition table */
#define GPT_PART_SOFFSET	0
#define GPT_DOS_TYPE	0xEE



/* This is located in sector 1 of the disk */
#define GPT_HEAD_OFFSET	1
#define GPT_HEAD_SIG	0x5452415020494645ULL

/* Byte offsets of fields inside the GPT header (UEFI 2.10, Table 5-4) */
#define GPT_HEAD_CRC_OFF            16
#define GPT_HEAD_FIXED_SIZE         92  /* size of all defined header fields */

    typedef struct {
        uint8_t signature[8];   /* EFI PART */
        uint8_t version[4];
        uint8_t head_size_b[4]; /* size of partition header */
        uint8_t head_crc[4];    /* crc of header */
        uint8_t f1[4];
        uint8_t head_lba[8];    /* lba of this header */
        uint8_t head2_lba[8];   /* lba of second header */
        uint8_t partarea_start[8];      /* lba of partition area start */
        uint8_t partarea_end[8];        /* lba of partition area end */
        uint8_t guid[16];       /* disk GUID */
        uint8_t tab_start_lba[8];       /* lba of table start */
        uint8_t tab_num_ent[4]; /* num of table entries */
        uint8_t tab_size_b[4];  /* size of each table entry */
        uint8_t tab_crc[4];     /* crc of table */
        uint8_t f2[420];
    } gpt_head;


/* The location of this is specified in the header - tab_start */
    typedef struct {
        uint8_t type_guid[16];  /* partition type guid */
        uint8_t id_guid[16];    /* unique partition GUID */
        uint8_t start_lba[8];   /* Starting lba of part */
        uint8_t end_lba[8];     /* end lba of part */
        uint8_t flags[8];       /* flags */
        uint8_t name[72];       /* name in unicode */
    } gpt_entry;

    typedef enum {
        PRIMARY_TABLE,
        SECONDARY_TABLE,
    } GPT_LOCATION_ENUM;

/**
 * \internal
 * On-disk copy of one GPT (header sector plus its partition entry array),
 * together with the results of the UEFI CRC32 validation.  A copy is
 * considered trustworthy only when both the header CRC and the partition
 * entry array CRC match the values stored in the header.
 */
    typedef struct {
        GPT_LOCATION_ENUM location;     /* primary or secondary copy */
        gpt_head *head;                 /* one sector, native on-disk bytes */
        uint8_t *tab;                   /* raw partition entry array bytes */
        size_t tab_size;                /* actual bytes stored in tab */
        uint32_t head_size;             /* head->head_size_b, decoded */
        uint32_t ent_size;             /* head->tab_size_b, decoded */
        uint32_t tab_num_ent;           /* head->tab_num_ent, decoded */
        uint64_t tab_start_lba;         /* head->tab_start_lba, decoded */
        uint8_t head_crc_ok;            /* header CRC matches */
        uint8_t tab_crc_ok;             /* entry array CRC matches */
        uint8_t valid;                  /* both CRCs and sanity checks pass */
    } gpt_copy;


#ifdef __cplusplus
}
#endif
#endif

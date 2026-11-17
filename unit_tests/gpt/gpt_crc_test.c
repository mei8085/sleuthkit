/*
 * Test harness for GPT CRC / tamper detection.
 * Opens each generated image through the real TSK API (tsk_vs_open) and
 * reports whether partitions were returned and what error was raised.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tsk/libtsk.h"

typedef struct {
    const char *name;
    int expect_open;       /* 1 = open must succeed, 0 = must fail */
    int expect_crc_err;    /* 1 = failure must carry TSK_ERR_VS_CRC */
    int min_alloc_parts;   /* expected minimum ALLOC partitions on success */
} scenario_t;

static scenario_t scenarios[] = {
    {"valid.img",                     1, 0, 1},
    {"tamper_primary_head_crc.img",   0, 1, 0},
    {"tamper_backup_head_crc.img",    0, 1, 0},
    {"tamper_primary_table_crc.img",  0, 1, 0},
    {"tamper_backup_table_crc.img",   0, 1, 0},
    {"tamper_header_field_mismatch.img", 0, 1, 0},
    {"tamper_entry_mismatch.img",     0, 1, 0},
    {"wipe_primary.img",              1, 0, 1},  /* backup-only recovery */
};

static int alloc_count = 0;
static const TSK_VS_PART_INFO *first_alloc = NULL;

static TSK_WALK_RET_ENUM
count_cb(TSK_VS_INFO * vs, const TSK_VS_PART_INFO * p, void *ptr)
{
    (void) vs; (void) ptr;
    if (p->flags & TSK_VS_PART_FLAG_ALLOC) {
        alloc_count++;
        if (first_alloc == NULL)
            first_alloc = p;
    }
    return TSK_WALK_CONT;
}

int
main(int argc, char **argv)
{
    const char *dir;
    size_t i;
    int failures = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <image_dir>\n", argv[0]);
        return 2;
    }
    dir = argv[1];

    for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
        char path[1024];
        TSK_IMG_INFO *img;
        TSK_VS_INFO *vs;
        int opened, crc_err, ok;

        snprintf(path, sizeof(path), "%s/%s", dir, scenarios[i].name);

        img = tsk_img_open_sing(path, TSK_IMG_TYPE_RAW, 512);
        if (img == NULL) {
            printf("[FAIL] %-32s image open failed\n", scenarios[i].name);
            tsk_error_print(stderr);
            failures++;
            continue;
        }

        vs = tsk_vs_open(img, 0, TSK_VS_TYPE_GPT);
        opened = (vs != NULL);
        crc_err =
            (tsk_error_get_errno() == TSK_ERR_VS_CRC) ||
            ((tsk_error_get_errno() & 0xFFFF) ==
                (TSK_ERR_VS_CRC & 0xFFFF));

        if (opened) {
            alloc_count = 0;
            first_alloc = NULL;
            if (tsk_vs_part_walk(vs, 0, vs->part_count - 1,
                    TSK_VS_PART_FLAG_ALL, count_cb, NULL)) {
                printf("[FAIL] %-32s walk error\n", scenarios[i].name);
                tsk_error_print(stderr);
                failures++;
                tsk_vs_close(vs);
                tsk_img_close(img);
                continue;
            }
        }

        ok = 1;
        if (opened != scenarios[i].expect_open)
            ok = 0;
        if (!scenarios[i].expect_open && scenarios[i].expect_crc_err &&
            !crc_err)
            ok = 0;
        if (opened && alloc_count < scenarios[i].min_alloc_parts)
            ok = 0;

        if (ok)
            printf("[PASS] %-32s open=%d crc_err=%d alloc_parts=%d\n",
                scenarios[i].name, opened, crc_err, alloc_count);
        else {
            printf("[FAIL] %-32s open=%d (want %d) crc_err=%d (want %d) "
                "alloc_parts=%d\n", scenarios[i].name, opened,
                scenarios[i].expect_open, crc_err,
                scenarios[i].expect_crc_err, alloc_count);
            failures++;
        }

        if (!opened) {
            printf("       reported error: ");
            tsk_error_print(stdout);
        }
        else if (first_alloc) {
            printf("       first alloc part: start=%" PRIuDADDR
                " len=%" PRIuDADDR " desc=%s\n", first_alloc->start,
                first_alloc->len,
                first_alloc->desc ? first_alloc->desc : "(null)");
        }

        if (vs)
            tsk_vs_close(vs);
        tsk_img_close(img);
        tsk_error_reset();
    }

    printf("\n%s: %d failure(s)\n",
        failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}

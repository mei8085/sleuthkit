#!/bin/bash
#
# Self-contained builder/runner for the GPT CRC tamper-detection tests.
# Does not require autotools/cppunit. Uses a scratch directory outside the
# source tree for all build artifacts and generated images.
#
# Usage: unit_tests/gpt/run_tests.sh
set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_DIR="$REPO_ROOT/unit_tests/gpt"
BUILD_DIR="${TMPDIR:-/tmp}/tsk_gpt_crc_test"
INC_DIR="$BUILD_DIR/include"

CC="${CC:-gcc}"
CXX="${CXX:-g++}"
CFLAGS="-g -O0 -Wall -Wextra -Wno-unused-parameter"

rm -rf "$BUILD_DIR"
mkdir -p "$INC_DIR/tsk" "$BUILD_DIR/obj" "$BUILD_DIR/images"

# Minimal equivalent of the configure-generated tsk/tsk_incs.h.
cat > "$INC_DIR/tsk/tsk_incs.h" <<'EOF'
#ifndef _TSK_INCS_H
#define _TSK_INCS_H
#include <unistd.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <sys/param.h>
#endif
EOF

BASE_SRC="crc mymalloc tsk_endian tsk_error tsk_list tsk_lock tsk_parse \
    tsk_printf tsk_stack tsk_unicode tsk_version"
IMG_SRC="img_io img_types mult_files raw unsupported_types logical_img"
UTIL_SRC="detect_encryption file_system_utils"
VS_SRC="mm_open mm_part mm_types mm_io dos bsd mac sun gpt"

for name in $BASE_SRC; do
    $CC $CFLAGS -I"$INC_DIR" -I"$REPO_ROOT" \
        -c "$REPO_ROOT/tsk/base/$name.c" -o "$BUILD_DIR/obj/$name.o"
done
for name in $IMG_SRC; do
    $CC $CFLAGS -I"$INC_DIR" -I"$REPO_ROOT" \
        -c "$REPO_ROOT/tsk/img/$name.c" -o "$BUILD_DIR/obj/$name.o"
done
for name in $UTIL_SRC; do
    $CC $CFLAGS -I"$INC_DIR" -I"$REPO_ROOT" -I"$REPO_ROOT/tsk/util" \
        -c "$REPO_ROOT/tsk/util/$name.c" -o "$BUILD_DIR/obj/$name.o"
done
for name in $VS_SRC; do
    $CC $CFLAGS -I"$INC_DIR" -I"$REPO_ROOT" \
        -c "$REPO_ROOT/tsk/vs/$name.c" -o "$BUILD_DIR/obj/$name.o"
done
# tsk_img_open_sing lives in a C++ translation unit.
$CXX $CFLAGS -I"$INC_DIR" -I"$REPO_ROOT" \
    -c "$REPO_ROOT/tsk/img/img_open.cpp" -o "$BUILD_DIR/obj/img_open.o"

# Generate the GPT scenario images (isolated python run).
( cd "$BUILD_DIR" && python3 -I "$TEST_DIR/gen_gpt_images.py" images/ )

# CRC32 known-answer test.
$CC $CFLAGS -I"$INC_DIR" -I"$REPO_ROOT" \
    "$TEST_DIR/crc_kat.c" "$BUILD_DIR/obj/crc.o" -o "$BUILD_DIR/crc_kat"
"$BUILD_DIR/crc_kat"

# GPT open/tamper scenario test.
$CXX $CFLAGS -I"$INC_DIR" -I"$REPO_ROOT" \
    "$TEST_DIR/gpt_crc_test.c" "$BUILD_DIR"/obj/*.o \
    -lpthread -o "$BUILD_DIR/gpt_crc_test"
"$BUILD_DIR/gpt_crc_test" "$BUILD_DIR/images"

echo
echo "All GPT CRC / tamper-detection tests passed."

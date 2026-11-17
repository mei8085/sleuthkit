#!/usr/bin/env python3
"""Generate GPT disk images for the CRC / tamper-detection tests.

Run with: python3 -I gen_gpt_images.py <out_dir>

Each image is 34 sectors of 512 bytes:
  LBA  0     protective MBR
  LBA  1     primary GPT header
  LBA  2-5   primary partition entry array (128 entries x 128 B = 16384 B)
  LBA 28-31  backup partition entry array
  LBA 33     backup GPT header

All checksums are real UEFI CRC32 values (zlib.crc32, polynomial
0x04C11DB7 reflected) so the images are valid GPT disks until a scenario
deliberately tampers with specific bytes.
"""
import os
import struct
import sys
import zlib

SECTOR = 512
ENTRIES = 128
ENT_SIZE = 128
TAB_BYTES = ENTRIES * ENT_SIZE                 # 16384
TAB_SECTORS = TAB_BYTES // SECTOR              # 32
# Layout:
#   LBA 0        protective MBR
#   LBA 1        primary header
#   LBA 2..33    primary entry array (32 sectors)
#   LBA 34..35   partition area (2 sectors)
#   LBA 36..67   backup entry array (32 sectors)
#   LBA 68       backup header
TAB_LBA_PRIMARY = 2
TAB_LBA_BACKUP = 36
NUM_SECTORS = TAB_LBA_BACKUP + TAB_SECTORS + 1   # 69
DISK_LAST = NUM_SECTORS - 1                      # 68
GPT_SIG = b"EFI PART"


def le16(v):
    return struct.pack("<H", v)


def le32(v):
    return struct.pack("<I", v)


def le64(v):
    return struct.pack("<Q", v)


def protective_mbr():
    mbr = bytearray(SECTOR)
    # one partition entry of type 0xEE covering the whole disk
    pe = 0
    mbr[446 + pe + 0] = 0x00          # status
    mbr[446 + pe + 1:446 + pe + 4] = b"\x00\x02\x00"   # CHS start
    mbr[446 + pe + 4] = 0xEE          # GPT protective type
    mbr[446 + pe + 5:446 + pe + 8] = b"\xff\xff\xff"   # CHS end
    mbr[446 + pe + 8:446 + pe + 12] = le32(1)          # LBA start
    mbr[446 + pe + 12:446 + pe + 16] = le32(DISK_LAST) # sectors
    mbr[510] = 0x55
    mbr[511] = 0xAA
    return bytes(mbr)


def make_entry(type_guid, id_guid, first, last, flags, name):
    e = bytearray(ENT_SIZE)
    e[0:16] = type_guid
    e[16:32] = id_guid
    e[32:40] = le64(first)
    e[40:48] = le64(last)
    e[48:56] = le64(flags)
    # UTF-16LE name, max 36 code units
    name16 = name.encode("utf-16-le")[:72]
    e[56:56 + len(name16)] = name16
    return bytes(e)


def make_entry_array():
    tab = bytearray(ENTRIES * ENT_SIZE)
    e0 = make_entry(
        b"\x28\x73\x2a\xc1\x1f\xf8\xd2\x11\xba\x4b\x00\xa0\xc9\x3e\xc9\x3b",
        b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        TAB_LBA_PRIMARY + TAB_SECTORS,      # first usable LBA (34)
        TAB_LBA_BACKUP - 1,                 # last usable LBA (35)
        0, "Test Partition")
    tab[0:ENT_SIZE] = e0
    return bytes(tab)

def make_header(my_lba, alt_lba, tab_lba, tab_crc, disk_guid):
    head = bytearray(SECTOR)
    head[0:8] = GPT_SIG
    head[8:12] = le32(0x00010000)                  # revision 1.0
    head[12:16] = le32(92)                         # header size
    # head[16:20] header CRC, filled below
    head[20:24] = le32(0)                          # reserved
    head[24:32] = le64(my_lba)
    head[32:40] = le64(alt_lba)
    head[40:48] = le64(TAB_LBA_PRIMARY + TAB_SECTORS)   # first usable LBA (34)
    head[48:56] = le64(TAB_LBA_BACKUP - 1)               # last usable LBA (35)
    head[56:72] = disk_guid
    head[72:80] = le64(tab_lba)
    head[80:84] = le32(ENTRIES)
    head[84:88] = le32(ENT_SIZE)
    head[88:92] = le32(tab_crc)
    crc = zlib.crc32(bytes(head[:92])) & 0xFFFFFFFF
    head[16:20] = le32(crc)
    return bytes(head), crc


def table_bytes(sectors, start_lba):
    """Reassemble a multi-sector entry array from the sector map."""
    out = bytearray()
    for i in range(TAB_SECTORS):
        out += sectors[start_lba + i]
    return bytes(out)


def build_image(tamper=None):
    """tamper: None or a callable(sectors dict) that mutates sector bytes."""
    disk_guid = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    tab = make_entry_array()
    tab_crc = zlib.crc32(tab) & 0xFFFFFFFF

    primary_head, ph_crc = make_header(1, DISK_LAST, TAB_LBA_PRIMARY,
        tab_crc, disk_guid)
    backup_head, bh_crc = make_header(DISK_LAST, 1, TAB_LBA_BACKUP,
        tab_crc, disk_guid)

    sectors = {0: protective_mbr(), 1: primary_head, DISK_LAST: backup_head}
    for i in range(TAB_SECTORS):
        chunk = tab[i * SECTOR:(i + 1) * SECTOR]
        # independent copies so tampering one copy never aliases the other
        sectors[TAB_LBA_PRIMARY + i] = bytes(chunk)
        sectors[TAB_LBA_BACKUP + i] = bytes(chunk)

    if tamper is not None:
        tamper(sectors)

    out = bytearray(NUM_SECTORS * SECTOR)
    for lba, data in sectors.items():
        out[lba * SECTOR:(lba + 1) * SECTOR] = data
    return bytes(out), ph_crc, bh_crc, tab_crc


# ---- tamper scenarios ----------------------------------------------------

def tamper_primary_head_crc(sectors):
    """Flip a byte in the primary header without updating its CRC."""
    h = bytearray(sectors[1])
    h[56] ^= 0xFF                    # disk GUID byte, inside CRC coverage
    sectors[1] = bytes(h)


def tamper_backup_head_crc(sectors):
    h = bytearray(sectors[DISK_LAST])
    h[56] ^= 0xFF
    sectors[DISK_LAST] = bytes(h)


def tamper_primary_table_crc(sectors):
    """Flip a byte in the primary entry array (start LBA of entry 0)."""
    s = TAB_LBA_PRIMARY + 32 // SECTOR          # LBA field offset 32
    off = 32 % SECTOR
    b = bytearray(sectors[s])
    b[off] ^= 0x01
    sectors[s] = bytes(b)


def tamper_backup_table_crc(sectors):
    s = TAB_LBA_BACKUP + 32 // SECTOR
    off = 32 % SECTOR
    b = bytearray(sectors[s])
    b[off] ^= 0x01
    sectors[s] = bytes(b)


def tamper_header_field_mismatch(sectors):
    """Both CRCs stay internally valid, but a shared structural field
    differs between primary and backup headers."""
    ph = bytearray(sectors[1])
    ph[40:48] = le64(7)               # first usable LBA changed
    ph[16:20] = le32(0)
    new_crc = zlib.crc32(bytes(ph[:92])) & 0xFFFFFFFF
    ph[16:20] = le32(new_crc)
    sectors[1] = bytes(ph)


def tamper_entry_mismatch(sectors):
    """Both array CRCs stay internally valid, but the backup entry array
    no longer matches the primary one."""
    s = TAB_LBA_BACKUP + 40 // SECTOR          # end LBA field offset 40
    off = 40 % SECTOR
    b = bytearray(sectors[s])
    b[off] ^= 0x01
    sectors[s] = bytes(b)
    # recompute the backup header's table CRC
    tab = table_bytes(sectors, TAB_LBA_BACKUP)
    new_tab_crc = zlib.crc32(tab) & 0xFFFFFFFF
    bh = bytearray(sectors[DISK_LAST])
    bh[88:92] = le32(new_tab_crc)
    bh[16:20] = le32(0)
    new_head_crc = zlib.crc32(bytes(bh[:92])) & 0xFFFFFFFF
    bh[16:20] = le32(new_head_crc)
    sectors[DISK_LAST] = bytes(bh)


def wipe_primary(sectors):
    """Destroy the protective MBR + primary header + primary array,
    leaving a valid backup (backup-only recovery scenario)."""
    for lba in (0, 1):
        sectors[lba] = b"\x00" * SECTOR
    for i in range(TAB_SECTORS):
        sectors[TAB_LBA_PRIMARY + i] = b"\x00" * SECTOR


SCENARIOS = {
    "valid.img": None,
    "tamper_primary_head_crc.img": tamper_primary_head_crc,
    "tamper_backup_head_crc.img": tamper_backup_head_crc,
    "tamper_primary_table_crc.img": tamper_primary_table_crc,
    "tamper_backup_table_crc.img": tamper_backup_table_crc,
    "tamper_header_field_mismatch.img": tamper_header_field_mismatch,
    "tamper_entry_mismatch.img": tamper_entry_mismatch,
    "wipe_primary.img": wipe_primary,
}


def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for name, fn in SCENARIOS.items():
        data, ph_crc, bh_crc, tab_crc = build_image(fn)
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"{name}: {len(data)} bytes, head_crcs={ph_crc:#010x}/"
              f"{bh_crc:#010x} tab_crc={tab_crc:#010x}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")

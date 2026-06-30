#!/usr/bin/env python3

import argparse
from pathlib import Path
import usb
import struct

DFU_DNLOAD      = 1
DFU_ABORT       = 4
CUSTOM_DEMOTE   = 7
CUSTOM_BOOT     = 8
CUSTOM_ARB_CALL = 9
    
def open_device():
    dev = usb.core.find(idProduct=0x1227)

    if not dev:
        raise RuntimeError("no device?")

    srnm = dev.serial_number

    if "PWND:[" not in srnm:
        raise RuntimeError("this is not Pwned DFU device")

    return dev

TRANSFER_SIZE = 0x800

def download(dev, buf):
    offset = 0
    left = len(buf)

    while left:
        curr_len = min(TRANSFER_SIZE, left)

        dev.ctrl_transfer(0x21, DFU_DNLOAD, 0, 0, buf[offset:offset+curr_len], 1000)

        offset += curr_len
        left -= curr_len

        print("\rsent - 0x%x" % (offset), end="")

    print()

    dev.ctrl_transfer(0x21, DFU_DNLOAD, 0, 0, None, 100)

def decrypt_kbag(kbag):
    dev = open_device();
    # for t8020 (A12)
    AES_CRYPTO_CMD = 0x100009BE8
    INSECURE_MEMORY_BASE = 0x19C028C00
    registers = [
        AES_CRYPTO_CMD,            # pc
        0,                         # ret
        0x11,                      # x0
        INSECURE_MEMORY_BASE + 80, # x1
        INSECURE_MEMORY_BASE + 80, # x2
        48,                        # x3
        0x20000200,                # x4
        0,                         # x5
        0,                         # x6
        0,                         # x7
    ]
    registers_bytes = struct.pack('<10Q', *registers)
    payload = registers_bytes + bytes(kbag)
    download(dev, payload)
    response = bytes(dev.ctrl_transfer(0xA1, CUSTOM_ARB_CALL, 0, 0, 80 + 48, 10000)[-48:]) # perform arbitrary call and return 80 + 48 bytes from insecure_memory_base
    iv = response[:16].hex()
    key = response[16:].hex()
    print(f"IV:  {iv}")
    print(f"KEY: {key}")

def do_decrypt_kbag_test(args):
    decrypt_kbag([0xc,0xf,0x5c,0x44,0xcb,0xfe,0x48,0x94,0x67,0x32,0x2d,0x9c,0xca,0x9,0x65,0xdf,0x1e,0xe0,0x4,0x76,0xae,0x5c,0xdf,0x99,0x21,0xb5,0x6a,0x96,0x39,0x9d,0x7f,0x14,0x30,0x61,0x43,0x74,0xd9,0xfd,0x8f,0x3b,0x5a,0x48,0x92,0x4b,0x4e,0x51,0xea,0x44])
    decrypt_kbag([0x48,0xe3,0x65,0x62,0x25,0x56,0x9e,0x1f,0xda,0xc4,0x49,0x55,0xf,0x8f,0x29,0x0,0xba,0xa9,0xd8,0xe5,0x88,0x8,0x5b,0xc6,0x6b,0x8e,0x84,0x9a,0x20,0xb8,0xa5,0xd4,0xee,0x5f,0x52,0x10,0x9d,0x2f,0x7a,0x3b,0xc6,0x8b,0xc4,0x9d,0x26,0xa1,0xd2,0xa3])

def main():
    parser = argparse.ArgumentParser(description="Love is Control")

    subparsers = parser.add_subparsers()

    test_parser = subparsers.add_parser("test", help="decrypt kbag test")
    test_parser.set_defaults(func=do_decrypt_kbag_test)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        exit(-1)

    args.func(args)

if __name__ == "__main__":
    main()

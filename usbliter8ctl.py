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
    payload = registers_bytes + kbag
    download(dev, payload)
    response = bytes(dev.ctrl_transfer(0xA1, CUSTOM_ARB_CALL, 0, 0, 80 + 48, 10000)[-48:]) # perform arbitrary call and return 80 + 48 bytes from insecure_memory_base
    iv = response[:16].hex()
    key = response[16:].hex()
    print(f"IV:  {iv}")
    print(f"KEY: {key}")
    
# usbliter8ctl.py decrypt_kbag "0C0F5C44CBFE489467322D9CCA0965DF1EE00476AE5CDF9921B56A96399D7F1430614374D9FD8F3B5A48924B4E51EA44"
# usbliter8ctl.py decrypt_kbag "48E3656225569E1FDAC449550F8F2900BAA9D8E588085BC66B8E849A20B8A5D4EE5F52109D2F7A3BC68BC49D26A1D2A3"
def do_decrypt_kbag(args):
    kbag = bytearray.fromhex(args.kbag)

    if len(kbag) == 48:
        decrypt_kbag(kbag)
    else:
        print(f"Error: Expected 48 bytes, but got {len(kbag)} bytes.")

def main():
    parser = argparse.ArgumentParser(description="Love is Control")

    subparsers = parser.add_subparsers()

    decrypt_kbag_parser = subparsers.add_parser("decrypt_kbag", help="decrypt kbag")
    decrypt_kbag_parser.set_defaults(func=do_decrypt_kbag)
    decrypt_kbag_parser.add_argument("kbag", type=str)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        exit(-1)

    args.func(args)

if __name__ == "__main__":
    main()

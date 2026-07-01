#!/usr/bin/env python3

import argparse
from pathlib import Path
import usb
import struct
import re

DFU_DNLOAD      = 1
DFU_ABORT       = 4
CUSTOM_DEMOTE   = 7
CUSTOM_BOOT     = 8
CUSTOM_ARB_CALL = 9

AES_CRYPTO_CMD = 0
INSECURE_MEMORY_BASE = 0
MEMCPY = 0

def open_device():
    global AES_CRYPTO_CMD, INSECURE_MEMORY_BASE, MEMCPY

    dev = usb.core.find(idProduct=0x1227)

    if not dev:
        raise RuntimeError("no device?")

    srnm = dev.serial_number

    if "PWND:[" not in srnm:
        raise RuntimeError("this is not Pwned DFU device")
        
    match = re.search(r'CPID:([0-9A-Fa-f]+)', srnm)
    if match:
        CPID = match.group(1)
        if CPID == "8020":
            print("A12")
            AES_CRYPTO_CMD = 0x100009BE8
            INSECURE_MEMORY_BASE = 0x19C028C00
            MEMCPY = 0x100010BD0
        elif CPID == "8030":
            print("A13")
            AES_CRYPTO_CMD = 0x10000a47c
            INSECURE_MEMORY_BASE = 0x19C028A80
            MEMCPY = 0x100011770
        else:
            raise RuntimeError(f"device with CPID {CPID} is not supported")
    else:
        raise RuntimeError("unable to get ECID")

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

        # print("\rsent - 0x%x" % (offset), end="")

    # print()

    dev.ctrl_transfer(0x21, DFU_DNLOAD, 0, 0, None, 100)

def decrypt_kbag(kbag):
    dev = open_device();
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

def arbitrary_read(dev, addr, size):
    registers = [
        MEMCPY,                    # pc
        0,                         # ret
        INSECURE_MEMORY_BASE + 80, # x0
        addr,                      # x1
        size,                      # x2
        0,                         # x3
        0,                         # x4
        0,                         # x5
        0,                         # x6
        0,                         # x7
    ]
    registers_bytes = struct.pack('<10Q', *registers)
    payload = registers_bytes
    download(dev, payload)
    return bytes(dev.ctrl_transfer(0xA1, CUSTOM_ARB_CALL, 0, 0, 80 + size, 10000)[80:])
    
def arbitrary_read_large(dev, addr, size):
    CHUNK_SIZE = 0x7B0
    buf = bytearray(size)
    bytes_read = 0
    while bytes_read < size:
        remaining = size - bytes_read
        current_chunk_size = min(CHUNK_SIZE, remaining)
        chunk = arbitrary_read(dev, addr + bytes_read, current_chunk_size)
        if not chunk:
            return bytes(buf[:bytes_read])
        buf[bytes_read:bytes_read + len(chunk)] = chunk
        bytes_read += len(chunk)
    return bytes(buf)

def do_decrypt_kbag(args):
    kbag = bytearray.fromhex(args.kbag)
    if len(kbag) == 48:
        decrypt_kbag(kbag)
    else:
        print(f"Error: Expected 48 bytes, but got {len(kbag)} bytes.")
        
def do_arbitrary_read(args):
    dev = open_device();
    response = arbitrary_read_large(dev, args.addr, args.size)
    if args.output:
        with open(args.output, "wb") as f:
            f.write(response)
        print(f"Successfully wrote {len(response)} bytes to {args.output}")
    else:
        print(f"Read {len(response)} bytes from 0x{args.addr:X}:")
        print(" ".join(f"{b:02X}" for b in response))

def main():
    parser = argparse.ArgumentParser(description="Love is Control")

    subparsers = parser.add_subparsers()

    decrypt_kbag_parser = subparsers.add_parser("decrypt_kbag", help="decrypt kbag")
    decrypt_kbag_parser.set_defaults(func=do_decrypt_kbag)
    decrypt_kbag_parser.add_argument("kbag", type=str)
    
    arbitrary_read_parser = subparsers.add_parser("read", help="arbitrary read")
    arbitrary_read_parser.set_defaults(func=do_arbitrary_read)
    arbitrary_read_parser.add_argument("addr", type=lambda x: int(x, 0))
    arbitrary_read_parser.add_argument("size", type=lambda x: int(x, 0))
    arbitrary_read_parser.add_argument("-o", "--output", type=Path)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        exit(-1)

    args.func(args)

if __name__ == "__main__":
    main()

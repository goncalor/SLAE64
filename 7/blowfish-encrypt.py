#!/usr/bin/env python3
import sys
import blowfish
from os import urandom

key = bytes(sys.argv[1], 'utf-8')
shellcode = bytes.fromhex(sys.argv[2].replace('\\x', ''))

iv = b'\x00\x00\x00\x00\x00\x00\x00\x00' #urandom(8)
cipher = blowfish.Cipher(key)
blocks = cipher.encrypt_cfb(shellcode, iv)

output = []
for block in blocks:
    for byte in block:
        output.append(byte)

print()
print(''.join(['\\x{:02x}'.format(b) for b in output]))
print()
print(','.join(['0x{:02x}'.format(b) for b in output]))

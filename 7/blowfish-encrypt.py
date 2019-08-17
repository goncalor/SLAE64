#!/usr/bin/env python3
import sys
import blowfish
from os import urandom

key = bytes(sys.argv[1], 'utf-8')
shellcode = bytes.fromhex(sys.argv[2].replace('\\x', ''))

iv = urandom(8)
cipher = blowfish.Cipher(key)
blocks = cipher.encrypt_cfb(shellcode, iv)

output = []
for block in blocks:
    for byte in block:
        output.append(byte)

print()
print(''.join([hex(b) for b in output]).replace('0x', '\\x'))
print()
print(','.join([hex(b) for b in output]))

#!/usr/bin/env python3
import sys

shellcode = bytes.fromhex(sys.argv[1].replace('\\x', ''))

output = [0xaa]
for b in shellcode:
    xored_byte = b ^ output[-1]
    output.append(xored_byte)

output = bytes(output)

print()
print(''.join([hex(b) for b in output]).replace('0x', '\\x'))
print()
print(','.join([hex(b) for b in output]))

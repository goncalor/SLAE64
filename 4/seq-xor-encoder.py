#!/usr/bin/env python3
import sys
from random import randint

shellcode = bytes.fromhex(sys.argv[1].replace('\\x', ''))

if len(sys.argv) == 3:
    output = [int(sys.argv[2], 0)]
else:
    output = [randint(1, 255)]

for b in shellcode:
    xored_byte = b ^ output[-1]
    output.append(xored_byte)

output = bytes(output)

print()
print(''.join([hex(b) for b in output]).replace('0x', '\\x'))
print()
print(','.join([hex(b) for b in output]))

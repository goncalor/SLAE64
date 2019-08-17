#!/usr/bin/env python3
import sys
import blowfish
from os import urandom

key = bytes(sys.argv[1], 'utf-8')
# shellcode = bytes.fromhex(sys.argv[2].replace('\\x', ''))

enc = r"\x3\x89\xc1\xa0\xbf\xb6\xdb\x63\xa8\xa2\xb3\x21\x18\xe\x2e\x42\xdc\x7a\x58\x12\x13\xe5\xb3\x7e\xed\x33"

iv = b'\x00\x00\x00\x00\x00\x00\x00\x00' #urandom(8)
cipher = blowfish.Cipher(key)
blocks = cipher.decrypt_cfb(enc, iv)

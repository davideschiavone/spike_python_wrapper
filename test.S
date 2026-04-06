.section .boot, "ax"
.global _boot
_boot:
    la t0, _start
    jr t0

.section .rodata, "a"
.align 2
val_init: .float 1.0
val_incr: .float 3.3

.section .text, "ax"
.global _start

_start:

    li x5, 0x6000 #(0x11 << 13)
    csrs mstatus, x5

    li x1, 0
    li x2, 10

    la x3, val_init
    la x4, val_incr
    flw f3, 0(x3)
    flw f4, 0(x4)


loop:
    addi x1, x1, 1
    fadd.s f3, f3, f4
    blt x1, x2, loop

    ecall               

finish:
    j finish
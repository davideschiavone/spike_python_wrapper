/* ========================================================================
   Test Program for RISC-V Spike Wrapper
   
   This program is compatible with both RV32 and RV64 targets.
   It performs:
   1. Setting up privilege mode (machine mode)
   2. Integer arithmetic operations
   3. Floating-point operations (if F extension enabled)
   4. Loop execution
   5. System call (ecall) to terminate
   
   Compilation:
   - RV32: riscv64-unknown-elf-gcc -march=rv32imac -mabi=ilp32d -T link.ld test.S -o test.elf
   - RV64: riscv64-unknown-elf-gcc -march=rv64gc -mabi=lp64d -T link.ld test.S -o test.elf
   
   ======================================================================== */
//#define USE_FLOATING_POINT

.section .boot, "ax"
.global _boot
_boot:
    /* Bootstrap: load _start address and jump to it */
    la t0, _start
    jr t0


.section .rodata, "a"
.align 2
#ifdef USE_FLOATING_POINT
val_init: .float 1.0
val_incr: .float 3.3
val_result: .float 0.0
#else
val_init: .word 1
val_incr: .word 3
val_result: .word 0
#endif

.section .text, "ax"
.global _start

_start:

    /* ====================================================================
       Step 1: Set Machine Mode Status Register
       
       This sets the Floating-Point Unit Enable (FPU) and Machine 
       Interrupt Enable (MIE) bits in the mstatus register.
       
       mstatus bit layout:
       - Bits [14:13]: FS (FP State): 01 = initial state
       - Bits [3:3]: MIE (M-mode interrupt enable)
       
       0x6000 = 0110 0000 0000 0000 (binary)
       This sets FS=11 (dirty state) for FPU access
       ==================================================================== */
#ifdef USE_FLOATING_POINT
    li x5, 0x6000          /* Load immediate 0x6000 into x5 */
    csrs mstatus, x5       /* Set bits in mstatus from x5 */
#endif
    /* ====================================================================
       Step 2: Initialize working registers
       ==================================================================== */
    li x1, 0               /* x1 = 0 (loop counter) */
    li x2, 10              /* x2 = 10 (loop limit) */

    /* ====================================================================
       Step 3: Load initial floating-point values
       
       Load two single-precision floats:
       - f3 = 1.0 (initial accumulator)
       - f4 = 3.3 (increment per iteration)
       ==================================================================== */
    la x3, val_init        /* Load address of val_init into x3 */
    la x4, val_incr        /* Load address of val_incr into x4 */
#ifdef USE_FLOATING_POINT
    flw f3, 0(x3)          /* Load float from [x3] into f3 (1.0) */
    flw f4, 0(x4)          /* Load float from [x4] into f4 (3.3) */
#else
     lw x3, 0(x3)           /* Load word from [x3] */
     lw x4, 0(x4)           /* Load word from [x4] */
 #endif

    /* ====================================================================
       Step 4: Main Loop
       
       Perform 10 iterations, accumulating sum of floating-point values.
       Each iteration:
       1. Increment counter x1
       2. Add increment to f3
       3. Branch back if counter < limit
       
       After 10 iterations:
       f3 = 1.0 + (3.3 * 10) = 34.0
       ==================================================================== */
loop:
    addi x1, x1, 1         /* x1 = x1 + 1 (increment counter) */

#ifdef USE_FLOATING_POINT
    fadd.s f3, f3, f4      /* f3 = f3 + f4 (floating-point add) */
#else
    add x3, x3, x4         /* x3 = x3 + x4 (integer add) */
#endif
    blt x1, x2, loop       /* Branch to loop if x1 < x2 */

   la x4, val_result      /* Load address of val_result into x4 */

#ifdef USE_FLOATING_POINT
   fsw f3, 0(x4)          /* Store float from f3 into [x4] */
#else
   sw  x3, 0(x4)           /* Store word from x3 into [x4] */
#endif

    /* ====================================================================
       Step 5: System Call
       
       Call ecall to request Spike/OS to terminate the simulation.
       This will typically trigger a machine-mode exception that Spike
       handles as a termination signal.
       ==================================================================== */
    ecall                  /* System call: terminate */

    /* ====================================================================
       Step 6: Infinite Loop (fallback, should not reach here)
       ==================================================================== */
finish:
    j finish               /* Jump to self forever */

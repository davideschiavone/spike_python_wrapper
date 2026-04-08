/* ========================================================================
   RISC-V Linker Script
   
   This linker script is compatible with both RV32 and RV64 targets.
   It defines a memory layout with:
   - 4 KB Boot ROM (0x00001000)
   - 16 MB RAM (0x80000000)
   
   The boot code will jump from ROM to the main program in RAM.
   
   ======================================================================== */

MEMORY
{
  ROM (rx)  : ORIGIN = 0x00001000, LENGTH = 0x1000         /* 4 KB Bootstrap ROM */
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 16M             /* 16 MB Main Memory */
}

SECTIONS
{
  /* ====================================================================
     1. Bootstrap Code (.boot section)
     
     Executed at reset (vector 0x1000).
     Performs minimal initialization and jumps to _start.
     ===================================================================== */
  .boot : {
    KEEP(*(.boot))
  } > ROM

  /* ====================================================================
     2. Main Program Code
     ===================================================================== */
  .text : {
    . = ALIGN(4);
    *(.text)
    *(.text.*)
  } > RAM

  /* ====================================================================
     3. Read-Only Data (Constants, String Literals)
     ===================================================================== */
  .rodata : {
    . = ALIGN(8);
    *(.rodata)
    *(.rodata.*)
    *(.srodata)
    *(.srodata.*)
  } > RAM

  /* ====================================================================
     4. Initialized Data (Global Variables with Initial Values)
     ===================================================================== */
  .data : {
    . = ALIGN(8);
    *(.data)
    *(.data.*)
    *(.sdata)
    *(.sdata.*)
  } > RAM

  /* ====================================================================
     5. Uninitialized Data (BSS - Zero-Initialized at Startup)
     ===================================================================== */
  .bss : {
    . = ALIGN(8);
    *(.bss)
    *(.bss.*)
    *(.sbss)
    *(.sbss.*)
    *(COMMON)
  } > RAM

  /* ====================================================================
     6. Spike Host Communication
     
     Used by Spike's HTIF (Host-Target Interface) for console I/O
     and host feature detection.
     ===================================================================== */
  .tohost : {
    *(.tohost)
  } > RAM
}

import struct
import sys
import traceback
import os

# ============================================================================
# libstdc++ preload — Anaconda / conda-forge compatibility fix
# ============================================================================
# Anaconda ships its own libstdc++.so.6 which is often older than the one
# used to compile cve2_py.so (the system GCC).  When Python (from Anaconda)
# dlopen()s cve2_py.so it resolves libstdc++ against Anaconda's copy first,
# which may lack newer GLIBCXX_3.4.x symbols, producing:
#
#   version `GLIBCXX_3.4.32' not found
#
# Fix: preload the system libstdc++ with RTLD_GLOBAL *before* importing
# cve2_py so the dynamic linker picks up the correct version.
# We locate it via ldconfig rather than hard-coding a path.
# This is a no-op on systems where Anaconda's libstdc++ is already new
# enough, or where the user is not using Anaconda at all.

def _preload_system_libstdcxx() -> None:
    import ctypes
    import ctypes.util
    import subprocess

    # First try the standard ctypes search (works when LD_LIBRARY_PATH is
    # already pointing at the system lib).
    path = ctypes.util.find_library("stdc++")
    if path and "conda" not in path and "anaconda" not in path.lower():
        try:
            ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL)
            return
        except OSError:
            pass

    # Fall back to asking ldconfig for the full path of the system libstdc++.
    try:
        out = subprocess.check_output(
            ["ldconfig", "-p"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            if "libstdc++.so.6" in line and "=>" in line:
                candidate = line.split("=>")[-1].strip()
                # Skip anything inside conda/anaconda trees
                if "conda" in candidate.lower() or "anaconda" in candidate.lower():
                    continue
                try:
                    ctypes.CDLL(candidate, mode=ctypes.RTLD_GLOBAL)
                    return
                except OSError:
                    continue
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass  # ldconfig not available (macOS, some containers) — silently skip

_preload_system_libstdcxx()

# Get the path to the folder containing spike_py.so
wrapper_path = os.path.abspath("./spike_wrapper")

if wrapper_path not in sys.path:
    sys.path.append(wrapper_path)

import spike_py

# ============================================================================
# ABI Register Names
# ============================================================================

ABI = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
]

# ============================================================================
# RISC-V CSR Map
# ============================================================================

RISCV_CSR_MAP = {
    # User-Level CSRs
    0x001: "fflags",    0x002: "frm",       0x003: "fcsr",
    0xC00: "cycle",     0xC01: "time",      0xC02: "instret",

    # Supervisor-Level CSRs
    0x100: "sstatus",   0x104: "sie",       0x105: "stvec",
    0x106: "scounteren",0x140: "sscratch",  0x141: "sepc",
    0x142: "scause",    0x143: "stval",     0x144: "sip",
    0x180: "satp",      0x10A: "senvcfg",

    # Machine-Level CSRs
    0x300: "mstatus",   0x301: "misa",      0x302: "medeleg",
    0x303: "mideleg",   0x304: "mie",       0x305: "mtvec",
    0x306: "mcounteren",0x340: "mscratch",  0x341: "mepc",
    0x342: "mcause",    0x343: "mtval",     0x344: "mip",
    0xB00: "mcycle",    0xB02: "minstret",
    0xF11: "mvendorid", 0xF12: "marchid",   0xF13: "mimpid",
    0xF14: "mhartid",
    0xF15: "mconfigptr",
    0x310: "mstatush",   0x31a: "mconfigptr",
    0x3b0: "pmpcfg0",   0x3b1: "pmpcfg1",   0x3b2: "pmpcfg2",   0x3b3: "pmpcfg3",


    # Interrupt and Delegation
    0x30A: "menvcfg",

    # Performance Monitoring Counter Enablers
    0x320: "mcountinhibit",
    0xB80: "mcycle",
    0xB82: "mcountinhibit",

    # Debug / Triggers
    0x7A0: "tselect",    0x7A1: "tdata1",     0x7A2: "tdata2",     0x7A3: "tdata3",
    0x7A4: "tinfo",
    0x7a8: "tcontrol",

    0x7B0: "dcsr",       0x7B1: "dpc",        0x7B2: "dscratch0",  0x7B3: "dscratch1",

    0x5A8: "senvcfg",
    0x747: "mseccfg",
    0x757: "mseccfgh",
    0x008: "vstart",
    0x009: "vxsat",
    0x00A: "vxrm",
    0x00F: "vcsr",

    0xC20: "custom_cache_info",
    0xC21: "mhpmcounter3h",
    0xC22: "mhpmcounter4h",
}

# ============================================================================
# Utility Functions
# ============================================================================

def hex_to_float(h):
    """Convert 64-bit hex to 32-bit float (using lower 32 bits)"""
    low_32 = h & 0xffffffff
    return struct.unpack('!f', struct.pack('!I', low_32))[0]


def format_reg_value(value, xlen):
    """
    Format a register value with proper width based on XLEN.
    
    Args:
        value: Register value (as integer)
        xlen: Register width (32 or 64)
    
    Returns:
        Formatted hex string
    """
    if xlen == 32:
        # For RV32, mask to 32 bits and format as 8 hex digits
        value = value & 0xffffffff
        return f"0x{value:08x}"
    else:
        # For RV64, format as 16 hex digits
        return f"0x{value:016x}"


def print_state(bridge):
    """
    Print current processor state (GPRs, FPRs, CSRs) in XLEN-aware format.
    
    Args:
        bridge: SpikeBridge instance
    """
    xlen = bridge.get_xlen()
    
    print(f"--- XLEN: {xlen} bits ---")
    
    # ========================================================================
    # GPR Display
    # ========================================================================
    print(f"--- GPRs ---")
    
    if xlen == 32:
        # RV32: Display as 4 registers per row
        for i in range(32):
            val = bridge.get_reg(i)
            print(f"x{i:02}: {format_reg_value(val, 32)}", end="  " if (i+1) % 4 != 0 else "\n")
    else:
        # RV64: Display as 4 registers per row
        for i in range(32):
            val = bridge.get_reg(i)
            print(f"x{i:02}: {format_reg_value(val, 64)}", end="  " if (i+1) % 4 != 0 else "\n")

    # ========================================================================
    # FPR Display
    # ========================================================================
    print(f"\n--- FPRs ---")
    
    if xlen == 32:
        # For RV32, use only lower 32 bits for single-precision floats
        for i in range(32):
            val = bridge.get_fp_reg(i)
            fval = hex_to_float(val)
            print(f"f{i:02}: {format_reg_value(val, 32)} ({fval:>8.4f})", 
                  end="  " if (i+1) % 2 != 0 else "\n")
    else:
        # For RV64, display full 64-bit value
        for i in range(32):
            val = bridge.get_fp_reg(i)
            fval = hex_to_float(val)
            print(f"f{i:02}: {format_reg_value(val, 64)} ({fval:>8.4f})", 
                  end="  " if (i+1) % 2 != 0 else "\n")

    # ========================================================================
    # CSR Display
    # ========================================================================
    print(f"\n--- CSRs ---")
    csrs = bridge.get_csrs()

    # Sort by address for clean output
    for addr in sorted(csrs.keys()):
        name = RISCV_CSR_MAP.get(addr, f"csr_0x{addr:03x}")
        val = csrs[addr]
        formatted_val = format_reg_value(val, xlen)
        print(f"{name:10} (0x{addr:03x}): {formatted_val}")


def populate_csr_map():
    """Populate additional CSR addresses dynamically"""
    # Add missing PMP address CSRs to the map
    for i in range(4, 64):
        RISCV_CSR_MAP[0x3B0 + i] = f"pmpaddr{i}"
    
    # Add missing performance monitoring counters
    for i in range(3, 32):
        RISCV_CSR_MAP[0xB00 + i] = f"mhpmcounter{i}"
    
    # Add missing pmpcfg0 - pmpcfg15 (0x3A0 - 0x3AF)
    for i in range(16):
        RISCV_CSR_MAP[0x3A0 + i] = f"pmpcfg{i}"

    # Add Event Selectors (mhpmevent3 to mhpmevent31)
    for i in range(3, 32):
        if 0x320 + i not in RISCV_CSR_MAP:
            RISCV_CSR_MAP[0x320 + i] = f"mhpmevent{i}"
    for i in range(3, 32):
            addr = 0xb80 + i
            if addr not in RISCV_CSR_MAP:
                RISCV_CSR_MAP[addr] = f"mhpmcounter{i}"

def run_trace(target, isa, max_steps=100):
    """
    Run the Spike simulator trace for a given target and ISA.
    
    Args:
        target: Program name (without extension, e.g., 'test')
        isa: ISA string (e.g., 'rv32imac' or 'rv64gcv_zba_zbb_zbs_zicond_zfa_zcb')
        max_steps: Maximum number of instructions to execute
    
    Raises:
        FileNotFoundError: If ELF or hex files are missing
        RuntimeError: If Spike initialization fails
    """
    populate_csr_map()

    print(f"\n{'='*95}")
    print(f" SPIKE TRACER - Running : {target}")
    print(f" ISA Configuration     : {isa}")
    print(f"{'='*95}\n")

    try:
        # ====================================================================
        # 1. Initialize Spike with ISA configuration
        # ====================================================================
        sim = spike_py.SpikeBridge(target, isa)
        
        xlen = sim.get_xlen()
        detected_isa = sim.get_isa()
        
        print(f"[*] Simulator initialized successfully")
        print(f"    - XLEN: {xlen} bits")
        print(f"    - ISA: {detected_isa}")

        # ====================================================================
        # 2. Print Vector Unit Info (if available)
        # ====================================================================
        try:
            vlen = sim.get_vlen()
            elen = sim.get_elen()
            print(f"\n[*] SPIKE Vector Unit Info:")
            print(f"    - VLEN: {vlen} bits")
            print(f"    - ELEN: {elen} bits")
        except Exception:
            print(f"\n[*] Vector Unit not available (ISA does not include 'V' extension)")

        print(f"\n[*] Initial PC: {format_reg_value(sim.get_pc(), xlen)}")

        # ====================================================================
        # 3. Check RAM state
        # ====================================================================
        print("\n[*] Checking RAM state (first 4 words):")
        sim.dump_memory(0x80000000, 4)

        # ====================================================================
        # 4. Print Initial Processor State
        # ====================================================================
        print("[*] Checking GPRs and CSRs state:")
        print_state(sim)

        # ====================================================================
        # 5. Execution Loop
        # ====================================================================
        print(f"{'ORD':<4} | {'PC':<12} | {'INSTRUCTION':<28} | {'REGISTER CHANGES'}")
        print("-" * 95)

        # Capture initial register state
        last_regs = [sim.get_reg(i) for i in range(32)]
        
        for step in range(1, max_steps + 1):
            current_pc = sim.get_pc()
            instr_str = sim.get_disasm().strip()
            
            # Execute one instruction
            sim.step()
            
            # Check for register changes
            changes = []
            for i in range(32):
                new_val = sim.get_reg(i)
                if new_val != last_regs[i]:
                    formatted = format_reg_value(new_val, xlen)
                    changes.append(f"{ABI[i]}: {formatted}")
                    last_regs[i] = new_val
            
            change_log = ", ".join(changes) if changes else "-"
            pc_str = format_reg_value(current_pc, xlen)
            print(f"{step:<4} | {pc_str:<12} | {instr_str:<28} | {change_log}")

            # ================================================================
            # 6. Stop Condition: PC doesn't advance
            # ================================================================
            if sim.get_pc() == current_pc:
                print("\n[STOP] Instruction loop detected or simulation stopped.")
                
                print("\n[*] Final processor state:")
                print_state(sim)
                break

    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR]: {e}")
        traceback.print_exc()
        sys.exit(1)
    
    print(f"\n{'='*95}")


def check_files(target):
    """
    Verify that both .elf and .hex files exist for the given target.
    
    Args:
        target: Program name (without extension)
    
    Raises:
        FileNotFoundError: If any required file is missing
    """
    elf_file = f"{target}.elf"
    hex_file = f"{target}.hex"

    missing = []
    if not os.path.isfile(elf_file):
        missing.append(elf_file)
    if not os.path.isfile(hex_file):
        missing.append(hex_file)

    if missing:
        raise FileNotFoundError(
            f"\n[PYTHON ERROR] Required files not found for target '{target}':\n"
            f" -> Missing: {', '.join(missing)}\n"
            f"Please run 'make {target}' to generate these files before execution."
        )


# ============================================================================
# ISA String Examples
# ============================================================================

ISA_EXAMPLES = {
    "rv32imac": "32-bit RISC-V with Multiply, Atomic, Compressed",
    "rv32imafc": "32-bit RISC-V with Multiply, Atomic, Float (single), Compressed",
    "rv64imac": "64-bit RISC-V with Multiply, Atomic, Compressed",
    "rv64imafc": "64-bit RISC-V with Multiply, Atomic, Float (double), Compressed",
    "rv64gc": "64-bit RISC-V with General-purpose (G = IMAFD + C)",
    "rv64gcv_zba_zbb_zbs_zicond_zfa_zcb": "64-bit RISC-V with G + Vector + bit manipulation + transcendental + compressed bit",
}


def main():
    """
    Main entry point for the Spike tracer.
    
    Usage:
        python trace_spike.py <target> [isa]
    
    Examples:
        python trace_spike.py test                                          # Uses default ISA
        python trace_spike.py test rv64gc                                   # 64-bit with G extension
        python trace_spike.py test rv32imac                                 # 32-bit with IMAC
        python trace_spike.py test rv64gcv_zba_zbb_zbs_zicond_zfa_zcb       # 64-bit with vectors
    """
    
    if len(sys.argv) < 2:
        print("\n[USAGE] python trace_spike.py <target> [isa]")
        print("\n[EXAMPLES]")
        print(f"  python trace_spike.py test")
        print(f"  python trace_spike.py test rv64gc")
        print(f"  python trace_spike.py test rv32imac")
        print(f"\n[ISA EXAMPLES]")
        for isa, desc in ISA_EXAMPLES.items():
            print(f"  {isa:45} # {desc}")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Default ISA based on availability; can be overridden via command line
    default_isa = "rv64gcv_zba_zbb_zbs_zicond_zfa_zcb"
    isa = sys.argv[2] if len(sys.argv) > 2 else default_isa
    
    try:
        # Verify files exist before attempting simulation
        check_files(target)
        
        # Run the trace with the specified ISA
        run_trace(target, isa)
    
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)
    except Exception as e:
        print(f"[UNEXPECTED ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

import struct
import spike_py
import sys
import traceback
import os

# Mappa nomi ABI per i registri
ABI = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
]

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
    0xF15: "mconfigptr", # Machine Configuration Pointer (RISC-V 1.12+)

    # Interrupt and Delegation
    0x30A: "menvcfg",    # Machine Environment Configuration

    # Performance Monitoring Counter Enablers
    0x320: "mcountinhibit", # Controls which counters can increment

    # Debug / Triggers
    0x7A0: "tselect",    0x7A1: "tdata1",     0x7A2: "tdata2",     0x7A3: "tdata3",
    0x7A4: "tinfo",
    0x7a8: "tcontrol",

    0x7B0: "dcsr",       0x7B1: "dpc",        0x7B2: "dscratch0",  0x7B3: "dscratch1",

    0x5A8: "senvcfg",
    0x747: "mseccfg",

    0x008: "vstart",
    0x009: "vxsat",
    0x00A: "vxrm",
    0x00F: "vcsr",

    0xC20: "custom_cache_info", # custom CSR for cache information (example of a custom CSR)
    0xC21: "mhpmcounter3h",
    0xC22: "mhpmcounter4h",
}

def hex_to_float(h):
    low_32 = h & 0xffffffff
    return struct.unpack('!f', struct.pack('!I', low_32))[0]


def print_state(bridge):
    print(f"--- GPRs ---")
    for i in range(32):
        print(f"x{i:02}: 0x{bridge.get_reg(i):016x}", end="  " if (i+1)%4 != 0 else "\n")

    print(f"--- FPRs ---")
    for i in range(32):
        # print(f"fp{i:02}: 0x{bridge.get_fp_reg(i):016x}", end="  " if (i+1)%4 != 0 else "\n")
        val = bridge.get_fp_reg(i)
        print(f"f{i:02}: 0x{val:016x} ({hex_to_float(val):>8.4f})", end="  " if (i+1)%2 != 0 else "\n")

    print(f"\n--- CSRs ---")
    csrs = bridge.get_csrs() # This returns a dict {int: int}

    # Sort by address for a clean output
    for addr in sorted(csrs.keys()):
        name = RISCV_CSR_MAP.get(addr, f"csr_0x{addr:03x}")
        val = csrs[addr]
        print(f"{name:10} (0x{addr:03x}): 0x{val:x}")

def run_trace(target, max_steps=100):

    #add missing PMP address CSRs to the map
    for i in range(4, 64):
        RISCV_CSR_MAP[0x3B0 + i] = f"pmpaddr{i}"
    # add missing performance monitoring counters to the map
    for i in range(3, 32):
        RISCV_CSR_MAP[0xB00 + i] = f"mhpmcounter{i}"
    # add missing pmpcfg0 - pmpcfg15 (0x3A0 - 0x3AF)
    for i in range(16):
        RISCV_CSR_MAP[0x3A0 + i] = f"pmpcfg{i}"
    #add missing pmpaddr0 - pmpaddr63 (0x3B0 - 0x3FF)
    for i in range(64):
        RISCV_CSR_MAP[0x3B0 + i] = f"pmpaddr{i}"

    # add Event Selectors (mhpmevent3 to mhpmevent31)
    for i in range(3, 32):
        if 0x320 + i not in RISCV_CSR_MAP:
            RISCV_CSR_MAP[0x320 + i] = f"mhpmevent{i}"


    print(f"\n{'='*95}")
    print(f" SPIKE TRACER - Running : {target}")
    print(f"{'='*95}\n")

    try:

        sim = spike_py.SpikeBridge(target)
        
        print("SPIKE Vector Unit Info:")
        print(f"  VLEN: {sim.get_vlen()} bits")
        print(f"  ELEN: {sim.get_elen()} bits")


        print(f"[*] Initial PC: {hex(sim.get_pc())}")

        print("[*] Checking RAM state:")
        sim.dump_memory(0x00001000, 4)

        print("[*] Checking GPRs and CSRs state:")
        print_state(sim)

        print(f"{'ORD':<4} | {'PC':<12} | {'INSTRUCTION':<28} | {'REGISTER CHANGES'}")
        print("-" * 95)

        last_regs = [sim.get_reg(i) for i in range(32)]
        for step in range(1, max_steps + 1):
            current_pc = sim.get_pc()
            instr_str = sim.get_disasm().strip()
            
            # execute one istruction
            sim.step()
            
            # check changes in registers
            changes = []
            for i in range(32):
                new_val = sim.get_reg(i)
                if new_val != last_regs[i]:
                    changes.append(f"{ABI[i]}: {hex(new_val)}")
                    last_regs[i] = new_val
            
            change_log = ", ".join(changes) if changes else "-"
            print(f"{step:<4} | {hex(current_pc):<12} | {instr_str:<28} | {change_log}")

            # Se il PC non avanza, stop
            if sim.get_pc() == current_pc:
                print("\n[STOP] Instruction loop detected or simulation stopped.")

                print("[*] Print final state:")
                print_state(sim)

                break

    except Exception as e:
        print(f"\n[ERROR]: {e}")
        traceback.print_exc()
    
    print(f"\n{'='*95}")


def check_files(target):
    """
    Verify that both .elf and .hex files exist for the given target.
    Raises FileNotFoundError if any file is missing.
    """
    elf_file = f"{target}.elf"
    hex_file = f"{target}.hex"

    missing = []
    if not os.path.isfile(elf_file):
        missing.append(elf_file)
    if not os.path.isfile(hex_file):
        missing.append(hex_file)

    if missing:
        # Raise detailed exception for missing dependencies
        raise FileNotFoundError(
            f"\n[PYTHON ERROR] Required files not found for target '{target}':\n"
            f" -> Missing: {', '.join(missing)}\n"
            f"Please run 'make firmware' to generate these files before execution."
        )

if __name__ == "__main__":

    target = sys.argv[1] if len(sys.argv) > 1 else "test"
    try:
        # 2. Pre-execution file validation
        check_files(target)

        # 3. Execute the trace if files are present
        run_trace(target)

    except FileNotFoundError as e:
        # Handle missing files gracefully
        print(e)
        sys.exit(1)
    except Exception as e:
        # Handle unexpected runtime errors
        print(f"[UNEXPECTED ERROR] {e}")
        sys.exit(1)

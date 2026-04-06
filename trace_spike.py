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

def run_trace(target, max_steps=100):
    print(f"\n{'='*95}")
    print(f" SPIKE TRACER - Running : {target}")
    print(f"{'='*95}\n")
    
    try:

        sim = spike_py.SpikeBridge(target)
        
        print(f"[*] Initial PC: {hex(sim.get_pc())}")

        print("[*] Checking RAM state:")
        sim.dump_memory(0x00001000, 4)

        print("[*] Checking RF state:")
        last_regs = [sim.get_reg(i) for i in range(32)]
        for i, val in enumerate(last_regs):
            print(f"  {ABI[i]:>4}: {hex(val)}")

        print(f"{'ORD':<4} | {'PC':<12} | {'INSTRUCTION':<28} | {'REGISTER CHANGES'}")
        print("-" * 95)

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

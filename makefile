# ============================================================================
# RISC-V Spike Wrapper - Configurable Makefile
# ============================================================================
# This Makefile supports building both RV32 and RV64 targets with
# various ISA extensions.
#
# USAGE:
#   make test                    # Compile test program with default ISA
#   make test MARCH=-march=rv32imac
#   make test MARCH=-march=rv64gc
#   make spike_wrapper           # Compile Python wrapper
#   make clean                   # Remove generated files
#
# ============================================================================

# ============================================================================
# Toolchain Configuration
# ============================================================================

RISCV_BIN       := $(RVA23_COMPILER)/bin/

# Automatically detect the compiler prefix
# It checks for riscv64-unknown-elf-gcc first; if missing, it switches to any found GCC

DETECTED_GCC    := $(firstword $(shell ls $(RISCV_BIN)*-elf-gcc 2>/dev/null))
CROSS_COMPILE   := $(subst gcc,,$(DETECTED_GCC))

# Extract XLEN (32 or 64) from the prefix for use in your C++/SystemVerilog code
# This searches the string for '64' or '32'
ifneq (,$(findstring 64,$(CROSS_COMPILE)))
    XLEN := 64
else
    XLEN := 32
endif

# Fallback check
ifeq ($(CROSS_COMPILE),)
$(error No RISC-V toolchain found in $(RISCV_BIN))
endif

AS              := $(CROSS_COMPILE)as
CC              := $(CROSS_COMPILE)gcc
LD              := $(CROSS_COMPILE)ld
OBJCOPY         := $(CROSS_COMPILE)objcopy
OBJDUMP         := $(CROSS_COMPILE)objdump

# ============================================================================
# ISA Configuration
# ============================================================================
# Default ISA: rv64gc with additional extensions
# Override with: make test MARCH="-march=rv32imac -mabi=ilp32d"

MARCH           ?= -march=rv64gcv_zba_zbb_zbs_zicond_zfa_zcb -mabi=lp64d
ABI_FLAG        := $(word 2, $(MARCH))

# If no ABI specified in MARCH, infer from -march
ifeq ($(ABI_FLAG),)
    ifeq ($(findstring rv32, $(MARCH)), rv32)
        MARCH += -mabi=ilp32d
    else
        MARCH += -mabi=lp64d
    endif
endif

# ============================================================================
# Linker Configuration
# ============================================================================

LDFLAGS         := -T link.ld -nostdlib -nostartfiles -static

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean wrapper test help

all: test spike_wrapper

help:
	@echo "=========================================================================="
	@echo "RISC-V Spike Wrapper - Configurable Build"
	@echo "=========================================================================="
	@echo ""
	@echo "USAGE:"
	@echo "  make [target] [OPTIONS]"
	@echo ""
	@echo "TARGETS:"
	@echo "  all              - Build test program and Python wrapper (default)"
	@echo "  test             - Compile assembly test program (test.elf/test.hex)"
	@echo "  test.elf         - Compile test.S into ELF"
	@echo "  test.bin         - Convert ELF to binary"
	@echo "  test.dis         - Generate disassembly"
	@echo "  test.hex         - Generate Verilog hex file for simulation"
	@echo "  spike_wrapper    - Compile C++ Pybind11 wrapper"
	@echo "  clean            - Remove generated files"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "OPTIONS:"
	@echo "  MARCH            - ISA and ABI flags (default: -march=rv64gcv_... -mabi=lp64d)"
	@echo ""
	@echo "EXAMPLES:"
	@echo ""
	@echo "  # RV64 with G extensions (default)"
	@echo "  make test"
	@echo ""
	@echo "  # RV64 with G and Vector extensions"
	@echo "  make test MARCH='-march=rv64gcv -mabi=lp64d'"
	@echo ""
	@echo "  # RV32 with I+M+A+C extensions"
	@echo "  make test MARCH='-march=rv32imac -mabi=ilp32d'"
	@echo ""
	@echo "  # RV32 with floating point"
	@echo "  make test MARCH='-march=rv32imafc -mabi=ilp32d'"
	@echo ""
	@echo "  # Clean and rebuild for RV64"
	@echo "  make clean && make test MARCH='-march=rv64imac -mabi=lp64d'"
	@echo ""
	@echo "=========================================================================="

# ============================================================================
# Test Program Compilation (Assembly -> ELF -> Binary -> Hex)
# ============================================================================

test: test.elf test.bin test.dis test.hex

test.elf: test.S link.ld
	@echo "[COMPILE] test.S -> test.elf"
	@echo "  MARCH: $(MARCH)"
	$(CC) $(MARCH) $(LDFLAGS) $< -o $@
	@echo "  [OK] Output: test.elf"

test.bin: test.elf
	@echo "[BINARY] test.elf -> test.bin"
	$(OBJCOPY) -O binary $< $@
	@echo "  [OK] Output: test.bin"

test.dis: test.elf
	@echo "[DISASM] test.elf -> test.dis"
	$(OBJDUMP) -D $< > $@
	@echo "  [OK] Output: test.dis"

test.hex: test.elf
	@echo "[HEXGEN] test.elf -> test.hex (Verilog format)"
	$(OBJCOPY) -O verilog $< $@
	@echo "  [OK] Output: test.hex"

# ============================================================================
# C++ Spike Wrapper Compilation (Pybind11)
# ============================================================================

spike_wrapper:
	@echo "[BUILD] C++ Spike Wrapper (Python module)"
	rm -f spike_py.cpython-*.so
	sh ./compile_wrapper.sh
	@echo "[OK] Output: spike_py.cpython-*.so"

# ============================================================================
# Clean Generated Files
# ============================================================================

clean:
	@echo "[CLEAN] Removing generated files..."
	rm -f test.elf test.bin test.dis test.hex
	@echo "[OK] Clean complete"

# ============================================================================
# Debug Target: Print Configuration
# ============================================================================

debug-config:
	@echo "=========================================="
	@echo "Build Configuration"
	@echo "=========================================="
	@echo "RISCV_BIN:        $(RISCV_BIN)"
	@echo "CROSS_COMPILE:    $(CROSS_COMPILE)"
	@echo "CC:               $(CC)"
	@echo "MARCH:            $(MARCH)"
	@echo "LDFLAGS:          $(LDFLAGS)"
	@echo "=========================================="

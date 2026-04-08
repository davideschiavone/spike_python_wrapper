# ============================================================================
# cosim/makefile
# ============================================================================
#
# Builds the lock-step co-simulation binary by linking pre-built libraries.
#
# Build order:
#   1. cd ../cve2          && make setup verilate cve2_lib
#   2. cd ../spike_wrapper && make spike_wrapper_lib
#   3. cd ../cosim         && make cosim_tb
#
# IMPORTANT: the -DTRACE flag used here must match how libcve2_tb.a was
# compiled.  The cve2 makefile writes the flag it used into
# build_cve2/cve2_tb_trace_flag.txt; this makefile reads it back so both
# always agree.  If you rebuild libcve2_tb.a with a different TRACE setting,
# just run `make cosim_tb` again — the flag file change will trigger a relink.
#
# ============================================================================

# --- Sibling directories ------------------------------------------------------
CVE2_DIR          := ../cve2
SPIKE_WRAPPER_DIR := ../spike_wrapper

# --- CVE2 pre-built libraries -------------------------------------------------
CVE2_BUILD_DIR := $(CVE2_DIR)/build_cve2
TOP_MODULE     := cve2_top

CVE2_VERILATE_STAMP := $(CVE2_BUILD_DIR)/.verilate_stamp
CVE2_TRACE_FLAG_FILE := $(CVE2_BUILD_DIR)/cve2_tb_trace_flag.txt

CVE2_LIBS := \
    $(CVE2_BUILD_DIR)/libcve2_tb.a \
    $(CVE2_BUILD_DIR)/V$(TOP_MODULE)__ALL.a \
    $(CVE2_BUILD_DIR)/libverilated.a

# --- Spike wrapper pre-built library ------------------------------------------
SPIKE_WRAPPER_LIB := $(SPIKE_WRAPPER_DIR)/libspike_wrapper.a

# --- Verilator runtime headers ------------------------------------------------
VERILATOR_ROOT ?= $(shell verilator --getenv VERILATOR_ROOT 2>/dev/null)
VROOT_INC       = $(VERILATOR_ROOT)/include

# --- Spike installation -------------------------------------------------------
SPIKE_INCLUDE ?= /home/$(USER)/tools/spike/include
SPIKE_LIB     ?= /home/$(USER)/tools/spike/lib

# --- Read the TRACE flag that libcve2_tb.a was compiled with ------------------
# This guarantees the Cve2Tb struct layout seen by cosim.cpp exactly matches
# the layout compiled into the library.  The file is written by `make cve2_lib`.
ifneq ($(wildcard $(CVE2_TRACE_FLAG_FILE)),)
  CVE2_TB_TRACE_FLAG := $(shell cat $(CVE2_TRACE_FLAG_FILE))
else
  # Flag file absent — library not built yet; guard rule below will catch it.
  CVE2_TB_TRACE_FLAG :=
endif

# --- Compiler -----------------------------------------------------------------
CXX      ?= g++
CXXFLAGS  = -std=c++20 -O2 -Wall \
            $(CVE2_TB_TRACE_FLAG) \
            -I./ \
            -I$(CVE2_DIR) \
            -I$(CVE2_BUILD_DIR) \
            -I$(SPIKE_WRAPPER_DIR) \
            -I$(VROOT_INC) \
            -I$(VROOT_INC)/vltstd \
            -I$(SPIKE_INCLUDE) \
            -DCOSIM_HAS_READ_MEM

LDFLAGS = \
    -L$(SPIKE_LIB) \
    -Wl,-rpath,$(SPIKE_LIB) \
    -lriscv -lfesvr \
    -lpthread -lm -ldl

# --- cosim source files -------------------------------------------------------
COSIM_SRCS := cosim.cpp cosim_main.cpp
COSIM_HDRS := cosim.h \
              $(CVE2_DIR)/cve2_tb.h \
              $(SPIKE_WRAPPER_DIR)/spike_wrapper.h

# ============================================================================
# Phony targets
# ============================================================================

.PHONY: all clean cosim_run cosim_run_verbose help

all: cosim_tb

help:
	@echo "=========================================================================="
	@echo "Spike × CVE2 Lock-Step Co-Simulation"
	@echo "=========================================================================="
	@echo ""
	@echo "PREREQUISITES (run once, and after any cve2_tb.h/cve2_tb.cpp change):"
	@echo "  cd ../cve2          && make setup verilate cve2_lib"
	@echo "  cd ../spike_wrapper && make spike_wrapper_lib"
	@echo ""
	@echo "TARGETS:"
	@echo "  cosim_tb            - Build co-simulation binary"
	@echo "  cosim_run           - Build and run  (set PROGRAM=, ISA=)"
	@echo "  cosim_run_verbose   - Build and run with per-instruction trace"
	@echo "  clean               - Remove build artefacts"
	@echo ""
	@echo "EXAMPLES:"
	@echo "  make cosim_tb"
	@echo "  make cosim_run PROGRAM=../tests/build/test ISA=rv32imc MAX_INSTRUCTIONS=20"
	@echo "  make cosim_run_verbose PROGRAM=../tests/build/test ISA=rv32imc"
	@echo "=========================================================================="

# ============================================================================
# Guard rules: fail with a clear message if prerequisites are missing
# ============================================================================

$(CVE2_BUILD_DIR)/libcve2_tb.a:
	$(error libcve2_tb.a not found. Run: cd ../cve2 && make cve2_lib)

$(CVE2_BUILD_DIR)/V$(TOP_MODULE)__ALL.a:
	$(error Verilated model not found. Run: cd ../cve2 && make verilate)

$(CVE2_BUILD_DIR)/libverilated.a:
	$(error libverilated.a not found. Run: cd ../cve2 && make verilate)

$(SPIKE_WRAPPER_LIB):
	$(error libspike_wrapper.a not found. Run: cd ../spike_wrapper && make spike_wrapper_lib)

# ============================================================================
# cosim_tb
# ============================================================================
# Also depends on the trace flag file so that a change in TRACE setting
# (e.g. rebuild library with TRACE=0) automatically triggers a relink.

cosim_tb: $(COSIM_SRCS) $(COSIM_HDRS) \
          $(CVE2_VERILATE_STAMP) $(CVE2_LIBS) $(SPIKE_WRAPPER_LIB) \
          $(CVE2_TRACE_FLAG_FILE)
	@echo "[BUILD] cosim_tb  (TRACE flag: '$(CVE2_TB_TRACE_FLAG)')"
	$(CXX) $(CXXFLAGS) \
	    $(COSIM_SRCS) \
	    -o cosim_tb \
	    $(CVE2_LIBS) $(SPIKE_WRAPPER_LIB) $(LDFLAGS)
	@echo "[OK]    cosim_tb"

# ============================================================================
# Convenience run targets
# ============================================================================

cosim_run: cosim_tb
	./cosim_tb $(PROGRAM) $(ISA) $(MAX_INSTRUCTIONS)

cosim_run_verbose: cosim_tb
	./cosim_tb $(PROGRAM) $(ISA) $(MAX_INSTRUCTIONS) --verbose

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -f cosim_tb
	@echo "[OK] cosim artefacts cleaned."

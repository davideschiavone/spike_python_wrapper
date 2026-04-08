# ============================================================================
# cosim/makefile
# ============================================================================
#
# Builds the lock-step co-simulation binary by linking pre-built libraries.
# No source files from cve2/ or spike_wrapper/ are recompiled here.
#
# Build order:
#   1. cd ../cve2          && make cve2_lib   → build_cve2/.verilate_stamp
#                                               build_cve2/libcve2_tb.a
#                                               build_cve2/libV*.a + libverilated.a
#   2. cd ../spike_wrapper && make lib        → libspike_wrapper.a
#   3. cd ../cosim         && make cosim_tb
#
# ============================================================================

# --- Sibling directories ------------------------------------------------------
CVE2_DIR          := ../cve2
SPIKE_WRAPPER_DIR := ../spike_wrapper

# --- CVE2 pre-built libraries -------------------------------------------------
CVE2_BUILD_DIR := $(CVE2_DIR)/build_cve2
TOP_MODULE     := cve2_top

# The stamp file is the authoritative signal that the Verilated model is fresh.
# All library archives are produced by the same verilate step, so depending on
# the stamp is sufficient — and it correctly goes stale when RTL changes.
CVE2_VERILATE_STAMP := $(CVE2_BUILD_DIR)/.verilate_stamp

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

# --- Compiler -----------------------------------------------------------------
CXX      ?= g++
CXXFLAGS  = -std=c++20 -O2 -Wall \
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

# --- cosim source files (only cosim itself, no upstream sources) --------------
COSIM_SRCS := cosim.cpp cosim_main.cpp
COSIM_HDRS := cosim.h \
              $(CVE2_DIR)/cve2_tb.h \
              $(SPIKE_WRAPPER_DIR)/spike_wrapper.h

# --- All libraries to link ----------------------------------------------------
ALL_LIBS := \
    $(SPIKE_WRAPPER_LIB) \
    $(CVE2_LIBS)

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
	@echo "PREREQUISITES (run once before building cosim):"
	@echo "  cd ../cve2          && make cve2_lib   (verilates + builds libcve2_tb.a)"
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
	@echo "  make cosim_run_verbose PROGRAM=../tests/build/test ISA=rv32imc MAX_INSTRUCTIONS=20"
	@echo "=========================================================================="

# ============================================================================
# cosim_tb
# ============================================================================
# Explicitly depends on the verilate stamp so that stale RTL is detected
# even when the library .a timestamps look up-to-date.

cosim_tb: $(COSIM_SRCS) $(COSIM_HDRS) $(CVE2_VERILATE_STAMP) $(ALL_LIBS)
	@echo "[BUILD] cosim_tb"
	$(CXX) $(CXXFLAGS) \
	    $(COSIM_SRCS) \
	    -o cosim_tb \
	    $(ALL_LIBS) $(LDFLAGS)
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

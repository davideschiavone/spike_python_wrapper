# ============================================================================
# cve2/makefile
# ============================================================================

# --- Repository / branch -------------------------------------------------------
CVE2_REPO   := git@github.com:openhwgroup/cve2.git
CVE2_BRANCH := e35390a7754f4e9acbce22840835a7a0f045ddc7

# --- Verilator -----------------------------------------------------------------
VERILATOR_ROOT ?= $(shell verilator --getenv VERILATOR_ROOT 2>/dev/null)
VROOT_INC       = $(VERILATOR_ROOT)/include

# --- Directories ---------------------------------------------------------------
EXT_DIR   := external
CVE2_DIR  := $(EXT_DIR)/cv32e20
BUILD_DIR := build_cve2
VC_FILE   := cve2.vc

# --- Trace flag ----------------------------------------------------------------
# TRACE controls VCD waveform support in cve2_tb.  It must be set consistently
# everywhere cve2_tb.h is included — the library, cve2_sim, cve2_py, and cosim
# must all agree, otherwise the Cve2Tb struct layout differs between translation
# units and every member after tfp_ lands at the wrong offset (segfault).
#
# Default: enabled.  Override with: make TRACE=0 ...
TRACE ?= 1

ifeq ($(TRACE),1)
  TRACE_FLAG := -DTRACE
else
  TRACE_FLAG :=
endif

# Export so that compile_cve2_py.sh and any sub-makes pick it up automatically.
export TRACE
export TRACE_FLAG

# --- Verilator flags -----------------------------------------------------------
VERILATOR  := verilator
TOP_MODULE := cve2_top

V_FLAGS := -Wall -cc --trace --trace-structs --trace-underscore \
           --trace-max-array 1024 \
           -CFLAGS -fPIC

TRACE_SRC  := $(VROOT_INC)/verilated_vcd_c.cpp

# --- Verilated library outputs -------------------------------------------------
VERILATED_LIBS := \
    $(BUILD_DIR)/V$(TOP_MODULE)__ALL.a \
    $(BUILD_DIR)/libverilated.a

# --- C++ compiler --------------------------------------------------------------
CXX      ?= g++
AR       ?= ar

CXXFLAGS  = -std=c++20 -O2 -Wall -fPIC \
            $(TRACE_FLAG) \
            -I$(BUILD_DIR) \
            -I./ \
            -I$(VROOT_INC) \
            -I$(VROOT_INC)/vltstd \
            -I$(VROOT_INC)/gtkwave

# --- Collect all RTL sources so that verilate reruns when they change ----------
RTL_SRCS := $(wildcard $(CVE2_DIR)/rtl/*.sv) \
            $(wildcard $(CVE2_DIR)/vendor/lowrisc_ip/ip/prim/rtl/*.sv)

# ============================================================================
# Phony targets
# ============================================================================

.PHONY: all clean setup verilate cve2_lib cve2_py help

all: verilate cve2_lib

# --- 1. Clone CVE2 if needed --------------------------------------------------
setup:
	@mkdir -p $(EXT_DIR)
	@if [ ! -d "$(CVE2_DIR)" ]; then \
		echo "--- Cloning CVE2 into $(CVE2_DIR) ---"; \
		git clone $(CVE2_REPO) $(CVE2_DIR); \
		git -C $(CVE2_DIR) checkout $(CVE2_BRANCH); \
		echo "--- CVE2 setup complete ---"; \
	else \
		echo "--- CVE2 already exists ---"; \
	fi

# --- 2. Verilate ---------------------------------------------------------------
$(BUILD_DIR)/.verilate_stamp: $(VC_FILE) $(RTL_SRCS) | setup
	@echo "--- Verilating $(TOP_MODULE) ---"
	@mkdir -p $(BUILD_DIR)
	$(VERILATOR) $(V_FLAGS) \
		--Mdir $(BUILD_DIR) \
		-f $(VC_FILE) \
		--top-module $(TOP_MODULE) \
		--build
	@touch $@
	@echo "--- Verilation complete ---"

verilate: $(BUILD_DIR)/.verilate_stamp

# --- 3. libcve2_tb.a -----------------------------------------------------------
# The TRACE_FLAG recorded at library build time is written into a small
# header so that consumers (cosim, cve2_py) can verify they were compiled
# with the same setting.

$(BUILD_DIR)/libcve2_tb.a: cve2_tb.cpp cve2_tb.h $(BUILD_DIR)/.verilate_stamp
	@echo "[AR]  libcve2_tb.a  (TRACE=$(TRACE))"
	$(CXX) $(CXXFLAGS) -c cve2_tb.cpp -o $(BUILD_DIR)/cve2_tb.o
	$(AR) rcs $@ $(BUILD_DIR)/cve2_tb.o
	@echo "$(TRACE_FLAG)" > $(BUILD_DIR)/cve2_tb_trace_flag.txt
	@echo "[OK]  $(BUILD_DIR)/libcve2_tb.a"

cve2_lib: $(BUILD_DIR)/libcve2_tb.a

# --- 4. cve2_py  –  Python extension module -----------------------------------
cve2_py: cve2_pybind.cpp cve2_tb.h compile_cve2_py.sh \
         $(BUILD_DIR)/libcve2_tb.a $(VERILATED_LIBS)
	@echo "[BUILD] cve2_py Python module  (TRACE=$(TRACE))"
	TOP_MODULE=$(TOP_MODULE) sh ./compile_cve2_py.sh
	@echo "[OK]    cve2_py Python module ready"

# ============================================================================
# Standalone CVE2 simulation binary (developer convenience)
# ============================================================================

cve2_sim: cve2_sim.cpp cve2_tb.h $(BUILD_DIR)/libcve2_tb.a $(VERILATED_LIBS)
	@echo "[BUILD] cve2_sim  (TRACE=$(TRACE))"
	$(CXX) $(CXXFLAGS) \
	    cve2_sim.cpp \
	    -o cve2_sim \
	    $(BUILD_DIR)/libcve2_tb.a \
	    $(VERILATED_LIBS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cve2_sim"

cve2_sim_trace: cve2_sim.cpp cve2_tb.h $(BUILD_DIR)/libcve2_tb.a $(VERILATED_LIBS)
	@echo "[BUILD] cve2_sim_trace  (VCD trace enabled)"
	$(CXX) $(CXXFLAGS) -DTRACE -g \
	    cve2_sim.cpp \
	    $(TRACE_SRC) \
	    -o cve2_sim_trace \
	    $(BUILD_DIR)/libcve2_tb.a \
	    $(VERILATED_LIBS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cve2_sim_trace"
	@echo "        Run it, then open cve2_wave.vcd in GTKWave"

# --- Run targets --------------------------------------------------------------
run: cve2_sim
	./cve2_sim $(HEX) $(MAX_CYCLES)

run_trace: cve2_sim_trace
	./cve2_sim_trace $(HEX) $(MAX_CYCLES)

view_trace:
	gtkwave cve2_wave.vcd cve2.gtkw

# --- Help ---------------------------------------------------------------------
help:
	@echo "=========================================================================="
	@echo "CVE2 Verilator Build"
	@echo "=========================================================================="
	@echo ""
	@echo "TARGETS:"
	@echo "  setup            - Clone CVE2 RTL into external/"
	@echo "  verilate         - Run Verilator on the CVE2 RTL"
	@echo "  cve2_lib         - Build libcve2_tb.a"
	@echo "  cve2_sim         - Build standalone simulation binary (no VCD by default)"
	@echo "  cve2_sim_trace   - Build standalone simulation binary (VCD forced on)"
	@echo "  cve2_py          - Build Python extension module"
	@echo "  run              - Run cve2_sim  (HEX=, MAX_CYCLES=)"
	@echo "  run_trace        - Run cve2_sim_trace (HEX=, MAX_CYCLES=)"
	@echo "  view_trace       - Open cve2_wave.vcd in GTKWave"
	@echo "  clean            - Remove build artefacts"
	@echo ""
	@echo "TRACE flag (must match across all consumers of libcve2_tb.a):"
	@echo "  make TRACE=1 ...  (default) — VCD support compiled in"
	@echo "  make TRACE=0 ...            — VCD support omitted"
	@echo "=========================================================================="

# --- Clean --------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR) cve2_sim cve2_sim_trace cve2_py.cpython-*.so
	@echo "Build directory cleaned."

distclean: clean
	rm -rf $(EXT_DIR)
	@echo "External sources removed."

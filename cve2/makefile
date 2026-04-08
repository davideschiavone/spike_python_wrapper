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

# --- Verilator flags -----------------------------------------------------------
VERILATOR  := verilator
TOP_MODULE := cve2_top
V_FLAGS    := -Wall -cc --trace --trace-structs --trace-underscore \
              --trace-max-array 1024

TRACE_SRC  := $(VROOT_INC)/verilated_vcd_c.cpp

# --- Verilated library outputs -------------------------------------------------
# Note: libV$(TOP_MODULE).a and V$(TOP_MODULE)__ALL.a are identical files
# produced by Verilator --build. Only one is needed.
VERILATED_LIBS := \
    $(BUILD_DIR)/V$(TOP_MODULE)__ALL.a \
    $(BUILD_DIR)/libverilated.a

# --- C++ compiler --------------------------------------------------------------
CXX      ?= g++
AR       ?= ar
CXXFLAGS  = -std=c++20 -O2 -Wall \
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

.PHONY: all clean setup verilate cve2_lib help

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
# Depends on all RTL .sv sources: any change to the RTL forces re-verilation.
# The stamp file $(BUILD_DIR)/.verilate_stamp is touched on success so make
# can track freshness without re-inspecting all library archives.

$(BUILD_DIR)/.verilate_stamp: $(VC_FILE) $(RTL_SRCS) | setup
	@echo "--- Verilating $(TOP_MODULE) ---"
	@mkdir -p $(BUILD_DIR)
	$(VERILATOR) $(V_FLAGS) \
		--Mdir $(BUILD_DIR) \
		-f $(VC_FILE) \
		--top-module $(TOP_MODULE) \
		--build
	@touch $@
	@echo "--- Verilaton complete ---"

verilate: $(BUILD_DIR)/.verilate_stamp

# --- 3. libcve2_tb.a  –  testbench static library ----------------------------
#
# Depends on the verilate stamp so that any RTL change triggers full
# re-verilation before the testbench library is (re-)compiled.
#
# Compiled WITH -DTRACE so the default library has waveforms.

$(BUILD_DIR)/libcve2_tb.a: cve2_tb.cpp cve2_tb.h $(BUILD_DIR)/.verilate_stamp
	@echo "[AR]  libcve2_tb.a"
	$(CXX) $(CXXFLAGS) -c -DTRACE cve2_tb.cpp -o $(BUILD_DIR)/cve2_tb.o
	$(AR) rcs $@ $(BUILD_DIR)/cve2_tb.o
	@echo "[OK]  $(BUILD_DIR)/libcve2_tb.a"

cve2_lib: $(BUILD_DIR)/libcve2_tb.a

# ============================================================================
# Standalone CVE2 simulation binary (developer convenience)
# ============================================================================

cve2_sim: cve2_sim.cpp cve2_tb.h $(BUILD_DIR)/libcve2_tb.a $(VERILATED_LIBS)
	@echo "[BUILD] cve2_sim  (no trace)"
	$(CXX) $(CXXFLAGS) \
	    cve2_sim.cpp \
	    -o cve2_sim \
	    $(BUILD_DIR)/libcve2_tb.a \
	    $(VERILATED_LIBS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cve2_sim"

cve2_sim_trace: cve2_sim.cpp cve2_tb.h $(BUILD_DIR)/libcve2_tb.a $(VERILATED_LIBS)
	@echo "[BUILD] cve2_sim_trace  (VCD trace enabled)"
	$(CXX) $(CXXFLAGS) -g \
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

# --- Clean --------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR) cve2_sim cve2_sim_trace
	@echo "Build directory cleaned."

distclean: clean
	rm -rf $(EXT_DIR)
	@echo "External sources removed."

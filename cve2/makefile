# --- Configuration ---
# Repo and Branch
CVE2_REPO    := git@github.com:openhwgroup/cve2.git
CVE2_BRANCH  := e35390a7754f4e9acbce22840835a7a0f045ddc7

# Locate verilated.h:
#   1. It is usually placed in OBJ_DIR by `verilator --cc`
#   2. Fall back to VERILATOR_ROOT/include if OBJ_DIR doesn't have it
VERILATOR_ROOT ?= $(shell verilator --getenv VERILATOR_ROOT 2>/dev/null)
VROOT_INC       = $(VERILATOR_ROOT)/include

# Directories
EXT_DIR      := external
CVE2_DIR     := $(EXT_DIR)/cv32e20
BUILD_DIR    := build_cve2
VC_FILE      := cve2.vc  # Assumes this file is in your root

# Verilator Settings
VERILATOR    := verilator
TOP_MODULE   := cve2_top
V_FLAGS      := -Wall -cc --trace --trace-structs --trace-underscore --trace-max-array 1024

TRACE_SRC = $(VROOT_INC)/verilated_vcd_c.cpp

# Outputs
LIBS     = $(BUILD_DIR)/libV$(TOP_MODULE).a \
           $(BUILD_DIR)/libverilated.a \
		   $(BUILD_DIR)/V$(TOP_MODULE)__ALL.a

# ─── Compiler ────────────────────────────────────────────────────────────────
CXX     ?= g++
CXXFLAGS = -std=c++20 -O2 -Wall \
           -I$(BUILD_DIR) \
		   -I./ \
           -I$(VROOT_INC) \
           -I$(VROOT_INC)/vltstd

# Extra include for multi-threading support headers (present in newer Verilator)
CXXFLAGS += -I$(VROOT_INC)/gtkwave

.PHONY: all clean setup verilate build_lib

all: build_lib

# 1. Setup: Clone the repo if it doesn't exist
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

# 2. Verilate: Convert SystemVerilog to C++
# We use --Mdir to force Verilator to put everything in build_cve2
verilate: setup
	@echo "--- Verilating $(TOP_MODULE) ---"
	@mkdir -p $(BUILD_DIR)
	$(VERILATOR) $(V_FLAGS) \
		--Mdir $(BUILD_DIR) \
		-f $(VC_FILE) \
		--top-module $(TOP_MODULE) \
		--build
	@echo "--- Verilation complete ---"

cve2_tb: cve2_tb.cpp cve2_tb.h $(LIBS)
	@echo "[BUILD] cve2_tb  (no trace)"
	$(CXX) $(CXXFLAGS) \
	    cve2_tb.cpp \
	    -o cve2_tb \
	    $(LIBS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cve2_tb"

cve2_tb_trace: cve2_tb.cpp cve2_tb.h $(LIBS)
	@echo "[BUILD] cve2_tb_trace  (VCD trace enabled)"
	$(CXX) $(CXXFLAGS) -g -DTRACE \
	    cve2_tb.cpp \
	    $(TRACE_SRC) \
	    -o cve2_tb_trace \
	    $(LIBS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cve2_tb_trace"
	@echo "        Run it, then open cve2_wave.vcd in GTKWave"

# ── Run targets ───────────────────────────────────────────────────────────────
run: cve2_tb
	./cve2_tb $(HEX) $(MAX_CYCLES)

run_trace: cve2_tb_trace
	./cve2_tb_trace $(HEX) $(MAX_CYCLES)

view_trace:
	gtkwave cve2_wave.vcd cve2.gtkw

# 3. Build Lib: Just a wrapper for the build (Verilator --build handles the make)
build_lib: verilate
	@echo "--- Library created at $(LIB_A) ---"

clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned."

distclean: clean
	rm -rf $(EXT_DIR)
	@echo "External sources removed."
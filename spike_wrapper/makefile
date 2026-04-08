# ============================================================================
# RISC-V Spike Wrapper -
# ============================================================================

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean spike_wrapper help

all: spike_wrapper

help:
	@echo "=========================================================================="
	@echo "RISC-V Spike Wrapper - Configurable Build"
	@echo "=========================================================================="
	@echo ""
	@echo "USAGE:"
	@echo "  make [target] [OPTIONS]"
	@echo ""
	@echo "TARGETS:"
	@echo "  spike_wrapper    - Compile C++ Pybind11 wrapper"
	@echo "  clean            - Remove generated files"
	@echo "  help             - Show this help message"
	@echo ""


# ============================================================================
# C++ Spike Wrapper Compilation (Pybind11)
# ============================================================================

spike_wrapper:
	@echo "[BUILD] C++ Spike Wrapper (Python module)"
	sh ./compile_wrapper.sh
	@echo "[OK] Output: spike_py.cpython-*.so"

# ============================================================================
# Clean Generated Files
# ============================================================================

clean:
	@echo "[CLEAN] Removing generated files..."
	rm -f spike_py.cpython-*.so
	@echo "[OK] Clean complete"

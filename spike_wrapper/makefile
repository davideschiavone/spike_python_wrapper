# ============================================================================
# spike_wrapper/makefile
# ============================================================================
#
# Both targets delegate entirely to compile_wrapper.sh, which is the single
# source of truth for compiler flags, Spike paths, and pybind11 detection.
#
#   make spike_wrapper   →  spike_py.cpython-*.so  (Python extension module)
#   make lib             →  libspike_wrapper.a      (C++ static library for cosim)
#   make all             →  both of the above
# ============================================================================

.PHONY: all clean spike_wrapper lib help

all: spike_wrapper lib

help:
	@echo "=========================================================================="
	@echo "RISC-V Spike Wrapper"
	@echo "=========================================================================="
	@echo ""
	@echo "TARGETS:"
	@echo "  spike_wrapper  - Compile into Python extension  (spike_py.cpython-*.so)"
	@echo "  lib            - Compile into static library     (libspike_wrapper.a)"
	@echo "  all            - Both of the above"
	@echo "  clean          - Remove all generated files"
	@echo ""
	@echo "Both targets use compile_wrapper.sh as the single source of truth"
	@echo "for compiler flags, Spike paths, and pybind11 detection."
	@echo ""
	@echo "PREREQUISITES:"
	@echo "  - Spike installed at ~/tools/spike  (edit compile_wrapper.sh to override)"
	@echo "  - pip install pybind11"
	@echo "  - g++ with C++20 support"
	@echo "=========================================================================="

# ============================================================================
# Python extension module
# ============================================================================

spike_wrapper: spike_wrapper.h spike_wrapper.cpp compile_wrapper.sh
	sh ./compile_wrapper.sh module

# ============================================================================
# Static library for C++ consumers (cosim)
# ============================================================================

lib: spike_wrapper.h spike_wrapper.cpp compile_wrapper.sh
	sh ./compile_wrapper.sh lib

# ============================================================================
# Clean
# ============================================================================

clean:
	@echo "[CLEAN] Removing generated files..."
	rm -f spike_py.cpython-*.so libspike_wrapper.a
	@echo "[OK] Clean complete"

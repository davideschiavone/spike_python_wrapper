#!/bin/bash
# ============================================================================
# Pybind11 C++ Wrapper Compilation Script
# ============================================================================
# This script compiles the Spike wrapper C++ code into a Python module
# using Pybind11. It handles linking against the Spike libraries.
#
# Usage:
#   sh compile_wrapper.sh
#
# Requirements:
#   - spike headers and libraries installed
#   - pybind11 installed (pip install pybind11)
#   - g++ with C++20 support
# ============================================================================

set -e  # Exit on error

echo "=========================================================================="
echo "Spike Wrapper - Pybind11 Compilation"
echo "=========================================================================="
echo ""

SPIKE_PATH="/home/${USER}/tools/spike"
SPIKE_LIB_PATH="${SPIKE_PATH}/lib"
SPIKE_INCLUDE_PATH="${SPIKE_PATH}/include"

echo "[*] Configuration:"
echo "    Spike path:     ${SPIKE_PATH}"
echo "    Spike lib:      ${SPIKE_LIB_PATH}"
echo "    Spike include:  ${SPIKE_INCLUDE_PATH}"
echo ""

if [ ! -d "${SPIKE_INCLUDE_PATH}/riscv" ]; then
    echo "[ERROR] Spike headers not found at: ${SPIKE_INCLUDE_PATH}/riscv"
    exit 1
fi

# Get Python and Pybind11 info
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
PYBIND11_INCLUDES=$(python3 -m pybind11 --includes)
PYTHON_CONFIG_SUFFIX=$(python3-config --extension-suffix)

echo "[*] Python configuration:"
echo "    Version:        ${PYTHON_VERSION}"
echo "    Includes:       ${PYBIND11_INCLUDES}"
echo "    Extension:      ${PYTHON_CONFIG_SUFFIX}"
echo ""

# Clean old module
echo "[*] Cleaning old module..."
rm -f spike_py.cpython-*.so
echo "    Done"
echo ""

# Compile
echo "[*] Compiling spike_wrapper.cpp..."
echo ""

g++ -O3 -shared -std=c++20 -fPIC \
    ${PYBIND11_INCLUDES} \
    -I${SPIKE_INCLUDE_PATH} \
    spike_wrapper.cpp \
    -L${SPIKE_LIB_PATH} \
    -Wl,-rpath,${SPIKE_LIB_PATH} \
    -o spike_py${PYTHON_CONFIG_SUFFIX} \
    -lriscv -lfesvr

echo ""
echo "[OK] Compilation successful!"
echo "    Output: spike_py${PYTHON_CONFIG_SUFFIX}"
echo ""


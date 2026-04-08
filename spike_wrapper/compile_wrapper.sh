#!/bin/bash
# ============================================================================
# Spike Wrapper - Unified Compilation Script
# ============================================================================
#
# Builds spike_wrapper.cpp into either:
#   module  →  spike_py.cpython-*.so   (Python extension, default)
#   lib     →  libspike_wrapper.a      (C++ static library for cosim)
#
# Usage:
#   sh compile_wrapper.sh           # builds Python module (default)
#   sh compile_wrapper.sh module    # same as above
#   sh compile_wrapper.sh lib       # builds static library
#
# Requirements:
#   - Spike headers and libraries installed (default: ~/tools/spike)
#   - pybind11 installed: pip install pybind11
#   - g++ with C++20 support
# ============================================================================

set -e

MODE="${1:-module}"

if [ "$MODE" != "module" ] && [ "$MODE" != "lib" ]; then
    echo "[ERROR] Unknown mode: '$MODE'. Use 'module' or 'lib'."
    exit 1
fi

echo "=========================================================================="
echo "Spike Wrapper - Compilation  (mode: $MODE)"
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

# Common compiler flags (shared between both modes)
COMMON_FLAGS="-std=c++20 -O3 -Wall -fPIC \
    -I${SPIKE_INCLUDE_PATH}"

# ============================================================================
# Mode: module  →  spike_py.cpython-*.so
# ============================================================================

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
PYBIND11_INCLUDES=$(python3 -m pybind11 --includes)
PYTHON_CONFIG_SUFFIX=$(python3-config --extension-suffix)

echo "[*] Python configuration:"
echo "    Version:        ${PYTHON_VERSION}"
echo "    Includes:       ${PYBIND11_INCLUDES}"
echo "    Extension:      ${PYTHON_CONFIG_SUFFIX}"
echo ""


# ============================================================================
# Mode: lib  →  libspike_wrapper.a
# ============================================================================

if [ "$MODE" = "lib" ]; then
    OUTPUT="libspike_wrapper.a"

    echo "[*] Cleaning old library..."
    rm -f "${OUTPUT}"
    echo "    Done"
    echo ""

    echo "[*] Compiling spike_wrapper.cpp → spike_wrapper.o ..."
    g++ ${COMMON_FLAGS} \
        ${PYBIND11_INCLUDES} \
        -c spike_wrapper.cpp \
        -o spike_wrapper.o

    echo "[*] Archiving → ${OUTPUT} ..."
    ar rcs "${OUTPUT}" spike_wrapper.o
    rm -f spike_wrapper.o

    echo ""
    echo "[OK] Static library: ${OUTPUT}"
    echo ""
else

    OUTPUT="spike_py${PYTHON_CONFIG_SUFFIX}"

    echo "[*] Cleaning old module..."
    rm -f spike_py.cpython-*.so
    echo "    Done"
    echo ""

    echo "[*] Compiling spike_wrapper.cpp → ${OUTPUT} ..."
    echo ""

    g++ -shared ${COMMON_FLAGS} \
        ${PYBIND11_INCLUDES} \
        spike_wrapper.cpp \
        -L${SPIKE_LIB_PATH} \
        -Wl,-rpath,${SPIKE_LIB_PATH} \
        -o "${OUTPUT}" \
        -lriscv -lfesvr

    echo ""
    echo "[OK] Python module: ${OUTPUT}"
    echo ""
fi

exit 0

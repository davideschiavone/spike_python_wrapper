// ============================================================================
// cosim.h  –  Declarations for the Spike × CVE2 Lock-Step Co-Simulation Engine
// ============================================================================
//
// The implementation lives in cosim.cpp.
// The simulation entry point (main) lives in cosim_main.cpp.
//
// Architecture overview
// ─────────────────────
//
//   main() / Python
//       │
//       ▼
//   CoSim::run()
//       │
//       ├─ RTL side : Cve2Tb::step()  (clock cycles until rvfi_valid)
//       │                └─ RvfiInsn snapshot on each retirement
//       │
//       └─ ISA side : SpikeBridge::step()
//                        └─ PC, rd_wdata, mem read-back after each step
//
// Comparison matrix (per retired instruction)
// ────────────────────────────────────────────
//
//  ┌──────────────┬───────────────────────────────────────────┐
//  │ Signal       │ When compared                             │
//  ├──────────────┼───────────────────────────────────────────┤
//  │ pc_rdata     │ always                                    │
//  │ rd_wdata     │ rd_addr != 0  (x0 write is discarded)     │
//  │ mem_wdata    │ mem_wmask != 0  (store instruction)       │
//  │ mem_addr     │ mem_wmask != 0  (store instruction)       │
//  └──────────────┴───────────────────────────────────────────┘
//
//  Branches / jumps: not compared directly; control-flow divergence
//  is caught by the PC check on the next instruction.
//
// Bus timing for co-simulation
// ────────────────────────────
//   In lock-step mode we deliberately use randomised bus delays (the same
//   values that existed before the runtime-configurable change) to ensure
//   the RTL handles back-pressure correctly.  These are passed to Cve2Tb
//   explicitly so that the default Cve2Tb constructor (used by cve2_sim and
//   the Python binding) retains the fast 0-delay configuration.
//
// Pybind11 future binding
// ────────────────────────
//   CoSim is designed to be bound to Python with minimal friction.
//   All configuration goes through plain structs; CoSim::run() returns
//   CoSimResult by value.  A stub PYBIND11_MODULE is at the bottom of
//   cosim.cpp (commented out) ready to be enabled.
//
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Pull in both simulation sides.

#include "cve2_tb.h"
#include "spike_wrapper.h"

// ============================================================================
// ANSI colour helpers
// ============================================================================

namespace colour {
    constexpr const char* RED    = "\033[31m";
    constexpr const char* GREEN  = "\033[32m";
    constexpr const char* YELLOW = "\033[33m";
    constexpr const char* CYAN   = "\033[36m";
    constexpr const char* BOLD   = "\033[1m";
    constexpr const char* RESET  = "\033[0m";
}

// ABI register names
static constexpr const char* ABI_NAMES[32] = {
    "zero","ra","sp","gp","tp","t0","t1","t2",
    "s0","s1","a0","a1","a2","a3","a4","a5",
    "a6","a7","s2","s3","s4","s5","s6","s7",
    "s8","s9","s10","s11","t3","t4","t5","t6"
};

// ============================================================================
// Bus timing used for co-simulation (randomised back-pressure)
// These values reproduce the original behaviour from before the
// runtime-configurable constructor was introduced.
// ============================================================================

constexpr int COSIM_GNT_PROB_NUM     = 1;   // 1/2 probability of granting per cycle
constexpr int COSIM_GNT_PROB_DEN     = 2;
constexpr int COSIM_MAX_RVALID_DELAY = 3;   // up to 3 extra cycles GNT→RVALID

// ============================================================================
// MismatchKind
// ============================================================================

enum class MismatchKind {
    PC,
    RD_WDATA,
    MEM_ADDR,
    MEM_WDATA,
};

// ============================================================================
// MismatchRecord  –  one recorded comparison failure
// ============================================================================

struct MismatchRecord {
    uint64_t     retired_count = 0;
    MismatchKind kind          = MismatchKind::PC;
    uint32_t     rtl_val       = 0;
    uint64_t     ref_val       = 0;
    uint32_t     pc_rdata      = 0;
    uint8_t      rd_addr       = 0;

    std::string to_string() const;
};

// ============================================================================
// CoSimConfig
// ============================================================================

struct CoSimConfig {
    std::string program_path;
    std::string isa              = "rv32imc";
    uint64_t    max_retired      = 100'000;
    uint64_t    max_cycles       = 10'000'000ULL;
    uint32_t    boot_addr        = BOOT_ADDR;
    bool        verbose          = false;
    bool        stop_on_first_mismatch = true;
};

// ============================================================================
// CoSimResult
// ============================================================================

struct CoSimResult {
    uint64_t retired_count  = 0;
    uint64_t rtl_cycles     = 0;
    uint32_t mismatches     = 0;
    bool     halted_cleanly = false;

    std::vector<MismatchRecord> mismatch_log;

    void print_summary() const;
};

// ============================================================================
// SpikeState  –  Spike snapshot for one instruction
// ============================================================================

struct SpikeState {
    uint32_t pc_before = 0;
    uint32_t pc_after  = 0;
    uint32_t rd_wdata  = 0;
    uint32_t mem_wdata = 0;
    uint32_t mem_addr  = 0;
    bool     is_store  = false;
};

// ============================================================================
// CoSim  –  the lock-step engine
// ============================================================================

class CoSim {
public:
    explicit CoSim(const CoSimConfig& cfg);

    CoSimResult run();

private:
    const RvfiInsn* advance_rtl_to_retirement();
    SpikeState      capture_spike_state(const RvfiInsn& rvfi, uint32_t pc_before);
    uint32_t        read_spike_word(uint32_t addr, uint8_t wmask);
    bool            compare(const RvfiInsn& rvfi, const SpikeState& ss, CoSimResult& result);
    void            print_trace_line(uint64_t n, const RvfiInsn& rvfi,
                                     const SpikeState& ss, bool ok) const;

    static constexpr uint32_t SPIKE_MEM_READ_UNAVAILABLE = 0xDEAD'C0DEu;

    CoSimConfig  cfg_;
    Cve2Tb       rtl_;
    SpikeBridge  spike_;
};

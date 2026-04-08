// ============================================================================
// cosim.cpp  –  CoSim engine implementation
// ============================================================================
//
// The simulation entry point (main) lives in cosim_main.cpp.
// ============================================================================

#include "cosim.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdio>

// ============================================================================
// MismatchRecord::to_string
// ============================================================================

std::string MismatchRecord::to_string() const {
    std::ostringstream ss;
    ss << colour::RED << "[MISMATCH #" << retired_count << "] ";
    switch (kind) {
        case MismatchKind::PC:
            ss << "PC  rtl=0x" << std::hex << std::setw(8) << std::setfill('0') << rtl_val
               << "  ref=0x"   << std::setw(8) << std::setfill('0') << ref_val;
            break;
        case MismatchKind::RD_WDATA:
            ss << "rd=" << ABI_NAMES[rd_addr]
               << "  rtl=0x" << std::hex << std::setw(8) << std::setfill('0') << rtl_val
               << "  ref=0x" << std::setw(8) << std::setfill('0') << ref_val
               << "  (PC=0x" << std::setw(8) << std::setfill('0') << pc_rdata << ")";
            break;
        case MismatchKind::MEM_ADDR:
            ss << "STORE ADDR  rtl=0x" << std::hex << std::setw(8) << std::setfill('0') << rtl_val
               << "  ref=0x"           << std::setw(8) << std::setfill('0') << ref_val;
            break;
        case MismatchKind::MEM_WDATA:
            ss << "STORE DATA  rtl=0x" << std::hex << std::setw(8) << std::setfill('0') << rtl_val
               << "  ref=0x"           << std::setw(8) << std::setfill('0') << ref_val
               << "  (PC=0x"           << std::setw(8) << std::setfill('0') << pc_rdata << ")";
            break;
    }
    ss << colour::RESET;
    return ss.str();
}

// ============================================================================
// CoSimResult::print_summary
// ============================================================================

void CoSimResult::print_summary() const {
    std::cout << "\n" << colour::BOLD
              << "╔══════════════════════════════════════════════╗\n"
              << "║         Co-Simulation Summary                ║\n"
              << "╚══════════════════════════════════════════════╝\n"
              << colour::RESET;
    std::cout << "  Retired instructions : " << retired_count << "\n";
    std::cout << "  RTL clock cycles     : " << rtl_cycles    << "\n";
    std::cout << "  Mismatches           : ";
    if (mismatches == 0)
        std::cout << colour::GREEN << "0 — PASS ✓" << colour::RESET << "\n";
    else {
        std::cout << colour::RED << mismatches << " — FAIL ✗" << colour::RESET << "\n";
        for (auto& m : mismatch_log)
            std::cout << "    " << m.to_string() << "\n";
    }
    std::cout << "  Halted cleanly       : " << (halted_cleanly ? "yes" : "no") << "\n\n";
}

// ============================================================================
// CoSim constructor
//
// Cve2Tb is constructed with the cosim-specific randomised bus delays
// (COSIM_GNT_PROB_NUM/DEN and COSIM_MAX_RVALID_DELAY) so that lock-step
// simulation exercises the RTL back-pressure handling.
// The standalone cve2_sim and the Python binding use the default 0-delay
// constructor, giving maximum throughput.
// ============================================================================

CoSim::CoSim(const CoSimConfig& cfg)
    : cfg_  (cfg)
    , rtl_  (cfg.program_path + ".hex",
             cfg.boot_addr,
             cfg.max_cycles,
             /*rng_seed=*/42,
             COSIM_GNT_PROB_NUM,
             COSIM_GNT_PROB_DEN,
             COSIM_MAX_RVALID_DELAY)
    , spike_(cfg.program_path.c_str(), cfg.isa.c_str())
{
    std::cout << colour::CYAN << colour::BOLD
              << "\n╔═══════════════════════════════════════════════════╗\n"
              << "║    Spike × CVE2 Lock-Step Co-Simulation Engine    ║\n"
              << "╚═══════════════════════════════════════════════════╝\n"
              << colour::RESET;
    std::cout << "  HEX    : " << cfg.program_path + ".hex" << "\n";
    std::cout << "  ELF    : " << cfg.program_path + ".elf" << "\n";
    std::cout << "  ISA    : " << cfg.isa      << "\n";
    std::cout << "  Bus    : GNT=" << COSIM_GNT_PROB_NUM << "/" << COSIM_GNT_PROB_DEN
              << "  RVALID_DELAY=0.." << COSIM_MAX_RVALID_DELAY << "\n\n";

    std::cout << colour::YELLOW << "[CoSim] Spike initial PC: 0x"
              << std::hex << std::setw(8) << std::setfill('0')
              << (uint32_t)spike_.get_pc() << std::dec
              << colour::RESET << "\n\n";
}

// ============================================================================
// CoSim::run
// ============================================================================

CoSimResult CoSim::run() {
    CoSimResult result;
    rtl_.reset(8);

    if (cfg_.verbose) {
        std::printf("\n%-6s  %-10s  %-8s  %-8s  %-25s  %s\n",
                    "#RET", "PC", "INSN", "RD", "RTL→REF", "STATUS");
        std::printf("%s\n", std::string(80, '─').c_str());
    }

    while (!rtl_.halted() && result.retired_count < cfg_.max_retired) {

        // 1. Clock RTL until a retirement is visible on RVFI
        const RvfiInsn* rvfi = advance_rtl_to_retirement();
        if (!rvfi) break;

        // 2. Record Spike PC before stepping (= address of this instruction)
        uint32_t spike_pc_before = (uint32_t)spike_.get_pc();

        // 3. Step Spike one instruction
        spike_.step();

        // 4. Snapshot Spike state after step
        SpikeState ss = capture_spike_state(*rvfi, spike_pc_before);

        // 5. Compare RTL vs ISA reference
        ++result.retired_count;
        bool ok = compare(*rvfi, ss, result);

        // 6. Verbose trace line
        if (cfg_.verbose)
            print_trace_line(result.retired_count, *rvfi, ss, ok);

        if (!ok && cfg_.stop_on_first_mismatch)
            break;
    }

    result.rtl_cycles     = rtl_.cycle();
    result.halted_cleanly = rtl_.halted();
    return result;
}

// ============================================================================
// Private helpers
// ============================================================================

const RvfiInsn* CoSim::advance_rtl_to_retirement() {
    while (!rtl_.halted()) {
        rtl_.step();
        if (rtl_.rvfi_valid())
            return &rtl_.rvfi();
    }
    // Halted on the same cycle as a valid retirement
    if (rtl_.rvfi_valid())
        return &rtl_.rvfi();
    return nullptr;
}

SpikeState CoSim::capture_spike_state(const RvfiInsn& rvfi, uint32_t pc_before) {
    SpikeState ss;
    ss.pc_before = pc_before;
    ss.pc_after  = (uint32_t)spike_.get_pc();

    if (rvfi.rd_addr != 0)
        ss.rd_wdata = (uint32_t)spike_.get_reg(rvfi.rd_addr);

    if (rvfi.mem_wmask != 0) {
        ss.is_store = true;
        ss.mem_addr  = rvfi.mem_addr;
        ss.mem_wdata = read_spike_word(rvfi.mem_addr, rvfi.mem_wmask);
    }

    return ss;
}

uint32_t CoSim::read_spike_word(uint32_t addr, uint8_t wmask) {
    // Spike committed the store during step(), so a load at the same address
    // returns the freshly written value.  Requires read_mem32() on SpikeBridge.
    return spike_.read_mem32(addr);
    (void)wmask;  // wmask used for masking in compare(), not for the read
}

bool CoSim::compare(const RvfiInsn& rvfi, const SpikeState& ss, CoSimResult& result) {
    bool all_ok = true;

    auto record = [&](MismatchKind k, uint32_t rtl_val, uint64_t ref_val, uint8_t rd = 0) {
        result.mismatches++;
        MismatchRecord m;
        m.retired_count = result.retired_count;
        m.kind          = k;
        m.rtl_val       = rtl_val;
        m.ref_val       = ref_val;
        m.pc_rdata      = rvfi.pc_rdata;
        m.rd_addr       = rd;
        result.mismatch_log.push_back(m);
        std::cerr << m.to_string() << "\n";
        all_ok = false;
    };

    // ── PC ────────────────────────────────────────────────────────────
    // rvfi.pc_rdata = address of the retiring instruction
    // ss.pc_before  = Spike's PC captured before step() = same thing
    if (rvfi.pc_rdata != ss.pc_before)
        record(MismatchKind::PC, rvfi.pc_rdata, ss.pc_before);

    // ── Register write ────────────────────────────────────────────────
    if (rvfi.rd_addr != 0) {
        if (rvfi.rd_wdata != ss.rd_wdata)
            record(MismatchKind::RD_WDATA, rvfi.rd_wdata, ss.rd_wdata, rvfi.rd_addr);
    }

    // ── Store ─────────────────────────────────────────────────────────
    if (rvfi.mem_wmask != 0) {
        // Address
        if (rvfi.mem_addr != ss.mem_addr)
            record(MismatchKind::MEM_ADDR, rvfi.mem_addr, ss.mem_addr);

        // Data — mask to only the bytes that were actually written
        if (ss.mem_wdata != SPIKE_MEM_READ_UNAVAILABLE) {
            uint32_t mask = 0;
            if (rvfi.mem_wmask & 0x1) mask |= 0x0000'00FFu;
            if (rvfi.mem_wmask & 0x2) mask |= 0x0000'FF00u;
            if (rvfi.mem_wmask & 0x4) mask |= 0x00FF'0000u;
            if (rvfi.mem_wmask & 0x8) mask |= 0xFF00'0000u;

            if ((rvfi.mem_wdata & mask) != (ss.mem_wdata & mask))
                record(MismatchKind::MEM_WDATA,
                       rvfi.mem_wdata & mask,
                       ss.mem_wdata   & mask);
        }
    }

    return all_ok;
}

void CoSim::print_trace_line(uint64_t n, const RvfiInsn& rvfi,
                              const SpikeState& ss, bool ok) const
{
    std::string status = ok ? (std::string(colour::GREEN) + "OK " + colour::RESET)
                            : (std::string(colour::RED) + "ERR" + colour::RESET);
    
    std::string rd_str = "-";
    if (rvfi.rd_addr != 0) {
        char buf[48];
        std::snprintf(buf, sizeof(buf), "%s:0x%08x→0x%08x",
                      ABI_NAMES[rvfi.rd_addr], rvfi.rd_wdata, ss.rd_wdata);
        rd_str = buf;
    }
    std::printf("%-6lu  0x%08x  0x%08x  %-8s  %-28s  %s\n",
                (unsigned long)n,
                rvfi.pc_rdata,
                rvfi.insn,
                (rvfi.rd_addr ? ABI_NAMES[rvfi.rd_addr] : "-"),
                rd_str.c_str(),
                status.c_str());
}

// ============================================================================
// Pybind11 stub (future binding — uncomment and compile as .so)
// ============================================================================
//
// #include <pybind11/pybind11.h>
// #include <pybind11/stl.h>
// namespace py = pybind11;
//
// PYBIND11_MODULE(cosim_py, m) {
//     m.doc() = "Spike × CVE2 lock-step co-simulation engine";
// ...
// }

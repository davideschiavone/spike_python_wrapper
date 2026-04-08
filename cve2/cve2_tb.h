// ============================================================================
// cve2_tb.h  –  Verilator Testbench for CVE2 (cve2_top) with RVFI
// ============================================================================
//
// Bus protocol (GNT → RVALID minimum 1-cycle gap)
// ─────────────────────────────────────────────────
//
//  Instruction fetch (instr_*)
//
//   clk   ─┐ ┌─┐ ┌─┐ ┌─┐ ┌─
//           └─┘ └─┘ └─┘ └─┘
//           N   N+1 N+2
//   req_o  ─────────┐ idle ...
//   addr_o ────[A]──┘
//   gnt_i  ─────────┐     (asserted same cycle as req, de-asserted next)
//                   └─────
//   rvalid_i              ┌──── (exactly 1 cycle after gnt)
//                         └────
//   rdata_i               [mem[A]]
//
//  Data bus (data_*) – identical timing.
//  Writes are committed to memory at GNT time (data_wdata_o is stable).
//  RVALID is still required for stores (core waits for it).
//
// Memory map (must match linker script / Spike config)
// ─────────────────────────────────────────────────────
//   0x0000_1000  Boot ROM   4 KB
//   0x8000_0000  RAM       16 MB
//
// Waveform tracing
// ─────────────────
//   Compile with -DTRACE to enable VCD output → cve2_wave.vcd
//   This works even when the Verilated model was compiled separately
//   as a static library, because VerilatedVcdC is in libverilated.a.
//
// ============================================================================

#pragma once

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

// Verilator-generated headers.
// When linking against pre-built libraries these headers come from obj_dir/.
#include "Vcve2_top.h"
#include "verilated.h"

// VCD waveform support – only compiled when -DTRACE is passed to g++
#ifdef TRACE
#  include "verilated_vcd_c.h"
#endif

// ============================================================================
// Memory configuration
// ============================================================================

constexpr uint32_t BOOT_BASE = 0x0000'1000u;
constexpr uint32_t BOOT_SIZE = 0x0000'1000u;   //  4 KB
constexpr uint32_t RAM_BASE  = 0x8000'0000u;
constexpr uint32_t RAM_SIZE  = 0x0100'0000u;   // 16 MB

// Boot address driven to the CVE2 core.
// CVE2 resets to (boot_addr_i), so first fetch = 0x8000_0000.
// Adjust if your _start / _boot is mapped elsewhere.
constexpr uint32_t BOOT_ADDR = BOOT_BASE;

constexpr uint8_t FETCH_ENABLE_ON = 0x1u;

// ============================================================================
// vlwide_zero  –  zero a Verilator VlWide<N> packed-struct signal
//
// Verilator maps SystemVerilog packed structs wider than 64 bits to
// VlWide<N>, where N = ceil(total_bits / 32).  VlWide does not overload
// operator=, so "signal = 0" fails to compile.
//
// Usage:
//   vlwide_zero(dut_->x_result_i);     // works for any VlWide<N>
//
// The underlying storage is a plain C array of uint32_t words accessible
// via VlWide::operator[](i), so we just iterate and zero each word.
// ============================================================================

template <std::size_t N>
inline void vlwide_zero(VlWide<N>& w) {
    for (std::size_t i = 0; i < N; ++i)
        w[i] = 0;
}

// ============================================================================
// Cve2Memory  –  flat C++ byte-addressed memory (heap-allocated)
//
// Memory regions are allocated on the heap to avoid stack overflow with
// large RAM sizes (16 MB default). Uses std::unique_ptr for automatic
// cleanup and exception safety.
// ============================================================================

class Cve2Memory {
public:
    Cve2Memory()
        : boot_(std::make_unique<uint8_t[]>(BOOT_SIZE)),
          ram_(std::make_unique<uint8_t[]>(RAM_SIZE))
    {
        // Zero-initialize both memory regions
        std::memset(boot_.get(), 0, BOOT_SIZE);
        std::memset(ram_.get(),  0, RAM_SIZE);
    }

    // Explicitly delete copy operations (unique_ptr is move-only)
    Cve2Memory(const Cve2Memory&) = delete;
    Cve2Memory& operator=(const Cve2Memory&) = delete;

    // Enable move operations
    Cve2Memory(Cve2Memory&&) noexcept = default;
    Cve2Memory& operator=(Cve2Memory&&) noexcept = default;

    ~Cve2Memory() = default;

    // Load a Verilog objcopy hex file  (@ADDR / HEX_BYTE ... format)
    // Same format as used by SpikeBridge::load_hex()
    void load_hex(const std::string& path) {
        std::ifstream f(path);
        if (!f.is_open())
            throw std::runtime_error("[Cve2Memory] Cannot open: " + path);
        std::string tok;
        uint64_t addr = 0;
        while (f >> tok) {
            if (tok[0] == '@')
                addr = std::stoull(tok.substr(1), nullptr, 16);
            else
                write8(static_cast<uint32_t>(addr++),
                       static_cast<uint8_t>(std::stoul(tok, nullptr, 16)));
        }
        std::cout << "[Cve2Memory] Loaded: " << path << "\n";
    }

    // 32-bit little-endian read (for instruction fetch and data loads)
    uint32_t read32(uint32_t addr) const {
        return  static_cast<uint32_t>(read8(addr + 0))        |
               (static_cast<uint32_t>(read8(addr + 1)) <<  8) |
               (static_cast<uint32_t>(read8(addr + 2)) << 16) |
               (static_cast<uint32_t>(read8(addr + 3)) << 24);
    }

    // Byte-enable masked 32-bit write  (data_be_o is 4 bits wide)
    void write32(uint32_t addr, uint32_t data, uint8_t be) {
        if (be & 0x1) write8(addr + 0, (data >>  0) & 0xFF);
        if (be & 0x2) write8(addr + 1, (data >>  8) & 0xFF);
        if (be & 0x4) write8(addr + 2, (data >> 16) & 0xFF);
        if (be & 0x8) write8(addr + 3, (data >> 24) & 0xFF);
    }

    uint8_t read8(uint32_t addr) const {
        if (addr >= BOOT_BASE && addr < BOOT_BASE + BOOT_SIZE)
            return boot_[addr - BOOT_BASE];
        if (addr >= RAM_BASE  && addr < RAM_BASE  + RAM_SIZE)
            return ram_[addr - RAM_BASE];
        return 0x00;   // unmapped → return 0, no bus error signalled
    }

    void write8(uint32_t addr, uint8_t val) {
        if (addr >= BOOT_BASE && addr < BOOT_BASE + BOOT_SIZE)
            boot_[addr - BOOT_BASE] = val;
        else if (addr >= RAM_BASE && addr < RAM_BASE + RAM_SIZE)
            ram_[addr - RAM_BASE] = val;
        // unmapped writes silently ignored
    }

    // Debug dump
    void dump(uint32_t addr, uint32_t n_words) const {
        for (uint32_t i = 0; i < n_words; ++i)
            std::printf("  0x%08x : 0x%08x\n", addr + i*4, read32(addr + i*4));
    }

    // Direct access to memory regions (for advanced use cases)
    uint8_t* boot_data() { return boot_.get(); }
    uint8_t* ram_data()  { return ram_.get();  }
    const uint8_t* boot_data() const { return boot_.get(); }
    const uint8_t* ram_data()  const { return ram_.get();  }

    // Memory region sizes
    static constexpr uint32_t boot_size() { return BOOT_SIZE; }
    static constexpr uint32_t ram_size()  { return RAM_SIZE;  }

private:
    std::unique_ptr<uint8_t[]> boot_;   // 4 KB Boot ROM (heap)
    std::unique_ptr<uint8_t[]> ram_;    // 16 MB RAM (heap)
};

// ============================================================================
// RvfiInsn  –  snapshot of one retired instruction's RVFI outputs
// ============================================================================

struct RvfiInsn {
    uint64_t order      = 0;
    uint32_t insn       = 0;
    uint8_t  trap       = 0;
    uint8_t  halt       = 0;
    uint8_t  intr       = 0;
    uint8_t  mode       = 0;
    uint8_t  ixl        = 0;
    uint32_t pc_rdata   = 0;
    uint32_t pc_wdata   = 0;
    uint8_t  rs1_addr   = 0;
    uint8_t  rs2_addr   = 0;
    uint8_t  rd_addr    = 0;
    uint32_t rs1_rdata  = 0;
    uint32_t rs2_rdata  = 0;
    uint32_t rd_wdata   = 0;
    uint32_t mem_addr   = 0;
    uint8_t  mem_rmask  = 0;
    uint8_t  mem_wmask  = 0;
    uint32_t mem_rdata  = 0;
    uint32_t mem_wdata  = 0;
};

// ============================================================================
// Cve2Tb  –  testbench wrapper around the Verilated CVE2 model
// ============================================================================

class Cve2Tb {
public:
    // -------------------------------------------------------------------------
    // Construction
    //   hex_path  : Verilog hex file to load (test.hex)
    //   boot_addr : driven to boot_addr_i on the DUT
    //   max_cycles: hard simulation limit
    // -------------------------------------------------------------------------
    explicit Cve2Tb(const std::string& hex_path,
                    uint32_t           boot_addr  = BOOT_ADDR,
                    uint64_t           max_cycles = 1'000'000ULL)
        : boot_addr_(boot_addr), max_cycles_(max_cycles)
    {
        ctx_ = std::make_unique<VerilatedContext>();
        dut_ = std::make_unique<Vcve2_top>(ctx_.get(), "TOP");

#ifdef TRACE
        ctx_->traceEverOn(true);
        tfp_ = std::make_unique<VerilatedVcdC>();
        dut_->trace(tfp_.get(), 99 /*depth*/);
        tfp_->open("cve2_wave.vcd");
        std::cout << "[Cve2Tb] VCD tracing → cve2_wave.vcd\n";
#endif

        mem_.load_hex(hex_path);
        init_inputs();

        std::cout << "[Cve2Tb] Boot addr : 0x"
                  << std::hex << boot_addr_ << std::dec << "\n";
    }

    ~Cve2Tb() {
        dut_->final();
#ifdef TRACE
        if (tfp_) tfp_->close();
#endif
    }

    // -------------------------------------------------------------------------
    // reset() – hold rst_ni low for `cycles` full clock cycles then release
    // -------------------------------------------------------------------------
    void reset(uint32_t cycles = 8) {
        dut_->rst_ni = 0;
        for (uint32_t i = 0; i < cycles; ++i)
            raw_tick();
        dut_->rst_ni = 1;
        std::cout << "[Cve2Tb] Reset released after " << cycles << " cycles.\n";
    }

    // -------------------------------------------------------------------------
    // step() – advance one complete clock cycle
    //
    // Combinational input sequence each call:
    //
    //  A) De-assert GNT from the previous cycle.
    //  B) If a request was captured (granted) last cycle:
    //       → assert RVALID=1 and drive RDATA (this is cycle N+1 vs grant N).
    //  C) Sample the DUT's current req/addr/we/be/wdata outputs.
    //  D) If a new request is pending (and we are not already busy):
    //       → assert GNT=1 and latch the request details.
    //       → for writes: commit to memory now (wdata is already stable).
    //  E) Rising edge: eval(), capture RVFI, dump waveform.
    //  F) Falling edge: eval(), dump waveform.
    // -------------------------------------------------------------------------
    void step() {
        if (halted_) return;

        // A: de-assert GNT (it was pulsed for exactly one cycle last step)
        dut_->instr_gnt_i = 0;
        dut_->data_gnt_i  = 0;

        // B: drive RVALID/RDATA for the previously granted request
        drive_instr_rvalid();
        drive_data_rvalid();

        // C+D: sample new requests and grant them
        grant_instr_req();
        grant_data_req();

        // E: rising edge
        dut_->clk_i = 1;
        dut_->eval();
        ctx_->timeInc(1);
#ifdef TRACE
        tfp_->dump(ctx_->time());
#endif
        capture_rvfi();

        // F: falling edge
        dut_->clk_i = 0;
        dut_->eval();
        ctx_->timeInc(1);
#ifdef TRACE
        tfp_->dump(ctx_->time());
#endif

        ++cycle_;
        if (cycle_ >= max_cycles_) {
            std::cerr << "[Cve2Tb] Max cycles reached.\n";
            halted_ = true;
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────
    bool              halted()     const { return halted_;     }
    uint64_t          cycle()      const { return cycle_;      }
    bool              rvfi_valid() const { return rvfi_valid_; }
    const RvfiInsn&   rvfi()       const { return rvfi_;       }
    Cve2Memory&       memory()           { return mem_;        }
    const Cve2Memory& memory()     const { return mem_;        }

    void print_rvfi() const {
        if (!rvfi_valid_) return;
        const auto& r = rvfi_;
        std::printf(
            "[RVFI] #%-6lu  PC=0x%08x  insn=0x%08x"
            "  rd=x%02u:0x%08x"
            "  rs1=x%02u:0x%08x  rs2=x%02u:0x%08x%s\n",
            (unsigned long)r.order,
            r.pc_rdata, r.insn,
            r.rd_addr,  r.rd_wdata,
            r.rs1_addr, r.rs1_rdata,
            r.rs2_addr, r.rs2_rdata,
            r.trap ? "  [TRAP]" : "");
        if (r.mem_rmask || r.mem_wmask)
            std::printf(
                "               MEM[0x%08x]"
                "  rmask=0x%x wmask=0x%x"
                "  rdata=0x%08x wdata=0x%08x\n",
                r.mem_addr,
                r.mem_rmask, r.mem_wmask,
                r.mem_rdata, r.mem_wdata);
    }

private:
    // -----------------------------------------------------------------------
    // Pending-request registers  (one slot per bus)
    //
    // Filled when we assert GNT, consumed one cycle later when we assert RVALID.
    // We only support one outstanding transaction per bus at a time, which is
    // the minimum required by the CVE2 spec (it never issues a second request
    // before seeing RVALID for the first one under normal operation).
    // -----------------------------------------------------------------------
    struct Pending {
        bool     valid = false;
        uint32_t addr  = 0;
        bool     we    = false;  // data bus only
        uint8_t  be    = 0;     // data bus only
        uint32_t wdata = 0;     // data bus only
    };

    Pending instr_pend_;
    Pending data_pend_;

    // -----------------------------------------------------------------------
    // Instruction bus helpers
    // -----------------------------------------------------------------------

    void grant_instr_req() {
        // Only grant if the DUT is requesting AND we have no pending rvalid
        if (dut_->instr_req_o && !instr_pend_.valid) {
            instr_pend_ = { true, dut_->instr_addr_o, false, 0, 0 };
            dut_->instr_gnt_i = 1;
        } else {
            dut_->instr_gnt_i = 0;
        }
    }

    void drive_instr_rvalid() {
        if (instr_pend_.valid) {
            dut_->instr_rvalid_i = 1;
            dut_->instr_rdata_i  = mem_.read32(instr_pend_.addr);
            dut_->instr_err_i    = 0;
            instr_pend_.valid    = false;   // slot now free
        } else {
            dut_->instr_rvalid_i = 0;
            dut_->instr_rdata_i  = 0;
            dut_->instr_err_i    = 0;
        }
    }

    // -----------------------------------------------------------------------
    // Data bus helpers
    // -----------------------------------------------------------------------

    void grant_data_req() {
        if (dut_->data_req_o && !data_pend_.valid) {
            bool we = static_cast<bool>(dut_->data_we_o);
            data_pend_ = { true,
                           dut_->data_addr_o,
                           we,
                           dut_->data_be_o,
                           dut_->data_wdata_o };
            dut_->data_gnt_i = 1;

            // Writes: commit data to memory at GNT time.
            // The wdata lines are stable when req/gnt are asserted.
            if (we)
                mem_.write32(data_pend_.addr, data_pend_.wdata, data_pend_.be);
        } else {
            dut_->data_gnt_i = 0;
        }
    }

    void drive_data_rvalid() {
        if (data_pend_.valid) {
            dut_->data_rvalid_i = 1;
            dut_->data_err_i    = 0;
            // For loads: present the data; for stores: rdata is don't-care
            dut_->data_rdata_i  = data_pend_.we
                                  ? 0u
                                  : mem_.read32(data_pend_.addr);
            data_pend_.valid    = false;
        } else {
            dut_->data_rvalid_i = 0;
            dut_->data_rdata_i  = 0;
            dut_->data_err_i    = 0;
        }
    }

    // -----------------------------------------------------------------------
    // Tie all unused inputs to safe constants
    // -----------------------------------------------------------------------
    void init_inputs() {
        dut_->clk_i       = 0;
        dut_->rst_ni      = 0;

        dut_->test_en_i   = 0;

        // SRAM config (prim_ram_1p_pkg::ram_1p_cfg_t packed struct) → 0
        dut_->ram_cfg_i   = 0;

        // Core configuration
        dut_->hart_id_i   = 0;
        dut_->boot_addr_i = boot_addr_;

        // Instruction bus – idle
        dut_->instr_gnt_i    = 0;
        dut_->instr_rvalid_i = 0;
        dut_->instr_rdata_i  = 0;
        dut_->instr_err_i    = 0;

        // Data bus – idle
        dut_->data_gnt_i    = 0;
        dut_->data_rvalid_i = 0;
        dut_->data_rdata_i  = 0;
        dut_->data_err_i    = 0;

        // CV-X-IF – not used, tie all signals to zero.
        //
        // x_result_i is a packed structs in SystemVerilog.
        // Verilator represents them as VlWide<N> when they exceed 64 bits.
        // VlWide<N> does not support plain "= 0" assignment; use vlwide_zero()
        // to zero every 32-bit word in the underlying storage array.

        dut_->x_issue_ready_i  = 0;
        dut_->x_issue_resp_i   = 0;
        dut_->x_result_valid_i = 0;
        vlwide_zero(dut_->x_result_i);       // x_result_t      (>64 bits)

        // Interrupts – all deasserted
        dut_->irq_software_i = 0;
        dut_->irq_timer_i    = 0;
        dut_->irq_external_i = 0;
        dut_->irq_fast_i     = 0;
        dut_->irq_nm_i       = 0;

        // Debug – inactive
        dut_->debug_req_i         = 0;
        dut_->dm_halt_addr_i      = 0;
        dut_->dm_exception_addr_i = 0;

        // Fetch enable – ON (core starts fetching immediately after reset)
        dut_->fetch_enable_i = FETCH_ENABLE_ON;

        dut_->eval();
    }

    // One posedge + negedge without touching bus logic (used by reset())
    void raw_tick() {
        dut_->clk_i = 1; dut_->eval(); ctx_->timeInc(1);
#ifdef TRACE
        tfp_->dump(ctx_->time());
#endif
        dut_->clk_i = 0; dut_->eval(); ctx_->timeInc(1);
#ifdef TRACE
        tfp_->dump(ctx_->time());
#endif
        ++cycle_;
    }

    // Capture all RVFI outputs after posedge eval
    void capture_rvfi() {
        rvfi_valid_ = static_cast<bool>(dut_->rvfi_valid);
        if (!rvfi_valid_) return;

        rvfi_.order     = dut_->rvfi_order;
        rvfi_.insn      = dut_->rvfi_insn;
        rvfi_.trap      = dut_->rvfi_trap;
        rvfi_.halt      = dut_->rvfi_halt;
        rvfi_.intr      = dut_->rvfi_intr;
        rvfi_.mode      = dut_->rvfi_mode;
        rvfi_.ixl       = dut_->rvfi_ixl;
        rvfi_.pc_rdata  = dut_->rvfi_pc_rdata;
        rvfi_.pc_wdata  = dut_->rvfi_pc_wdata;
        rvfi_.rs1_addr  = dut_->rvfi_rs1_addr;
        rvfi_.rs2_addr  = dut_->rvfi_rs2_addr;
        rvfi_.rs1_rdata = dut_->rvfi_rs1_rdata;
        rvfi_.rs2_rdata = dut_->rvfi_rs2_rdata;
        rvfi_.rd_addr   = dut_->rvfi_rd_addr;
        rvfi_.rd_wdata  = dut_->rvfi_rd_wdata;
        rvfi_.mem_addr  = dut_->rvfi_mem_addr;
        rvfi_.mem_rmask = dut_->rvfi_mem_rmask;
        rvfi_.mem_wmask = dut_->rvfi_mem_wmask;
        rvfi_.mem_rdata = dut_->rvfi_mem_rdata;
        rvfi_.mem_wdata = dut_->rvfi_mem_wdata;

        // Stop on explicit trap, halt signal, or PC self-loop (ecall / j finish)
        if (rvfi_.trap || rvfi_.halt ||
            rvfi_.pc_wdata == rvfi_.pc_rdata)
            halted_ = true;
    }

    // ── Member variables ───────────────────────────────────────────────────
    std::unique_ptr<VerilatedContext> ctx_;
    std::unique_ptr<Vcve2_top>        dut_;
#ifdef TRACE
    std::unique_ptr<VerilatedVcdC>    tfp_;
#endif
    Cve2Memory mem_;
    uint32_t   boot_addr_;
    uint64_t   max_cycles_;
    uint64_t   cycle_      = 0;
    bool       halted_     = false;
    bool       rvfi_valid_ = false;
    RvfiInsn   rvfi_       = {};
};

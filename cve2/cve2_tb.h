// ============================================================================
// cve2_tb.h  –  Verilator Testbench for CVE2 (cve2_top) with RVFI
// ============================================================================
//
// Bus protocol  (mirrors x-heep slow_memory.sv)
// ─────────────────────────────────────────────────────────────────────────────
//
//  1. REQ is held by the CPU until GNT is received.
//     GNT can arrive in the SAME cycle as REQ, or ANY later cycle.
//     Each cycle a Bernoulli coin-flip (GNT_PROB_NUM/GNT_PROB_DEN) decides
//     whether to grant the pending request.
//
//  2. RVALID arrives AT LEAST one cycle after the corresponding GNT.
//     A random extra delay [0 .. MAX_RVALID_DELAY] is drawn at grant time
//     and stored in a FIFO together with RDATA.  The FIFO head is ticked
//     every cycle; when the countdown reaches 0 RVALID is asserted for
//     exactly one cycle and the entry is popped.
//
//  3. Both buses are in-order (no transaction IDs) so FIFOs are sufficient.
//
//  4. GNT and RVALID MAY be asserted in the same cycle when they refer to
//     DIFFERENT transactions.  The only constraint is that RVALID for
//     transaction T cannot appear in the same cycle as GNT for transaction T.
//     Example:
//       Cycle N  : REQ(A) → gnt=1                    RVALID(A) comes later
//       Cycle N+1: REQ(B) → gnt=1  AND rvalid=1(A)   ← perfectly legal
//
// Timeline example (GNT delayed 1 cycle, RVALID extra delay = 2):
//
//   Cycle N  : req=1 addr=A  gnt=0   rvalid=0        (coin said no)
//   Cycle N+1: req=1 addr=A  gnt=1 ← granted         countdown = 1+2 = 3
//   Cycle N+2: req=1 addr=B  gnt=1   rvalid=0        (A: countdown 3→2)
//   Cycle N+3: req=0         gnt=0   rvalid=1(A)     (A: countdown 2→1→pop, B: 3→2)
//   Cycle N+4: req=0         gnt=0   rvalid=1(B)     (B: countdown 2→1→pop)
//
// Memory map (must match linker script / Spike config)
// ─────────────────────────────────────────────────────
//   0x0000_1000  Boot ROM   4 KB
//   0x8000_0000  RAM       16 MB
//
// Tuning knobs (see constants below)
// ────────────────────────────────────
//   GNT_PROB_NUM / GNT_PROB_DEN   probability of granting each cycle
//   MAX_RVALID_DELAY               max extra cycles between GNT and RVALID
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
#include <queue>
#include <random>
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
// CVE2 resets to (boot_addr_i), so first fetch = 0x0000_1000.
constexpr uint32_t BOOT_ADDR = BOOT_BASE;

constexpr uint8_t FETCH_ENABLE_ON = 0x1u;

// ── Slow-bus tuning knobs ────────────────────────────────────────────────────
//
//  GNT probability per cycle = GNT_PROB_NUM / GNT_PROB_DEN
//    1/1 → always grant immediately (zero extra latency on GNT)
//    1/2 → 50 % chance per cycle  (default)
//    1/4 → 25 % chance per cycle  (slow)
//
constexpr int GNT_PROB_NUM     = 1;
constexpr int GNT_PROB_DEN     = 2;

//  Extra cycles added on top of the mandatory 1-cycle GNT→RVALID gap.
//  Drawn uniformly from [0 .. MAX_RVALID_DELAY].
//    0 → RVALID always exactly 1 cycle after GNT  (minimum legal)
//    3 → RVALID between 1 and 4 cycles after GNT  (default)
//
constexpr int MAX_RVALID_DELAY = 3;
// ─────────────────────────────────────────────────────────────────────────────

// ============================================================================
// vlwide_zero  –  zero a Verilator VlWide<N> packed-struct signal
//
// Verilator maps SystemVerilog packed structs wider than 64 bits to
// VlWide<N>, where N = ceil(total_bits / 32).  VlWide does not overload
// operator=, so "signal = 0" fails to compile.
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
          ram_ (std::make_unique<uint8_t[]>(RAM_SIZE))
    {
        std::memset(boot_.get(), 0, BOOT_SIZE);
        std::memset(ram_.get(),  0, RAM_SIZE);
    }

    // Explicitly delete copy operations (unique_ptr is move-only)
    Cve2Memory(const Cve2Memory&)            = delete;
    Cve2Memory& operator=(const Cve2Memory&) = delete;

    // Enable move operations
    Cve2Memory(Cve2Memory&&) noexcept            = default;
    Cve2Memory& operator=(Cve2Memory&&) noexcept = default;

    ~Cve2Memory() = default;

    // Load a Verilog objcopy hex file  (@ADDR / HEX_BYTE ... format)
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

    // 32-bit little-endian read
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
    uint8_t*       boot_data()       { return boot_.get(); }
    uint8_t*       ram_data()        { return ram_.get();  }
    const uint8_t* boot_data() const { return boot_.get(); }
    const uint8_t* ram_data()  const { return ram_.get();  }

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
// SlowBus  –  C++ model of one OBI-like bus with randomised GNT / RVALID
// ============================================================================
//
//  Mirrors the behaviour of x-heep slow_memory.sv.
//
//  Internal state
//  ──────────────
//  req_pending_     : true while the CPU's current REQ has been seen but not
//                     yet granted.  Prevents re-capturing the same transaction
//                     while the CPU holds req=1 stable waiting for GNT.
//
//  rvalid_fifo_     : FIFO of { countdown, rdata } entries, one per granted
//                     transaction.  Each entry's countdown is initialised to
//                     (1 + random_extra) so RVALID always arrives at least one
//                     cycle after the corresponding GNT.  The FIFO is drained
//                     head-first every cycle; when countdown reaches 0 the
//                     entry is popped and RVALID is raised for that cycle.
//
//  tick() algorithm (3 steps, called at negedge each cycle)
//  ─────────────────────────────────────────────────────────
//  A. Advance RVALID pipeline:
//       Decrement rvalid_fifo_.front().countdown.
//       If it hits 0 → pop, assert rvalid=1, drive rdata.
//       Otherwise rvalid=0.
//
//  B. Capture new request:
//       If req=1 and req_pending_=false, latch addr/we/be/wdata and set
//       req_pending_=true.  (CPU holds signals stable until GNT.)
//
//  C. Attempt grant:
//       If req_pending_, flip the coin.
//       Heads → commit write to memory (wdata stable at GNT time),
//               pre-fetch rdata for loads,
//               push { 1 + random_extra, rdata } onto rvalid_fifo_,
//               assert gnt=1, clear req_pending_.
//       Tails → gnt=0, try again next cycle.
//
//  GNT and RVALID for the SAME transaction can never overlap because
//  countdown ≥ 1.  GNT and RVALID from DIFFERENT transactions may overlap
//  (step A pops an old entry while step C grants a new one in the same cycle).
//
// ============================================================================

struct RvalidEntry {
    int      countdown = 1;  ///< cycles remaining before RVALID fires (min 1)
    uint32_t rdata     = 0;  ///< data to drive on rdata_i (0 for writes)
};

class SlowBus {
public:
    explicit SlowBus(const std::string& name,
                     Cve2Memory&        mem,
                     std::mt19937&      rng)
        : name_       (name)
        , mem_        (mem)
        , rng_        (rng)
        , gnt_dist_   (0, GNT_PROB_DEN - 1)
        , delay_dist_ (0, MAX_RVALID_DELAY)
    {}

    // -------------------------------------------------------------------------
    // tick()  –  drive one cycle of bus logic, called AT THE NEGATIVE EDGE.
    //
    // DUT outputs are read after they have settled following the falling edge.
    // The resulting input values are driven and remain stable until the next
    // rising edge, where the DUT latches them.
    //
    // Inputs  : current DUT output signals for this bus (stable post-negedge).
    // Outputs : values to drive onto the corresponding DUT input signals.
    // -------------------------------------------------------------------------
    void tick(uint8_t   req_i,
              uint32_t  addr_i,
              uint8_t   we_i,
              uint8_t   be_i,
              uint32_t  wdata_i,
              uint8_t&  gnt_o,
              uint8_t&  rvalid_o,
              uint32_t& rdata_o,
              uint8_t&  err_o)
    {
        // ── A: advance the RVALID pipeline ──────────────────────────────
        rvalid_o = 0;
        rdata_o  = 0;
        err_o    = 0;

        if (!rvalid_fifo_.empty()) {
            auto& head = rvalid_fifo_.front();
            head.countdown--;
            if (head.countdown == 0) {
                rvalid_o = 1;
                rdata_o  = head.rdata;
                rvalid_fifo_.pop();
            }
        }

        // ── B: capture new request (only once per transaction) ───────────
        // The CPU holds req=1 and addr/we/be/wdata stable until it sees
        // gnt=1, so we only need to latch once and re-use each tick.
        if (req_i && !req_pending_) {
            req_pending_   = true;
            pending_addr_  = addr_i;
            pending_we_    = static_cast<bool>(we_i);
            pending_be_    = be_i;
            pending_wdata_ = wdata_i;
        }

        // ── C: attempt to grant ──────────────────────────────────────────
        gnt_o = 0;

        if (req_pending_ && (gnt_dist_(rng_) < GNT_PROB_NUM)) {
            // Commit writes at GNT time (wdata is stable)
            if (pending_we_)
                mem_.write32(pending_addr_, pending_wdata_, pending_be_);

            // Pre-fetch rdata for loads (irrelevant for stores)
            uint32_t rdata = pending_we_ ? 0u : mem_.read32(pending_addr_);

            // Push into RVALID pipeline; mandatory 1-cycle gap enforced by
            // initialising countdown to at least 1.
            rvalid_fifo_.push({ 1 + delay_dist_(rng_), rdata });

            gnt_o        = 1;
            req_pending_ = false;  // CPU will de-assert req next cycle
        }
    }

    // Reset internal state (call after DUT reset is released)
    void reset() {
        rvalid_fifo_   = {};
        req_pending_   = false;
        pending_addr_  = 0;
        pending_we_    = false;
        pending_be_    = 0;
        pending_wdata_ = 0;
    }

private:
    std::string    name_;
    Cve2Memory&    mem_;
    std::mt19937&  rng_;

    std::uniform_int_distribution<int> gnt_dist_;    ///< coin for GNT
    std::uniform_int_distribution<int> delay_dist_;  ///< extra RVALID delay

    std::queue<RvalidEntry> rvalid_fifo_;  ///< granted txns waiting for RVALID

    // Latched request (one outstanding at a time per OBI bus)
    bool     req_pending_  = false;
    uint32_t pending_addr_  = 0;
    bool     pending_we_    = false;
    uint8_t  pending_be_    = 0;
    uint32_t pending_wdata_ = 0;
};

// ============================================================================
// Cve2Tb  –  testbench wrapper around the Verilated CVE2 model
// ============================================================================

class Cve2Tb {
public:
    // -------------------------------------------------------------------------
    // Construction
    //   hex_path   : Verilog hex file to load (test.hex)
    //   boot_addr  : driven to boot_addr_i on the DUT
    //   max_cycles : hard simulation limit
    //   rng_seed   : seed for the random GNT / RVALID delay generator
    // -------------------------------------------------------------------------
    explicit Cve2Tb(const std::string& hex_path,
                    uint32_t           boot_addr  = BOOT_ADDR,
                    uint64_t           max_cycles = 1'000'000ULL,
                    uint32_t           rng_seed   = 42)
        : boot_addr_(boot_addr)
        , max_cycles_(max_cycles)
        , rng_(rng_seed)
        , instr_bus_("INSTR", mem_, rng_)
        , data_bus_ ("DATA",  mem_, rng_)
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

        std::cout << "[Cve2Tb] Boot addr        : 0x"
                  << std::hex << boot_addr_ << std::dec << "\n";
        std::cout << "[Cve2Tb] RNG seed          : " << rng_seed          << "\n";
        std::cout << "[Cve2Tb] GNT probability   : "
                  << GNT_PROB_NUM << "/" << GNT_PROB_DEN                   << "\n";
        std::cout << "[Cve2Tb] Max RVALID delay  : +"
                  << MAX_RVALID_DELAY << " cycles (on top of mandatory 1)\n";
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
        instr_bus_.reset();
        data_bus_.reset();
        std::cout << "[Cve2Tb] Reset released after " << cycles << " cycles.\n";
    }

    // -------------------------------------------------------------------------
    // step() – advance one complete clock cycle
    //
    // Inputs are applied at the NEGATIVE edge so they are fully stable well
    // before the next rising edge samples them:
    //
    //  1. Rising edge : eval(), capture RVFI, dump waveform.
    //  2. Falling edge: eval(), dump waveform.
    //  3. SlowBus::tick() reads the DUT outputs that are now stable after the
    //     falling edge and drives new GNT/RVALID/RDATA values.  These remain
    //     stable on the inputs until the next rising edge.
    //
    // Timeline:
    //   … negedge(N-1) → tick() drives inputs for cycle N
    //        → posedge(N) → DUT latches inputs, RVFI captured
    //        → negedge(N) → tick() drives inputs for cycle N+1 …
    // -------------------------------------------------------------------------
    void step() {
        if (halted_) return;

        // ── Rising edge ───────────────────────────────────────────────────
        // Inputs were already driven at the previous negedge (or by reset()).
        dut_->clk_i = 1;
        dut_->eval();
        ctx_->timeInc(1);
#ifdef TRACE
        tfp_->dump(ctx_->time());
#endif
        capture_rvfi();

        // ── Falling edge ──────────────────────────────────────────────────
        dut_->clk_i = 0;

        // ── Drive inputs at negedge (stable for the upcoming posedge) ─────
        // Read DUT outputs that are now settled after the falling edge, then
        // compute and apply the new bus inputs for the next cycle.
        {
            uint8_t gnt, rvalid, err;
            uint32_t rdata;
            instr_bus_.tick(
                dut_->instr_req_o, dut_->instr_addr_o,
                /*we=*/0, /*be=*/0xF, /*wdata=*/0,
                gnt, rvalid, rdata, err);
            dut_->instr_gnt_i    = gnt;
            dut_->instr_rvalid_i = rvalid;
            dut_->instr_rdata_i  = rdata;
            dut_->instr_err_i    = err;
        }
        {
            uint8_t gnt, rvalid, err;
            uint32_t rdata;
            data_bus_.tick(
                dut_->data_req_o,  dut_->data_addr_o,
                dut_->data_we_o,   dut_->data_be_o,  dut_->data_wdata_o,
                gnt, rvalid, rdata, err);
            dut_->data_gnt_i    = gnt;
            dut_->data_rvalid_i = rvalid;
            dut_->data_rdata_i  = rdata;
            dut_->data_err_i    = err;
        }

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
        // x_result_i is a packed struct in SystemVerilog.
        // Verilator represents it as VlWide<N> when it exceeds 64 bits.
        // VlWide<N> does not support plain "= 0" assignment; use vlwide_zero()
        // to zero every 32-bit word in the underlying storage array.
        dut_->x_issue_ready_i  = 0;
        dut_->x_issue_resp_i   = 0;
        dut_->x_result_valid_i = 0;
        vlwide_zero(dut_->x_result_i);

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

    // One posedge + negedge without bus logic (used by reset()).
    // After the negedge we leave all bus inputs at their idle/zero state;
    // the first real tick() call will happen at the negedge after reset() returns.
    void raw_tick() {
        dut_->clk_i = 1; dut_->eval(); ctx_->timeInc(1);
#ifdef TRACE
        tfp_->dump(ctx_->time());
#endif
        dut_->clk_i = 0; dut_->eval(); ctx_->timeInc(1);
#ifdef TRACE
        tfp_->dump(ctx_->time());
#endif
        // Bus inputs remain at idle (set by init_inputs / previous tick).
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
    Cve2Memory   mem_;
    uint32_t     boot_addr_;
    uint64_t     max_cycles_;
    uint64_t     cycle_      = 0;
    bool         halted_     = false;
    bool         rvfi_valid_ = false;
    RvfiInsn     rvfi_       = {};

    std::mt19937 rng_;           ///< shared RNG – both buses draw from it
    SlowBus      instr_bus_;
    SlowBus      data_bus_;
};

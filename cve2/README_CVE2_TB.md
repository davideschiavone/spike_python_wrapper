# CVE2 Verilator Testbench

A C++ testbench for the **CVE2** (CV32E20) RISC-V core, linked against
pre-built Verilator static libraries with **RVFI** enabled and correct
1-cycle-delayed RVALID bus protocol.

---


## Quick start

```bash

# clones CVE2

make setup

# verilate CVE2
make verilate

# creates the cve2 tb class library
make cve2_lib

# build TB no TRACE
make cve2_sim

# or build TB with TRACE
make cve2_sim_trace

# Run
make run HEX=../tests/build/test.hex

# Build with VCD waveform output, then run
make run_trace HEX=../tests/build/test.hex MAX_CYCLES=180

# Open waveform
make view_trace
```

---

## Bus protocol

```
      Cycle N       Cycle N+1     Cycle N+2
clk   ──┐ ┌──       ──┐ ┌──       ──┐ ┌──
        └─┘             └─┘             └─┘

req_o ──[1]──────    [0]           [0]
addr_o──[A]──────
gnt_i ──[1]──────    [0]           [0]    ← GNT asserted with req
rvalid_i    [0]      [1]──────     [0]    ← RVALID exactly 1 cycle after GNT
rdata_i     [X]      [mem[A]]      [X]    ← RDATA valid with RVALID
```

**Key rule**: GNT and RVALID are **never** asserted in the same cycle.
The core reads RDATA only when it sees RVALID=1.

This is identical for both the instruction and data buses.

For **writes**: the data is committed to `Cve2Memory` at GNT time
(wdata/be are stable on req). RVALID is still pulsed the next cycle
(the core waits for it to consider the store complete).

---

## Waveform tracing

VCD tracing is compiled **in or out** at the C++ level via `-DTRACE`.
This is independent of whether the Verilated model was compiled with
`--trace` or not.

---

## Co-simulation hook (future)

```cpp
SpikeBridge spike("test", "rv32imc");
Cve2Tb      rtl("test.hex");
rtl.reset(8);

while (!rtl.halted()) {
    rtl.step();
    if (rtl.rvfi_valid()) {
        spike.step();
        assert(rtl.rvfi().pc_rdata == (uint32_t)spike.get_pc());
        if (rtl.rvfi().rd_addr)
            assert(rtl.rvfi().rd_wdata ==
                   (uint32_t)spike.get_reg(rtl.rvfi().rd_addr));
    }
}
```

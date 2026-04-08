"""
trace_cve2.py  –  CVE2 RISC-V Pipeline Viewer
===============================================

Instantiates the CVE2 Verilated core via the cve2_py Python module,
runs the program to completion, collects RVFI retirement records, and
generates a rich interactive pipeline diagram in HTML (Konata-style).

Usage
─────
    python3 trace_cve2.py <hex_file> [max_cycles] [--no-browser]

Examples
────────
    python3 trace_cve2.py ../tests/build/test.hex
    python3 trace_cve2.py ../tests/build/test.hex 50000
    python3 trace_cve2.py ../tests/build/test.hex 50000 --no-browser

The generated HTML file (pipeline_<basename>.html) can be opened in any
modern browser.  No external dependencies are required for the viewer.

CVE2 Pipeline Stages (2-stage in-order pipeline)
──────────────────────────────────────────────────
  IF  – Instruction Fetch
  ID  – Instruction Decode + Execute
  WB  – Write-Back / Retire

The CVE2 is a 2-stage pipeline (IF and ID/EX), so every instruction
retires 2 cycles after being fetched (ideally, without stalls).
We reconstruct approximate stage timing from the retirement cycle:
  WB cycle  = retirement cycle (from RVFI)
  ID cycle  = WB - 1
  IF cycle  = WB - 2
Stalls push WB further out; we detect stalls by comparing consecutive
retirement cycles and mark the stall slots visually.
"""

import os
import sys
import json
import struct
import webbrowser
import argparse
import textwrap

# ============================================================================
# libstdc++ preload — Anaconda / conda-forge compatibility fix
# ============================================================================
# Anaconda ships its own libstdc++.so.6 which is often older than the one
# used to compile cve2_py.so (the system GCC).  When Python (from Anaconda)
# dlopen()s cve2_py.so it resolves libstdc++ against Anaconda's copy first,
# which may lack newer GLIBCXX_3.4.x symbols, producing:
#
#   version `GLIBCXX_3.4.32' not found
#
# Fix: preload the system libstdc++ with RTLD_GLOBAL *before* importing
# cve2_py so the dynamic linker picks up the correct version.
# We locate it via ldconfig rather than hard-coding a path.
# This is a no-op on systems where Anaconda's libstdc++ is already new
# enough, or where the user is not using Anaconda at all.

def _preload_system_libstdcxx() -> None:
    import ctypes
    import ctypes.util
    import subprocess

    # First try the standard ctypes search (works when LD_LIBRARY_PATH is
    # already pointing at the system lib).
    path = ctypes.util.find_library("stdc++")
    if path and "conda" not in path and "anaconda" not in path.lower():
        try:
            ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL)
            return
        except OSError:
            pass

    # Fall back to asking ldconfig for the full path of the system libstdc++.
    try:
        out = subprocess.check_output(
            ["ldconfig", "-p"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            if "libstdc++.so.6" in line and "=>" in line:
                candidate = line.split("=>")[-1].strip()
                # Skip anything inside conda/anaconda trees
                if "conda" in candidate.lower() or "anaconda" in candidate.lower():
                    continue
                try:
                    ctypes.CDLL(candidate, mode=ctypes.RTLD_GLOBAL)
                    return
                except OSError:
                    continue
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass  # ldconfig not available (macOS, some containers) — silently skip

_preload_system_libstdcxx()


# ============================================================================
# ABI Register Names
# ============================================================================

ABI = [
    "zero", "ra",  "sp",  "gp",  "tp",  "t0",  "t1",  "t2",
    "s0",   "s1",  "a0",  "a1",  "a2",  "a3",  "a4",  "a5",
    "a6",   "a7",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
    "s8",   "s9",  "s10", "s11", "t3",  "t4",  "t5",  "t6",
]


# ============================================================================
# Cve2Runner  –  thin Python wrapper around the cve2_py extension
# ============================================================================

class Cve2Runner:
    """
    Wraps the cve2_py Pybind11 module.
    Constructs a Cve2Tb with 0-delay bus (maximum performance) and
    runs the program to completion.
    """

    def __init__(self, hex_path: str, max_cycles: int = 1_000_000):

        # Get the path to the folder containing spike_py.so
        wrapper_path = os.path.abspath("./cve2")

        if wrapper_path not in sys.path:
            sys.path.append(wrapper_path)

        try:
            import cve2_py
        except ImportError as e:
            raise ImportError(
                f"\n[ERROR] Cannot import cve2_py: {e}\n"
                "Please build it first:\n"
                "  cd cve2 && make setup verilate cve2_lib cve2_py\n"
            ) from e

        if not os.path.isfile(hex_path):
            raise FileNotFoundError(f"[ERROR] HEX file not found: {hex_path}")

        print(f"[CVE2] Loading  : {hex_path}")
        print(f"[CVE2] Max cycles: {max_cycles}")
        print(f"[CVE2] Bus mode  : 0-delay (max performance)")

        # Construct with default 0-delay bus for maximum throughput
        self.tb = cve2_py.Cve2Tb(
            hex_path,
            # boot_addr, max_cycles, rng_seed, gnt_prob_num, gnt_prob_den, max_rvalid_delay
            0x00001000,
            max_cycles,
            42,
            1, 1, 0,   # 100% GNT probability, 0 extra RVALID delay
        )

    def run(self, reset_cycles: int = 8):
        """Reset and step until halted. Returns list[RetiredInsn]."""
        log = self.tb.run_to_halt(reset_cycles)
        total_cycles = self.tb.cycle()
        print(f"[CVE2] Halted after {total_cycles} cycles, {len(log)} instructions retired.")
        return log, total_cycles


# ============================================================================
# Pipeline reconstruction helpers
# ============================================================================

# CVE2 has 2 pipeline stages (IF, ID/EX+WB).
# We approximate entry cycle of each stage from the retirement cycle.
STAGE_NAMES = ["IF", "ID", "WB"]
STAGE_OFFSETS = {
    "IF": -2,
    "ID": -1,
    "WB":  0,
}


def build_pipeline_data(log, total_cycles: int):
    """
    Reconstruct approximate per-instruction pipeline timing.

    Returns a list of dicts suitable for JSON serialisation:
      { pc, insn_hex, disasm_hint, order,
        retire_cycle, stages: {IF: c, ID: c, WB: c},
        stall_cycles: int,
        rd_name, rd_wdata, rs1_name, rs2_name,
        is_load, is_store, is_branch, is_trap }
    """
    instructions = []
    prev_retire = None

    for entry in log:
        r = entry.rvfi
        retire = int(entry.cycle)
        stalls = 0
        if prev_retire is not None:
            # Ideal throughput: 1 retirement per cycle.
            # Extra cycles indicate stalls (fetch miss, data dependency, etc.)
            delta = retire - prev_retire
            stalls = max(0, delta - 1)

        stages = {
            "IF": max(1, retire + STAGE_OFFSETS["IF"]),
            "ID": max(1, retire + STAGE_OFFSETS["ID"]),
            "WB": retire,
        }

        insn = int(r.insn)
        pc   = int(r.pc_rdata)
        rd   = int(r.rd_addr)
        rs1  = int(r.rs1_addr)
        rs2  = int(r.rs2_addr)

        is_load   = bool(r.mem_rmask)
        is_store  = bool(r.mem_wmask)
        is_branch = (pc != int(r.pc_wdata) - 4) and not is_load and not is_store and rd == 0
        is_trap   = bool(r.trap)

        instructions.append({
            "order":        int(r.order),
            "pc":           f"0x{pc:08x}",
            "pc_int":       pc,
            "insn_hex":     f"0x{insn:08x}",
            "disasm_hint":  decode_hint(insn, rd, rs1, rs2),
            "retire_cycle": retire,
            "stages":       stages,
            "stall_cycles": stalls,
            "rd_name":      ABI[rd]  if rd  < 32 else f"x{rd}",
            "rd_wdata":     f"0x{int(r.rd_wdata):08x}",
            "rs1_name":     ABI[rs1] if rs1 < 32 else f"x{rs1}",
            "rs2_name":     ABI[rs2] if rs2 < 32 else f"x{rs2}",
            "mem_addr":     f"0x{int(r.mem_addr):08x}",
            "is_load":      is_load,
            "is_store":     is_store,
            "is_branch":    is_branch,
            "is_trap":      is_trap,
        })
        prev_retire = retire

    return instructions


def decode_hint(insn: int, rd: int, rs1: int, rs2: int) -> str:
    """
    Produce a minimal mnemonic hint from the raw 32-bit instruction word.
    This is deliberately lightweight — just enough for the tooltip label.
    A full disassembler is not included here; the Spike wrapper can be
    used for that if needed.
    """
    opcode  = insn & 0x7F
    funct3  = (insn >> 12) & 0x7
    funct7  = (insn >> 25) & 0x7F
    rd_n    = ABI[rd]  if rd  < 32 else f"x{rd}"
    rs1_n   = ABI[rs1] if rs1 < 32 else f"x{rs1}"
    rs2_n   = ABI[rs2] if rs2 < 32 else f"x{rs2}"

    OPCODES = {
        0x33: {  # R-type
            (0x0, 0x00): f"add  {rd_n},{rs1_n},{rs2_n}",
            (0x0, 0x20): f"sub  {rd_n},{rs1_n},{rs2_n}",
            (0x4, 0x00): f"xor  {rd_n},{rs1_n},{rs2_n}",
            (0x6, 0x00): f"or   {rd_n},{rs1_n},{rs2_n}",
            (0x7, 0x00): f"and  {rd_n},{rs1_n},{rs2_n}",
            (0x1, 0x00): f"sll  {rd_n},{rs1_n},{rs2_n}",
            (0x5, 0x00): f"srl  {rd_n},{rs1_n},{rs2_n}",
            (0x5, 0x20): f"sra  {rd_n},{rs1_n},{rs2_n}",
            (0x2, 0x00): f"slt  {rd_n},{rs1_n},{rs2_n}",
            (0x3, 0x00): f"sltu {rd_n},{rs1_n},{rs2_n}",
            (0x0, 0x01): f"mul  {rd_n},{rs1_n},{rs2_n}",
        },
        0x13: {  # I-type ALU
            0x0: f"addi {rd_n},{rs1_n},imm",
            0x4: f"xori {rd_n},{rs1_n},imm",
            0x6: f"ori  {rd_n},{rs1_n},imm",
            0x7: f"andi {rd_n},{rs1_n},imm",
            0x2: f"slti {rd_n},{rs1_n},imm",
            0x3: f"sltiu {rd_n},{rs1_n},imm",
        },
        0x03: {  # Load
            0x0: f"lb   {rd_n},{rs1_n}",
            0x1: f"lh   {rd_n},{rs1_n}",
            0x2: f"lw   {rd_n},{rs1_n}",
            0x4: f"lbu  {rd_n},{rs1_n}",
            0x5: f"lhu  {rd_n},{rs1_n}",
        },
        0x23: {  # Store
            0x0: f"sb   {rs2_n},{rs1_n}",
            0x1: f"sh   {rs2_n},{rs1_n}",
            0x2: f"sw   {rs2_n},{rs1_n}",
        },
        0x63: {  # Branch
            0x0: f"beq  {rs1_n},{rs2_n}",
            0x1: f"bne  {rs1_n},{rs2_n}",
            0x4: f"blt  {rs1_n},{rs2_n}",
            0x5: f"bge  {rs1_n},{rs2_n}",
            0x6: f"bltu {rs1_n},{rs2_n}",
            0x7: f"bgeu {rs1_n},{rs2_n}",
        },
    }

    SIMPLE = {
        0x37: f"lui  {rd_n},imm",
        0x17: f"auipc {rd_n},imm",
        0x6F: f"jal  {rd_n},imm",
        0x67: f"jalr {rd_n},{rs1_n},imm",
        0x73: "ecall" if (insn >> 20) == 0 else "csr...",
    }

    if opcode in SIMPLE:
        return SIMPLE[opcode]

    if opcode == 0x33:
        return OPCODES[0x33].get((funct3, funct7), f"r-type {rd_n}")
    if opcode in (0x13, 0x03, 0x23, 0x63):
        tbl = OPCODES.get(opcode, {})
        return tbl.get(funct3, f"op 0x{opcode:02x}")

    # Compressed instructions (16-bit)
    if (insn & 0x3) != 0x3:
        return "c.insn"

    return f"op 0x{opcode:02x}"


# ============================================================================
# HTML / JavaScript pipeline viewer generation
# ============================================================================

def generate_html(instructions, total_cycles: int, hex_path: str) -> str:
    """
    Generate a self-contained interactive HTML pipeline viewer.
    """
    data_json = json.dumps(instructions)
    basename  = os.path.basename(hex_path)

    # Colour palette for pipeline stages
    STAGE_COLOURS = {
        "IF":  "#4ade80",   # emerald green
        "ID":  "#60a5fa",   # sky blue
        "WB":  "#f472b6",   # pink
    }
    stage_colours_json = json.dumps(STAGE_COLOURS)

    html = textwrap.dedent(f"""\
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE2 Pipeline — {basename}</title>
    <style>
    /* ── Reset & Base ──────────────────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg:          #0d1117;
      --surface:     #161b22;
      --surface2:    #1c2333;
      --border:      #30363d;
      --text:        #e6edf3;
      --text-muted:  #7d8590;
      --accent:      #58a6ff;
      --green:       #3fb950;
      --yellow:      #d29922;
      --red:         #f85149;
      --purple:      #bc8cff;
      --orange:      #ffa657;
      --if-color:    #4ade80;
      --id-color:    #60a5fa;
      --wb-color:    #f472b6;
      --stall-color: #374151;
      --font-mono:   'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
      --font-ui:     'Inter', 'Segoe UI', system-ui, sans-serif;
      --row-h:       28px;
      --cell-w:      28px;
      --label-w:     240px;
    }}

    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@300;400;500;600;700&display=swap');

    html, body {{
      height: 100%;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-ui);
      font-size: 13px;
      line-height: 1.5;
      overflow: hidden;
    }}

    /* ── Layout ────────────────────────────────────────────────────── */
    #app {{
      display: flex;
      flex-direction: column;
      height: 100vh;
    }}

    /* ── Header ─────────────────────────────────────────────────────  */
    #header {{
      background: linear-gradient(135deg, #0d1117 0%, #1a2744 50%, #0d1117 100%);
      border-bottom: 1px solid var(--border);
      padding: 14px 24px;
      display: flex;
      align-items: center;
      gap: 20px;
      flex-shrink: 0;
      position: relative;
      overflow: hidden;
    }}
    #header::before {{
      content: '';
      position: absolute;
      inset: 0;
      background: repeating-linear-gradient(
        90deg,
        transparent,
        transparent 80px,
        rgba(88,166,255,0.03) 80px,
        rgba(88,166,255,0.03) 81px
      );
      pointer-events: none;
    }}
    .header-chip {{
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 4px 10px;
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-muted);
      white-space: nowrap;
    }}
    .header-chip span {{
      color: var(--accent);
      font-weight: 600;
    }}
    h1 {{
      font-size: 15px;
      font-weight: 600;
      letter-spacing: 0.02em;
      color: var(--text);
      flex: 1;
    }}
    h1 small {{
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 400;
      margin-left: 8px;
    }}

    /* ── Toolbar ────────────────────────────────────────────────────  */
    #toolbar {{
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 8px 16px;
      display: flex;
      align-items: center;
      gap: 12px;
      flex-shrink: 0;
      flex-wrap: wrap;
    }}
    .toolbar-label {{
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 600;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      color: var(--text-muted);
    }}
    .legend-swatch {{
      width: 16px;
      height: 14px;
      border-radius: 3px;
      flex-shrink: 0;
    }}
    .spacer {{ flex: 1; }}
    .btn {{
      background: var(--surface2);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 4px 12px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      font-family: var(--font-ui);
      transition: background 0.15s, border-color 0.15s;
    }}
    .btn:hover {{ background: #2d333b; border-color: var(--accent); }}
    .btn.active {{ background: rgba(88,166,255,0.15); border-color: var(--accent); color: var(--accent); }}

    /* search */
    #search {{
      background: var(--surface2);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-family: var(--font-mono);
      width: 180px;
      outline: none;
      transition: border-color 0.15s;
    }}
    #search:focus {{ border-color: var(--accent); }}
    #search::placeholder {{ color: var(--text-muted); }}

    /* zoom */
    #zoom-range {{
      width: 80px;
      accent-color: var(--accent);
    }}

    /* ── Main area ──────────────────────────────────────────────────  */
    #main {{
      flex: 1;
      display: flex;
      overflow: hidden;
      position: relative;
    }}

    /* ── Frozen instruction label panel ─────────────────────────────  */
    #label-panel {{
      width: var(--label-w);
      flex-shrink: 0;
      overflow-y: auto;
      overflow-x: hidden;
      border-right: 1px solid var(--border);
      background: var(--surface);
      scrollbar-width: none;
    }}
    #label-panel::-webkit-scrollbar {{ display: none; }}

    /* header row in label panel */
    #label-header {{
      height: var(--row-h);
      line-height: var(--row-h);
      padding: 0 12px;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
      background: var(--bg);
      position: sticky;
      top: 0;
      z-index: 10;
      display: flex;
      gap: 6px;
    }}

    .lrow {{
      height: var(--row-h);
      display: flex;
      align-items: center;
      padding: 0 10px;
      gap: 6px;
      cursor: pointer;
      border-bottom: 1px solid transparent;
      transition: background 0.1s;
      font-family: var(--font-mono);
      font-size: 11px;
    }}
    .lrow:hover, .lrow.selected {{ background: rgba(88,166,255,0.1); }}
    .lrow.selected {{ border-left: 2px solid var(--accent); }}
    .lrow.dimmed {{ opacity: 0.3; }}

    .insn-order {{
      color: var(--text-muted);
      min-width: 28px;
      text-align: right;
      font-size: 10px;
    }}
    .insn-pc {{
      color: var(--accent);
      min-width: 86px;
      font-size: 11px;
    }}
    .insn-mnem {{
      color: var(--text);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .badge {{
      font-size: 9px;
      padding: 1px 4px;
      border-radius: 3px;
      font-weight: 700;
      flex-shrink: 0;
      letter-spacing: 0.04em;
    }}
    .badge-load  {{ background: rgba(250,204,21,0.2);  color: #fbbf24; }}
    .badge-store {{ background: rgba(251,146,60,0.2);  color: var(--orange); }}
    .badge-branch{{ background: rgba(167,139,250,0.2); color: var(--purple); }}
    .badge-trap  {{ background: rgba(248,81,73,0.2);   color: var(--red); }}

    /* ── Cycle chart panel ──────────────────────────────────────────  */
    #chart-panel {{
      flex: 1;
      overflow: auto;
      position: relative;
      background: var(--bg);
    }}

    #chart-canvas {{
      position: relative;
      /* width and min-height set by JS */
    }}

    /* Sticky cycle header */
    #cycle-header {{
      position: sticky;
      top: 0;
      z-index: 10;
      background: var(--bg);
      border-bottom: 1px solid var(--border);
      height: var(--row-h);
      display: flex;
      align-items: stretch;
    }}

    .cycle-tick {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
      font-size: 9px;
      color: var(--text-muted);
      border-right: 1px solid var(--border);
      flex-shrink: 0;
    }}
    .cycle-tick.major {{
      color: var(--text);
      background: rgba(255,255,255,0.03);
      font-weight: 700;
    }}

    /* Row in chart */
    .crow {{
      height: var(--row-h);
      display: flex;
      align-items: center;
      position: relative;
      border-bottom: 1px solid rgba(48,54,61,0.5);
      transition: background 0.1s;
    }}
    .crow:hover {{ background: rgba(88,166,255,0.05); }}
    .crow.selected {{ background: rgba(88,166,255,0.08); }}
    .crow.dimmed {{ opacity: 0.3; }}

    /* Stage cell */
    .stage-cell {{
      position: absolute;
      height: 20px;
      top: 4px;
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
      font-size: 10px;
      font-weight: 700;
      cursor: pointer;
      transition: filter 0.15s, transform 0.1s;
      box-shadow: 0 1px 3px rgba(0,0,0,0.4);
      letter-spacing: 0.04em;
      user-select: none;
    }}
    .stage-cell:hover {{
      filter: brightness(1.25);
      transform: scaleY(1.1);
      z-index: 5;
    }}

    /* Empty cycle placeholder */
    .empty-cell {{
      position: absolute;
      height: 8px;
      top: 10px;
      border-radius: 2px;
      background: var(--stall-color);
      opacity: 0.6;
    }}

    /* ── Detail panel ───────────────────────────────────────────────  */
    #detail-panel {{
      width: 0;
      overflow: hidden;
      background: var(--surface);
      border-left: 1px solid var(--border);
      flex-shrink: 0;
      transition: width 0.2s ease;
      font-size: 12px;
    }}
    #detail-panel.open {{
      width: 280px;
    }}
    #detail-inner {{
      width: 280px;
      padding: 16px;
      overflow-y: auto;
      height: 100%;
    }}
    .detail-title {{
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 12px;
      color: var(--text);
      font-family: var(--font-mono);
    }}
    .detail-row {{
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      border-bottom: 1px solid rgba(48,54,61,0.4);
    }}
    .detail-key {{
      color: var(--text-muted);
      font-size: 11px;
    }}
    .detail-val {{
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 11px;
      text-align: right;
      word-break: break-all;
    }}
    .detail-val.highlight {{ color: var(--accent); }}
    .detail-section {{
      margin-top: 12px;
      margin-bottom: 4px;
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
    }}

    /* stage pills in detail */
    .stage-pill {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 700;
      margin-right: 4px;
      margin-bottom: 4px;
    }}
    .pill-IF {{ background: rgba(74,222,128,0.2); color: #4ade80; }}
    .pill-ID {{ background: rgba(96,165,250,0.2); color: #60a5fa; }}
    .pill-WB {{ background: rgba(244,114,182,0.2); color: #f472b6; }}

    /* ── Stats bar ──────────────────────────────────────────────────  */
    #statsbar {{
      background: var(--surface);
      border-top: 1px solid var(--border);
      padding: 6px 20px;
      display: flex;
      gap: 24px;
      font-size: 11px;
      color: var(--text-muted);
      flex-shrink: 0;
    }}
    .stat-val {{ color: var(--accent); font-weight: 600; font-family: var(--font-mono); }}

    /* ── Tooltip ────────────────────────────────────────────────────  */
    #tooltip {{
      position: fixed;
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 12px;
      font-size: 11px;
      pointer-events: none;
      z-index: 1000;
      display: none;
      max-width: 260px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
    }}
    #tooltip.show {{ display: block; }}
    .tt-pc    {{ color: var(--accent); font-family: var(--font-mono); font-weight: 600; }}
    .tt-mnem  {{ color: var(--text); margin: 3px 0; font-family: var(--font-mono); }}
    .tt-extra {{ color: var(--text-muted); font-size: 10px; }}
    </style>
    </head>
    <body>
    <div id="app">

      <!-- Header -->
      <div id="header">
        <h1>CVE2 Pipeline Viewer <small>{basename}</small></h1>
        <div class="header-chip">Total cycles: <span id="hdr-cycles">—</span></div>
        <div class="header-chip">Instructions: <span id="hdr-insns">—</span></div>
        <div class="header-chip">IPC: <span id="hdr-ipc">—</span></div>
        <div class="header-chip">Stall cycles: <span id="hdr-stalls">—</span></div>
      </div>

      <!-- Toolbar -->
      <div id="toolbar">
        <span class="toolbar-label">Stages:</span>
        <div class="legend-item"><div class="legend-swatch" style="background:#4ade80"></div>IF</div>
        <div class="legend-item"><div class="legend-swatch" style="background:#60a5fa"></div>ID</div>
        <div class="legend-item"><div class="legend-swatch" style="background:#f472b6"></div>WB</div>
        <div class="legend-item"><div class="legend-swatch" style="background:#374151"></div>Stall</div>
        &nbsp;
        <span class="toolbar-label">Filter:</span>
        <button class="btn active" data-filter="all"   onclick="setFilter(this,'all')">All</button>
        <button class="btn"        data-filter="load"  onclick="setFilter(this,'load')">Loads</button>
        <button class="btn"        data-filter="store" onclick="setFilter(this,'store')">Stores</button>
        <button class="btn"        data-filter="branch"onclick="setFilter(this,'branch')">Branches</button>
        <button class="btn"        data-filter="stall" onclick="setFilter(this,'stall')">Stalled</button>
        <div class="spacer"></div>
        <label for="search" style="font-size:11px;color:var(--text-muted)">🔍</label>
        <input id="search" type="text" placeholder="PC / mnemonic…" oninput="onSearch(this.value)">
        <span class="toolbar-label">Zoom:</span>
        <input id="zoom-range" type="range" min="14" max="48" value="28"
               oninput="setZoom(+this.value)">
        <button class="btn" onclick="resetView()">Reset</button>
      </div>

      <!-- Main -->
      <div id="main">
        <!-- Label panel -->
        <div id="label-panel">
          <div id="label-header">
            <span style="min-width:28px;">#</span>
            <span style="min-width:86px;">PC</span>
            <span>Instruction</span>
          </div>
          <div id="label-rows"></div>
        </div>

        <!-- Chart panel -->
        <div id="chart-panel" onscroll="syncScroll(this)">
          <div id="chart-canvas">
            <div id="cycle-header"></div>
            <div id="chart-rows"></div>
          </div>
        </div>

        <!-- Detail panel -->
        <div id="detail-panel">
          <div id="detail-inner">
            <div class="detail-title">Instruction Detail</div>
            <div id="detail-content">
              <div style="color:var(--text-muted);font-size:12px;">
                Click an instruction to see details.
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Stats bar -->
      <div id="statsbar">
        <span>Visible: <span class="stat-val" id="stat-visible">—</span></span>
        <span>Selected cycle: <span class="stat-val" id="stat-sel-cycle">—</span></span>
        <span>Selected PC: <span class="stat-val" id="stat-sel-pc">—</span></span>
        <span style="flex:1"></span>
        <span style="font-size:10px;color:var(--text-muted)">
          Click instruction to inspect · Scroll to pan · Zoom slider to resize
        </span>
      </div>
    </div>

    <!-- Tooltip -->
    <div id="tooltip"></div>

    <script>
    // ── Data ──────────────────────────────────────────────────────────────
    const INSNS       = {data_json};
    const TOTAL_CYCLES = {total_cycles};
    const STAGE_COLORS = {stage_colours_json};
    const STAGE_NAMES  = ["IF","ID","WB"];

    // ── State ─────────────────────────────────────────────────────────────
    let cellW      = 28;   // px per cycle column
    let filter     = 'all';
    let searchTerm = '';
    let selectedIdx = -1;
    let visibleIdxs = [];

    // ── Dom refs ──────────────────────────────────────────────────────────
    const labelRows   = document.getElementById('label-rows');
    const chartRows   = document.getElementById('chart-rows');
    const cycleHeader = document.getElementById('cycle-header');
    const chartCanvas = document.getElementById('chart-canvas');
    const chartPanel  = document.getElementById('chart-panel');
    const detailPanel = document.getElementById('detail-panel');
    const tooltip     = document.getElementById('tooltip');

    // ── Stats ─────────────────────────────────────────────────────────────
    const totalStalls = INSNS.reduce((a,i)=>a+i.stall_cycles,0);
    document.getElementById('hdr-cycles').textContent = TOTAL_CYCLES;
    document.getElementById('hdr-insns').textContent  = INSNS.length;
    document.getElementById('hdr-ipc').textContent    =
        INSNS.length > 0 ? (INSNS.length / TOTAL_CYCLES).toFixed(3) : '—';
    document.getElementById('hdr-stalls').textContent = totalStalls;

    // ── Compute visible cycle range ───────────────────────────────────────
    let minCycle = Infinity, maxCycle = 0;
    INSNS.forEach(i => {{
        Object.values(i.stages).forEach(c => {{
            if(c < minCycle) minCycle = c;
            if(c > maxCycle) maxCycle = c;
        }});
    }});
    minCycle = Math.max(1, minCycle - 2);
    maxCycle = Math.min(TOTAL_CYCLES, maxCycle + 3);
    const numCycles = maxCycle - minCycle + 1;

    // ── Filter logic ──────────────────────────────────────────────────────
    function matchesFilter(insn) {{
        if(filter === 'load'   && !insn.is_load)    return false;
        if(filter === 'store'  && !insn.is_store)   return false;
        if(filter === 'branch' && !insn.is_branch)  return false;
        if(filter === 'stall'  && insn.stall_cycles < 1) return false;
        if(searchTerm) {{
            const q = searchTerm.toLowerCase();
            if(!insn.pc.includes(q) && !insn.disasm_hint.toLowerCase().includes(q))
                return false;
        }}
        return true;
    }}

    // ── Build visible index list ──────────────────────────────────────────
    function buildVisible() {{
        visibleIdxs = [];
        INSNS.forEach((insn, idx) => {{ if(matchesFilter(insn)) visibleIdxs.push(idx); }});
        document.getElementById('stat-visible').textContent = visibleIdxs.length;
    }}

    // ── Render ────────────────────────────────────────────────────────────
    function render() {{
        buildVisible();
        renderCycleHeader();
        renderRows();
    }}

    function renderCycleHeader() {{
        cycleHeader.innerHTML = '';
        const totalW = numCycles * cellW;
        chartCanvas.style.minWidth = (totalW + 20) + 'px';

        for(let c = minCycle; c <= maxCycle; c++) {{
            const el = document.createElement('div');
            el.className = 'cycle-tick' + (c % 5 === 0 ? ' major' : '');
            el.style.width = cellW + 'px';
            el.style.minWidth = cellW + 'px';
            if(cellW >= 20 || c % 5 === 0)
                el.textContent = c;
            cycleHeader.appendChild(el);
        }}
    }}

    function renderRows() {{
        labelRows.innerHTML = '';
        chartRows.innerHTML = '';

        visibleIdxs.forEach((idx, vi) => {{
            const insn = INSNS[idx];
            const isDimmed = (filter !== 'all' || searchTerm) && !matchesFilter(insn);
            const isSelected = idx === selectedIdx;

            // ── Label row ──────────────────────────────────────────────
            const lr = document.createElement('div');
            lr.className = 'lrow' + (isSelected ? ' selected' : '') + (isDimmed ? ' dimmed' : '');
            lr.dataset.idx = idx;
            lr.onclick = () => selectInsn(idx);

            lr.innerHTML =
                `<span class="insn-order">${{insn.order}}</span>`+
                `<span class="insn-pc">${{insn.pc}}</span>`+
                `<span class="insn-mnem">${{escHtml(insn.disasm_hint)}}</span>`+
                (insn.is_load   ? '<span class="badge badge-load">LD</span>'  : '')+
                (insn.is_store  ? '<span class="badge badge-store">ST</span>' : '')+
                (insn.is_branch ? '<span class="badge badge-branch">BR</span>': '')+
                (insn.is_trap   ? '<span class="badge badge-trap">TRAP</span>': '');
            labelRows.appendChild(lr);

            // ── Chart row ──────────────────────────────────────────────
            const cr = document.createElement('div');
            cr.className = 'crow' + (isSelected ? ' selected' : '') + (isDimmed ? ' dimmed' : '');
            cr.style.width = (numCycles * cellW) + 'px';
            cr.dataset.idx = idx;
            cr.onclick = () => selectInsn(idx);

            // Stall visualisation: fill gap before WB with stall marker
            if(insn.stall_cycles > 0) {{
                const stallStart = insn.stages.WB - insn.stall_cycles;
                const left = (stallStart - minCycle) * cellW;
                const width = insn.stall_cycles * cellW - 2;
                if(width > 0) {{
                    const sc = document.createElement('div');
                    sc.className = 'empty-cell';
                    sc.style.left  = left + 'px';
                    sc.style.width = Math.max(4, width) + 'px';
                    cr.appendChild(sc);
                }}
            }}

            // Stage cells
            STAGE_NAMES.forEach(stage => {{
                const cycleNum = insn.stages[stage];
                if(!cycleNum) return;
                const left  = (cycleNum - minCycle) * cellW + 1;
                const width = Math.max(cellW - 2, 10);
                const sc = document.createElement('div');
                sc.className = 'stage-cell';
                sc.style.left       = left + 'px';
                sc.style.width      = width + 'px';
                sc.style.background = STAGE_COLORS[stage];
                sc.style.color      = '#0d1117';

                if(cellW >= 22)
                    sc.textContent = stage;

                sc.addEventListener('mouseenter', e => showTooltip(e, insn, stage, cycleNum));
                sc.addEventListener('mouseleave', hideTooltip);
                cr.appendChild(sc);
            }});

            chartRows.appendChild(cr);
        }});
    }}

    // ── Detail panel ──────────────────────────────────────────────────────
    function selectInsn(idx) {{
        selectedIdx = (selectedIdx === idx) ? -1 : idx;
        if(selectedIdx === -1) {{
            detailPanel.classList.remove('open');
            document.getElementById('stat-sel-cycle').textContent = '—';
            document.getElementById('stat-sel-pc').textContent    = '—';
        }} else {{
            const insn = INSNS[idx];
            detailPanel.classList.add('open');
            document.getElementById('stat-sel-cycle').textContent = insn.retire_cycle;
            document.getElementById('stat-sel-pc').textContent    = insn.pc;
            renderDetail(insn);
        }}
        // Re-render to update selection highlight without full rebuild
        document.querySelectorAll('.lrow').forEach(el => {{
            const i = +el.dataset.idx;
            el.classList.toggle('selected', i === selectedIdx);
        }});
        document.querySelectorAll('.crow').forEach(el => {{
            const i = +el.dataset.idx;
            el.classList.toggle('selected', i === selectedIdx);
        }});
    }}

    function renderDetail(insn) {{
        const dc = document.getElementById('detail-content');
        const row = (k,v,hi=false) =>
            `<div class="detail-row">
               <span class="detail-key">${{k}}</span>
               <span class="detail-val ${{hi?'highlight':''}}">${{v}}</span>
             </div>`;

        dc.innerHTML =
            `<div class="detail-title">${{escHtml(insn.disasm_hint)}}</div>`+
            row('Order', '#'+insn.order)+
            row('PC', insn.pc, true)+
            row('Encoding', insn.insn_hex)+
            row('Retire cycle', insn.retire_cycle)+
            row('Stall cycles', insn.stall_cycles || '0')+
            `<div class="detail-section">Pipeline Stages</div>`+
            `<div style="margin:4px 0">`+
            STAGE_NAMES.map(s =>
                `<span class="stage-pill pill-${{s}}">${{s}} @${{insn.stages[s]}}</span>`
            ).join('')+
            `</div>`+
            `<div class="detail-section">Registers</div>`+
            row('rd',   insn.rd_addr  !== 0 ? `${{insn.rd_name}} = ${{insn.rd_wdata}}`  : '—')+
            row('rs1',  insn.rs1_name)+
            row('rs2',  insn.rs2_name)+
            (insn.is_load  ? row('Load addr', insn.mem_addr) : '')+
            (insn.is_store ? row('Store addr', insn.mem_addr) : '')+
            (insn.is_trap  ? `<div style="margin-top:8px;color:var(--red);font-weight:600">⚠ TRAP</div>` : '');
    }}

    // ── Tooltip ───────────────────────────────────────────────────────────
    function showTooltip(e, insn, stage, cycle) {{
        tooltip.innerHTML =
            `<div class="tt-pc">${{insn.pc}}</div>`+
            `<div class="tt-mnem">${{escHtml(insn.disasm_hint)}}</div>`+
            `<div class="tt-extra">Stage: <b>${{stage}}</b> @ cycle <b>${{cycle}}</b></div>`+
            (insn.stall_cycles > 0 ? `<div class="tt-extra" style="color:#fbbf24">⚡ ${{insn.stall_cycles}} stall cycle(s)</div>` : '')+
            (insn.is_load  ? `<div class="tt-extra">Load ← ${{insn.mem_addr}}</div>` : '')+
            (insn.is_store ? `<div class="tt-extra">Store → ${{insn.mem_addr}}</div>`: '');
        tooltip.classList.add('show');
        positionTooltip(e);
    }}
    function hideTooltip() {{ tooltip.classList.remove('show'); }}
    document.addEventListener('mousemove', e => {{
        if(tooltip.classList.contains('show')) positionTooltip(e);
    }});
    function positionTooltip(e) {{
        const x = e.clientX + 14, y = e.clientY + 14;
        const w = tooltip.offsetWidth, h = tooltip.offsetHeight;
        tooltip.style.left = (x + w > window.innerWidth  ? x - w - 20 : x) + 'px';
        tooltip.style.top  = (y + h > window.innerHeight ? y - h - 20 : y) + 'px';
    }}

    // ── Scroll sync (label panel mirrors chart panel) ─────────────────────
    function syncScroll(src) {{
        document.getElementById('label-panel').scrollTop = src.scrollTop;
    }}

    // ── Zoom ─────────────────────────────────────────────────────────────
    function setZoom(w) {{
        cellW = w;
        document.documentElement.style.setProperty('--cell-w', w+'px');
        render();
    }}

    // ── Filter / search ──────────────────────────────────────────────────
    function setFilter(btn, f) {{
        filter = f;
        document.querySelectorAll('.btn[data-filter]').forEach(b =>
            b.classList.toggle('active', b.dataset.filter === f));
        render();
    }}
    function onSearch(val) {{
        searchTerm = val.trim();
        render();
    }}

    // ── Reset ────────────────────────────────────────────────────────────
    function resetView() {{
        filter = 'all';
        searchTerm = '';
        selectedIdx = -1;
        document.getElementById('search').value = '';
        document.getElementById('zoom-range').value = 28;
        cellW = 28;
        detailPanel.classList.remove('open');
        document.querySelectorAll('.btn[data-filter]').forEach(b =>
            b.classList.toggle('active', b.dataset.filter === 'all'));
        render();
    }}

    // ── Utils ─────────────────────────────────────────────────────────────
    function escHtml(s) {{
        return String(s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }}

    // ── Init ─────────────────────────────────────────────────────────────
    render();
    </script>
    </body>
    </html>
    """)

    return html


# ============================================================================
# Entry point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="CVE2 RISC-V Pipeline Viewer — runs the core and generates "
                    "an interactive HTML pipeline diagram."
    )
    parser.add_argument("hex_file",    help="Path to the Verilog HEX file (test.hex)")
    parser.add_argument("max_cycles",  nargs="?", type=int, default=1_000_000,
                        help="Maximum simulation cycles (default: 1 000 000)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open the HTML viewer automatically")
    parser.add_argument("--output", default=None,
                        help="Output HTML filename (default: pipeline_<basename>.html)")
    args = parser.parse_args()

    # ── Run CVE2 simulation ───────────────────────────────────────────────
    runner  = Cve2Runner(args.hex_file, args.max_cycles)
    log, total_cycles = runner.run()

    if not log:
        print("[WARNING] No instructions retired — nothing to visualise.")
        sys.exit(0)

    # ── Print text summary ────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"{'CVE2 RVFI Retirement Log':^70}")
    print(f"{'='*70}")
    print(f"{'#':<5}  {'Cycle':<8}  {'PC':<12}  {'Encoding':<12}  {'Mnemonic'}")
    print("-" * 70)
    for entry in log:
        r = entry.rvfi
        pc      = int(r.pc_rdata)
        insn    = int(r.insn)
        cycle   = int(entry.cycle)
        rd      = int(r.rd_addr)
        rs1     = int(r.rs1_addr)
        rs2     = int(r.rs2_addr)
        mnem    = decode_hint(insn, rd, rs1, rs2)
        print(f"{int(r.order):<5}  {cycle:<8}  0x{pc:08x}  0x{insn:08x}  {mnem}")
    print(f"{'='*70}\n")

    total_stalls = sum(e['stall_cycles'] for e in build_pipeline_data(log, total_cycles))
    ipc = len(log) / total_cycles if total_cycles > 0 else 0
    print(f"  Instructions   : {len(log)}")
    print(f"  Total cycles   : {total_cycles}")
    print(f"  IPC            : {ipc:.4f}")
    print(f"  Stall cycles   : {total_stalls}")
    print()

    # ── Generate HTML ────────────────────────────────────────────────────
    instructions = build_pipeline_data(log, total_cycles)
    html = generate_html(instructions, total_cycles, args.hex_file)

    basename = os.path.splitext(os.path.basename(args.hex_file))[0]
    out_path = args.output or f"pipeline_{basename}.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Pipeline viewer written to: {out_path}")

    if not args.no_browser:
        url = "file://" + os.path.abspath(out_path)
        print(f"[OK] Opening in browser: {url}")
        webbrowser.open(url)


if __name__ == "__main__":
    main()

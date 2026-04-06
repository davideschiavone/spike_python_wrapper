#include <riscv/sim.h>
#include <riscv/processor.h>
#include <riscv/devices.h>
#include <riscv/cfg.h>
#include <riscv/disasm.h>
#include <riscv/decode.h>
#include <riscv/mmu.h>
#include <riscv/vector_unit.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <vector>
#include <string>
#include <memory>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>

namespace py = pybind11;

class SpikeBridge {
public:
    std::unique_ptr<cfg_t> cfg;
    sim_t *sim;
    processor_t *cpu;

    SpikeBridge(const char* program) {
        try {

            std::string program_str(program);
            cfg = std::make_unique<cfg_t>();
            cfg->isa = "rv64gcv_zba_zbb_zbs_zicond_zfa_zcb";
            cfg->mem_layout = {
                mem_cfg_t(0x00001000, 0x1000),     // BootROM
                mem_cfg_t(0x80000000, 0x1000000)   // RAM (16MB)
            };

            // Spike MEMORY OBJECTS
            auto boot_mem = std::make_shared<mem_t>(0x1000);
            auto ram_mem = std::make_shared<mem_t>(0x1000000);

            // Not clear how Spike uses these, but they are required for the sim_t constructor
            std::vector<std::pair<reg_t, abstract_mem_t*>> mems;
            mems.push_back(std::make_pair(reg_t(0x00001000), boot_mem.get()));
            mems.push_back(std::make_pair(reg_t(0x80000000), ram_mem.get()));

            // HTIF arguments, even if non-HTIF, Spike expects an ELF path here for loading
            std::string elf_path = program_str + ".elf";
            std::vector<std::string> htif_args = { elf_path };
            std::vector<std::pair<const device_factory_t*, std::vector<std::string>>> plugin_devices;

            std::cout << "[C++] sim_t initialiazed: " << elf_path << std::endl;

            // sim_t constructor: config, debug, mems, plugin devices, htif args, debug config, debug output, etc.
            sim = new sim_t(
                cfg.get(), false, mems, plugin_devices, false, htif_args,
                debug_module_config_t(), nullptr, false, nullptr, false, stdout, std::nullopt
            );

            // adding memory devices to the sim (Spike's internal mapping)
            sim->add_device(0x00001000, boot_mem);
            sim->add_device(0x80000000, ram_mem);

            // Set VLEN and ELEN for all cores (even if we have only 1 core, this is the correct way to do it)
            for (size_t i = 0; i < sim->nprocs(); i++) {
                //default values in Spike are VLEN=128 and ELEN=64, but we want to set VLEN=256 for our tests
                sim->get_core(i)->VU.VLEN = 256; // VLEN in bits
                sim->get_core(i)->VU.ELEN = 64;  // ELEN in bits
            }

            auto load_hex = [&](const std::string& path) {
                std::ifstream file(path);
                if (!file.is_open()) {
                    std::cerr << "[ERROR] Could not open hex file: " << path << std::endl;
                    return;
                }

                std::string word;
                uint64_t current_addr = 0;
                auto mmu = sim->get_core(0)->get_mmu();

                // Using '>>' skips whitespace automatically
                while (file >> word) {
                    if (word[0] == '@') {
                        // Set new base address (e.g., @80000000)
                        current_addr = std::stoull(word.substr(1), nullptr, 16);
                    } else {
                        // Read one byte (e.g., "81")
                        uint8_t byte_val = (uint8_t)std::stoul(word, nullptr, 16);

                        // Store 1 byte at a time
                        // This is safe and correctly handles Little-Endian
                        // because the .hex file is already ordered byte-by-byte
                        mmu->store<uint8_t>(current_addr, byte_val);
                        current_addr++;
                    }
                }
                std::cout << "[C++] Loaded HEX: " << path << " into simulation memory." << std::endl;
            };

            std::string hex_path = program_str + ".hex";
            load_hex(hex_path);

            auto core = sim->get_core(0);
            auto mmu = core->get_mmu();
            auto state = core->get_state();

            std::cout << "\n===========================================================" << std::endl;
            std::cout << "[DEBUG C++] Priviledge CSR PMP/MMU:" << std::endl;
            std::cout << "  Privilege Mode: " << (int)state->prv << " (3=M, 1=S, 0=U)" << std::endl;

            // 1. Dump PMP Config (0x3A0 = pmpcfg0)
            if (state->csrmap.count(0x3A0)) {
                uint64_t cfg0 = state->csrmap[0x3A0]->read();
                std::cout << "  CSR pmpcfg0 (0x3A0): 0x" << std::hex << cfg0 << std::endl;
            }

            // 2. Dump PMP Addresses (just first 4))
            for (int i = 0; i < 4; i++) {
                uint64_t addr_val = state->pmpaddr[i]->read();
                std::cout << "  CSR pmpaddr" << i << ": 0x" << std::hex << addr_val << std::endl;
            }

            // 3. Dump SATP (0x180)
            if (state->csrmap.count(0x180)) {
                uint64_t satp = state->csrmap[0x180]->read();
                std::cout << "  CSR satp (0x180): 0x" << std::hex << satp << " (0=Bare Mode)" << std::endl;
            }
            std::cout << "===========================================================" << std::endl;

#ifdef SPIKE_WRAPPER_DEBUG
            this->dump_memory(0x80000000, 6); // Dump first 6 words of RAM to verify loading
#endif
            cpu = sim->get_core(0);
            // in case you want to skip the bootloader
            // cpu->get_state()->pc = 0x80000000;
            // Spike sets the pc entry automatically to the reset vector (0x1000) during initialization
            // thus I aligned the linker script accordingly.

            std::cout << "[C++] Core starts at PC: 0x" << std::hex << cpu->get_state()->pc << std::dec << std::endl;

    } catch (std::exception& e) {
            std::cerr << "[C++ CRITICAL ERROR]: " << e.what() << std::endl;
            throw; // throw again to propagate to Python
        } catch (...) {
            std::cerr << "[C++ CRITICAL ERROR]: Unknown error in Spike constructor!" << std::endl;
            throw; // Rethrow as a generic exception to Python
        }
    }

    void dump_memory(reg_t start_addr, size_t count) {
        auto core = sim->get_core(0);
        auto mmu = core->get_mmu();

        std::cout << "===========================================================" << std::endl;
        std::cout << "[DEBUG C++] Dump memory from 0x" << std::hex << start_addr
                << " (" << std::dec << count << " 32-bit words):" << std::endl;

        for (size_t i = 0; i < count; i++) {
            reg_t current_addr = start_addr + (i * 4);
            try {
                uint32_t val = mmu->load<uint32_t>(current_addr);

                printf("  0x%08lx:  %08x\n", (unsigned long)current_addr, val);

            } catch (trap_t& t) {
                printf("  0x%08lx:  [ERROR] Trap: %s\n", (unsigned long)current_addr, t.name());
            } catch (...) {
                printf("  0x%08lx:  [ERROR] Access failed\n", (unsigned long)current_addr);
            }
        }
        std::cout << "===========================================================\n" << std::endl;
    }

    void step() {
        try {
            cpu->step(1);
        } catch (trap_t& t) {
            // trap RISC-V exceptions (e.g., access fault, illegal instruction, etc.)
            std::string msg = "Catched Trap RISC-V: ";
            msg += std::to_string(t.has_gva()) ;
            // map 'cause' to a string
            throw std::runtime_error("Trap ID: " + std::to_string(t.cause()));
        } catch (std::exception& e) {
            // catch any other C++ exceptions and rethrow as runtime_error to Python
            throw std::runtime_error(e.what());
        }
    }

    std::string get_disasm() {
        uint64_t pc = cpu->get_state()->pc;
        try {
            auto fetch = cpu->get_mmu()->load_insn(pc);
            return cpu->get_disassembler()->disassemble(fetch.insn);
        } catch (trap_instruction_access_fault& t) {
            return "ERROR: Instruction Access Fault (PMP/MMU block)";
        } catch (...) {
            return "ERROR: Unknown Fetch Error";
        }
    }
    uint64_t get_pc() {
        return cpu->get_state()->pc;
    }

    uint64_t get_reg(int i) {
        if (i < 0 || i >= 32) return 0;
        return cpu->get_state()->XPR[i];
    }

    uint64_t get_fp_reg(int i) {
        if (i < 0 || i >= 32) return 0;
        return cpu->get_state()->FPR[i].v[0];
    }

    std::vector<uint8_t> get_vec_reg(int i) {
        std::vector<uint8_t> reg_data;
        if (i < 0 || i >= 32 || !sim->get_core(0)) return reg_data;

        size_t vlenb = sim->get_core(0)->VU.vlenb;
        reg_data.resize(vlenb);

        uint8_t* start_ptr = (uint8_t*)sim->get_core(0)->VU.reg_file + (i * vlenb);

        std::copy(start_ptr, start_ptr + vlenb, reg_data.begin());

        return reg_data;
    }

    size_t get_vlen() {
        if (sim && sim->get_core(0)) {
            return sim->get_core(0)->VU.get_vlen();        }
        return 0;
    }

    size_t get_elen() {
        if (sim && sim->get_core(0)) {
            return sim->get_core(0)->VU.get_elen();
        }
        return 0;
    }

    void set_interrupt(bool high) {
        if (high)
            cpu->get_state()->mip->write_with_mask(MIP_MEIP, MIP_MEIP);
        else
            cpu->get_state()->mip->write_with_mask(MIP_MEIP, 0);
    }

    // Returns a map of Address -> Value for all active CSRs
    std::map<int, reg_t> get_all_csrs() {
        std::map<int, reg_t> csr_snapshot;
        auto core = sim->get_core(0);
        auto& csrmap = core->get_state()->csrmap;

        for (auto const& [addr, csr_ptr] : csrmap) {
            try {
                // Read the current value of the CSR
                csr_snapshot[addr] = csr_ptr->read();
            } catch (...) {
                // Some CSRs might trigger side effects or traps on read; skip those
                continue;
            }
        }
        return csr_snapshot;
    }

    ~SpikeBridge() {
        delete sim;
    }
};

PYBIND11_MODULE(spike_py, m) {
    py::class_<SpikeBridge>(m, "SpikeBridge")
        .def(py::init<const char*>())
        .def("step", &SpikeBridge::step)
        .def("get_pc", &SpikeBridge::get_pc)
        .def("get_reg", &SpikeBridge::get_reg)
        .def("get_fp_reg", &SpikeBridge::get_fp_reg)
        .def("get_vec_reg", &SpikeBridge::get_vec_reg)
        .def("get_vlen", &SpikeBridge::get_vlen)
        .def("get_elen", &SpikeBridge::get_elen)
        .def("get_disasm", &SpikeBridge::get_disasm)
        .def("get_csrs", &SpikeBridge::get_all_csrs)
        .def("dump_memory", &SpikeBridge::dump_memory, "Dump n 32-bit words starting from addr",
             py::arg("addr"), py::arg("count"))
        .def("set_interrupt", &SpikeBridge::set_interrupt);
}
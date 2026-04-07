# spike_python_wrapper

# BASHRC

```
export PATH="/home/$USER/tools/spike/bin:$PATH"
export LD_LIBRARY_PATH="/home/$USER/tools/spike/lib:$LD_LIBRARY_PATH"
export CPATH="/home/$USER/tools/spike/include:$CPATH"
export LIBRARY_PATH="/home/$USER/tools/spike/lib:$LIBRARY_PATH"
export RVA23_COMPILER=/home/$USER/tools/riscv_rva23
```

## Install SPIKE

```
git clone https://github.com/riscv-software-src/riscv-isa-sim.git
cd riscv-isa-sim
git checkout 0ad45926ac6f42d0d39e936abf4ab1cb9bdc5086
mkdir build && cd build
../configure --prefix=/home/$USER/tools/spike
make
make install
```

## Install RISC-V RVA23 Compiler

```
git clone https://github.com/riscv/riscv-gnu-toolchain
cd riscv-gnu-toolchain
git checkout f27c68dd632102a1eab85d97a90f3cdc4e90350c
./configure --prefix=/home/$USER/tools/riscv_rva23 --with-arch=rv64gc_zba_zbb_zbs_v_zicond_zcb_zfa --with-abi=lp64d
make -j16
```

## Compile test.S app


```
make test
```

else:

```
make test MARCH="-march=rv32imfc_zicsr"
```

## Compile C++ Spike Wrapper

Make sure you have `pip install pybind11`

Then,

```
make spike_wrapper
```

## Start tracer

```
python trace_spike.py
```
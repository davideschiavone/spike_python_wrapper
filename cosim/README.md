`cosim` simulates in lock-step CVE2 and Spike

```
make cosim_tb
make cosim_run_verbose PROGRAM=../tests/build/test ISA=rv32imc MAX_INSTRUCTIONS=20
```
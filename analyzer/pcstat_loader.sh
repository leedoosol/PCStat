#!/bin/bash

# arg1: I/O log file name, arg2: binary file name(to disassemble), arg3: pc syscall log file name

cd ~/pcstat/analyzer

# 1. get base address of ELF binary
readelf -l $2 | grep LOAD | head -1 > base_address.tmp

# 2. get symbol table of ELF binary
objdump -Ct $2 > symbol_table.tmp

# 3. run pcstat with given files
python pcstat.py $1 $3 base_address.tmp symbol_table.tmp

# 4. remove temporary files
rm base_address.tmp
rm symbol_table.tmp

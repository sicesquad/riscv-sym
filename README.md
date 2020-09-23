
# RISC-V Symbolic Execution

This repo contains code to symbolically execute RISC-V executables. It is specifically designed for CSAW ESC 2020 and makes the following assumptions:
- arch is RV32 with C extension
- target is HiFive1 board

# Overview

The disassembly part is ported from a BinaryNinja plugin and the BinaryNinja LLIL is replaced with Z3 equivalent.

The search strategy is fairly simple:
1. Symbolically execute instructions until hitting a branch with condition `C`.
2. Take the true branch and add condition `C`. Also clone the state and take the false branch in the clone, adding the condition `not C`. _Note: if the branch condition is not symbolic (e.g. in a fixed loop), just take the correct branch._
3. If the current set of conditions is unsat or the current PC is in avoid, kill the current state.
4. If the current PC is in find, return the current state.

# Example

```py
from riscv_sym import StateManager

code = open('./example/qual-esc2020.elf', 'rb').read()

# Starting PC. (challenge_1 function)
INIT = 0x20400232

FILE_BASE = 0x1000
CODE_BASE = 0x20400000
DAT_BASE = 0x80000000

# Initialize a StateManager for this binary.
# Provide an initial sp so stack-relative memory accesses are non-symbolic.
# a0 points to our "input string"
s = StateManager(
    dat, 
    INIT, 
    FILE_BASE, 
    CODE_BASE, 
    DAT_BASE, 
    initial={
        'sp': 0x80000c70,
        'a0': 0x80001000,
    }
)

# Search for the "correct!" message, avoid the "incorrect!" message.
t = s.search(
    find=[0x204005b6], 
    avoid=[0x20400594], 
    verbose=True
)

# Print the password.
print(t.dump_mem_string(0x80001000))
```

# Limitations

- No indirect jumps
- No symbolic memory access (values can be symbolic, indexes cannot be)

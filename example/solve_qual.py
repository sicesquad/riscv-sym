
import time

import sys
sys.path.append('../')
from riscv_sym import StateManager

# name: (initial_pc, [find], [avoid])
CHALLS = {
    'challenge_1': (0x20400232, [0x2040031c], [0x204002fa, 0x204002b8]),
    'challenge_2': (0x2040032e, [0x204003ae], [0x2040038c]),
    'challenge_3': (0x2040052e, [0x204005b6], [0x20400594]),
}


def main():
    code = open('./qual-esc2020.elf', 'rb').read()

    FILE_BASE = 0x1000
    CODE_BASE = 0x20400000
    DAT_BASE = 0x80000000

    for k in CHALLS:
        print('Solving %s...' % k)

        s = StateManager(code, CHALLS[k][0], FILE_BASE, CODE_BASE, DAT_BASE, initial={
            'sp': 0x80000c70,
            'a0': 0x80001000,
        })

        start = time.time()
        t = s.search(find=CHALLS[k][1], avoid=CHALLS[k][2], verbose=False)
        end = time.time()

        pwd = t.dump_mem_string(0x80001000)

        print('Found \"%s\" in %f seconds.' % (pwd, end - start))


if __name__=='__main__':
    main()


from z3 import *

# disassembly and lifting
import instr


class State(object):
    def __init__(self, dat, pc, file_base, virtual_base, data_base, initial={}):
        """Initialize a State object.

        (See StateManager.__init__)
        """
        self.dat = dat
        self.pc = pc
        self.file_base = file_base
        self.virtual_base = virtual_base
        self.data_base = data_base
        
        self.constraints = []
        self.dyn_mem = [None] * 0x10000
        self.sym_mem = [None] * 0x10000
        
        self.regs = {
            k:BitVec(k, 32) if k not in initial else initial[k] for k in instr.REGS
        }
        
        self._solver = None
        
        # Setting _dup indicates that the current state will split.
        self._dup = None
        self._dont_inc_pc = False
        self._curr_instr_len = 0
        
    def clone(self):
        """Clone the current state."""
        s2 = State(self.dat, self.pc, self.file_base, self.virtual_base, self.data_base)
        s2.constraints = [x for x in self.constraints]
        s2.dyn_mem = [x for x in self.dyn_mem]
        s2.sym_mem = [x for x in self.sym_mem]
        s2.regs = {k:self.regs[k] for k in self.regs}
        return s2
    
    def __repr__(self):
        return 'State @ 0x%x [%d constraints]' % (self.pc, len(self.constraints))
        
    def step(self, verbose=False):
        fbase = self.pc - self.virtual_base + self.file_base
        tok, info, fn = instr.decode(self.dat[fbase:fbase+4], self.pc)
        
        if verbose:
            print('0x%x :: %s' % (self.pc, ''.join([str(x) for x in tok])))
            
        self._dont_inc_pc = False
        self._curr_instr_len = info.length # Used for return address offset.
            
        if type(fn) is list:
            for x in fn:
                x(self)
        elif fn is not None:
            fn(self)
        
        if not self._dont_inc_pc:
            self.pc += info.length
        
    def add_constraint(self, c):
        self.constraints.append(c)
        
    def solve(self):
        self._solver = Solver()
        self._solver.add(And(self.constraints))
        return self._solver.check()
    
    def model(self):
        assert self._solver is not None
        return self._solver.model()
    
    def do_branch(self, cond, tdest, fdest):
        if type(cond) is bool:
            # non-symbolic condition
            self.pc = tdest if cond else fdest
            self._dont_inc_pc = True
        else:
            self._dup = self.clone()
            
            # true dest
            self.pc = tdest
            self._dont_inc_pc = True
            self.add_constraint(Not(Not(cond))) # convert python bool to z3

            # false dest
            self._dup.pc = fdest
            self._dup.add_constraint(Not(cond))
        
    def do_jump(self, dest):
        self.pc = dest
        self._dont_inc_pc = True
        
    def do_call(self, dest):
        self.regs['ra'] = self.pc + self._curr_instr_len
        self.pc = dest
        self._dont_inc_pc = True

    def dump_mem_string(self, addr):
        m = self.model()

        buf = ''
        off = 0
        while True:
            sym = self.sym_mem[addr - self.data_base + off]
            if sym is None:
                break
            off += 1

            buf += chr(m[sym].as_long())

        return buf
        
    # --- LLIL handles ---
    
    def set_reg(self, sz, reg, val):
        if reg == 'zero':
            return
        elif reg == 'pc':
            assert type(val) is int
            self.pc = val
            self._dont_inc_pc = True
        else:
            self.regs[reg] = val
        
    def reg(self, sz, reg):
        if reg == 'zero':
            return 0
        return self.regs[reg]
        
    def const(self, sz, val):
        return val
    
    def add(self, sz, a, b):
        return a + b

    def sub(self, sz, a, b):
        return a - b
    
    def _mem_addr(self, addr):
        if type(addr) is int:
            return addr - self.data_base
        else:
            print('no dyn addr')
            return None
    
    def store(self, sz, addr, val):
        for i in range(sz):
            self.dyn_mem[self._mem_addr(addr + i)] = (
                Extract(7,0,val >> (8*i)) if type(val) is not int else (val >> (8*i)) & 0xff
            )
            
    def load_code(self, sz, addr):
        # load from 0x0204xxxx
        val = 0
        for i in range(sz):
            off = addr - self.virtual_base + self.file_base + i
            val |= self.dat[off] << (i * 8)
        return val
            
    def load_data(self, sz, addr):
        # load from 0x8000xxxx
        val = 0
        for i in range(sz):
            a = self._mem_addr(addr + i)
            orig_val = self.dyn_mem[a]
            
            if orig_val is None:
                # initialize symbolic
                self.sym_mem[a] = BitVec('m_%d' % a, 8)
                v = ZeroExt(24, self.sym_mem[a])
            elif type(orig_val) is int:
                v = orig_val
            else:
                v = ZeroExt(24, orig_val)
                
            val |= v << (i * 8)
        return val
    
    def load(self, sz, addr):
        if addr > 0x80000000:
            return self.load_data(sz, addr)
        else:
            return self.load_code(sz, addr)
        
    def low_part(self, sz, x):
        return x
    
    def sign_extend(self, sz, x):
        return x
    
    def zero_extend(self, sz, x):
        return x
    
    def compare_equal(self, sz, a, b):
        return a == b
    
    def compare_not_equal(self, sz, a, b):
        return a != b
    
    def compare_signed_greater_than(self, sz, a, b):
        return a > b
    
    def compare_unsigned_greater_than(self, sz, a, b):
        return a > b
    
    def compare_signed_less_than(self, sz, a, b):
        return a < b
    
    def const_pointer(self, sz, x):
        return x
    
    def xor_expr(self, sz, a, b):
        return a ^ b
    
    def and_expr(self, sz, a, b):
        return a & b

    def rem(self, sz, a, b):
        return a % b
    
    
class StateManager(object):
    def __init__(self, dat, pc, file_base, virtual_base, data_base, initial={}):
        """Initialize a StateManager.

        Args:
          dat: A bytes object with binary code.
          pc: The initial PC address.
          file_base: Offset of code in the file.
          virtual_base: Virtual address of the code section.
          data_base: Virtual address of the data section.
          initial: Mapping of name:value mappings for initial register values.
        """
        self.states = []
        self.states.append(State(
            dat, pc, file_base, virtual_base, data_base, initial))
        
    def search(self, find=[], avoid=[], verbose=False):
        """Search for an input state that reaches a target state.

        Args:
          find: A list of target PC addresses.
          avoid: A list of PC addresses to avoid.
          verbose: If true, print disassembly at each step.

        Returns: A State that reaches the target or None.
        """
        while len(self.states) > 0:
            s = self.states[0]
            
            # check deadend
            if s.solve() == unsat:
                if verbose: print('Deadend!')
                self.states = self.states[1:]
                continue
            
            if verbose: print('(%d)> %s' % (len(self.states), repr(s)))
            s.step(verbose=verbose)
            
            if s._dup:
                dup = s._dup
                s._dup = None
                
                # check primary deadend
                if s.solve() == unsat:
                    if verbose: print('Deadend!')
                    self.states = self.states[1:]

                # check new state deadend
                if dup.solve() == unsat:
                    if verbose: print('dup Deadend!')
                else:
                    self.states.append(dup)

                continue
                
            # check targets
            if s.pc in find:
                if verbose: print('Found!')
                return s
            elif s.pc in avoid:
                if verbose: print('Kill!')
                self.states = self.states[1:]
                
        return None

from mango.elf.disas import Function, Instruction
from mango.style import *
import utcq.test as test


class MangoRunThis():
    def __init__(self, functions:list[Function]):
        self.functions = functions
        self.fn_instr = None
        self.stack_vulns = {
            "freeInputs": {},   
        }
        self.analzye()
    
    def __log_fn(self, fn:Function):
        LOG("Running analysis on function "
                + STYLE_C.YELLOW + fn.name
                + STYLE_C.MAGENTA + f" [{hex(fn.address)}]")
    
    def __format_stack_offset(self, arg:str):
        if arg.startswith("[rbp-"):
            return arg[4:-1]
        return arg

    def __log_buffer_overflow(self, target_stack:str, source:Instruction):
        target_stack = self.__format_stack_offset(target_stack)
        OK(
            f"Buffer overflow detected targetting stack position " + STYLE_C.BOLD + STYLE_C.CYAN + target_stack
            + STYLE_C.END
            + " generated from instruction:\n\t"
            + STYLE_C.RED + "(" + hex(source.address) + ") " + STYLE_C.YELLOW + ' '.join(source.asm)
            + "\n"
        )
    
    def __log_format_vuln(self, source:Instruction, target:Instruction):
        OK(
            f"Potential format string vulnerability"
            + " generated from instruction:\n\t"
            + STYLE_C.RED + "(" + hex(source.address) + ") " + STYLE_C.YELLOW + ' '.join(source.asm)
            + STYLE_C.END + "\n     getting input from instruction: \n\t"
            + STYLE_C.RED + "(" + hex(target.address) + ") " + STYLE_C.YELLOW + ' '.join(target.asm)
            + "\n"
        )
    
    def _parse_stack_offset(self, arg:str):
        if arg.startswith("[rbp-"):
            return int(arg[5:-1], 16)
        raise ValueError("Unknown stack offset syntax, contribute to the project, implement me! " + arg)

    def analzye(self):
        for fn_name in self.functions:
            func = self.functions[fn_name]
            self.fn_instr = func.instructions
            self.__log_fn(func)
            for i, instr in enumerate(func.instructions):
                if (instr.asm[0] == 'call'):
                    self.__analyze_call(i, instr)

    def __analyze_argument(self, i:int, instr:Instruction):
        stack_pos = None
        i-=1;
        while (i>=0 and self.fn_instr[i].asm[0] != 'call'):
            # check for SYS V ABI calling convention
            # it ends when it finds a call instruction, it means the call setup ended (in reverse order)
            instr_s = self.fn_instr[i].asm
            if (instr_s[0] == 'mov'):
                args = instr_s[1].split(",")
                if (args[0]=="rdi"):
                    # we have found the buffer argument
                    if (args[1] == "rax"):
                        prev_instr = self.fn_instr[i-1].asm
                        if (prev_instr[0] == 'mov' or prev_instr[0] == 'lea'):
                            stack_pos = prev_instr[1].split(",")[1]
                            break
                    else:
                        stack_pos = args[1]
                        break
            i-=1
        return stack_pos

    def __analyze_buffer_overflow(self, i:int, instr:Instruction):
        stack_pos = self.__analyze_argument(i, instr)
        if (stack_pos):
            self.__log_buffer_overflow(stack_pos, instr)
            self.stack_vulns[self._parse_stack_offset(stack_pos)] = instr

    def __analyze_scanf(self, i:int, instr:Instruction):
        pass
    
    def __analyze_gets(self, i, instr:Instruction):
        self.__analyze_buffer_overflow(i, instr)
    
    def __analyze_printf(self, i, instr:Instruction):
        stack_pos = self.__analyze_argument(i, instr)
        if (stack_pos):
            stack_off = self._parse_stack_offset(stack_pos)
            if (stack_off in self.stack_vulns):
                self.__log_format_vuln(instr, self.stack_vulns[stack_off])
    
    def __analyze_call(self, i:int, instr:Instruction):
        match (instr.asm[-1]):
            case '<__isoc99_scanf@plt>':
                self.__analyze_scanf(i, instr)
            case '<gets@plt>':
                self.__analyze_gets(i, instr)
            case '<printf@plt>':
                self.__analyze_printf(i, instr)
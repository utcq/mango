from mango.elf.disas import Function, Instruction
from mango.style import *
import utcq.test as test

## Every printf shifts canary by 40 bytes, so n+5


def util_get_rodata(rodata:dict, addr:int):
    index = (addr-rodata["offset"])
    if (index < 0 or index >= rodata["size"]):
        return None
    data = ""
    for i in range(index, len(rodata["data"])): 
        if (rodata["data"][i] == 0):
            break
        data += chr(rodata["data"][i])
    return data

class MangoRunThis():
    def __init__(self, functions:list[Function], rodata:dict):
        self.rodata = rodata
        self.functions = functions
        self.fn_instr = None
        self.stack_vulns = {
            "freeInputs": {},
            "stackSize": 0
        }
        self.cached = {
            "io_emulation": ""
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
            + STYLE_C.END
            + "\n   >>  " + STYLE_C.BLUE + "Canary exposing format: " + STYLE_C.END + STYLE_C.UNDERLINE + "%" + str( (self.stack_vulns["stackSize"]//8 ) + 5) + "$p"
            + STYLE_C.END + "  << \n"
        )
    
    def __log_overunderflow(self, source:Instruction):
        OK(
            f"Potential integer overflow/underflow"
            + " generated from instruction:\n\t"
            + STYLE_C.RED + "(" + hex(source.address) + ") " + STYLE_C.YELLOW + ' '.join(source.asm)
            + "\n"
        )
    
    def _parse_stack_offset(self, arg:str):
        if arg.startswith("[rbp-"):
            return {
                "type": "rbp",
                "off": int(arg[5:-1], 16)
            }
        elif arg.startswith("[rip+"):
            return {
                "type": "rip",
                "off": int(arg[5:-1], 16)
            }
        elif arg.startswith("0x"):
            # absolute address of rodata
            return {
                "type": "rod",
                "off": int(arg, 16)
            }
        raise ValueError("Unknown stack offset syntax, contribute to the project, implement me! " + arg)

    def analzye(self):
        for fn_name in self.functions:
            self.stack_vulns = {
                "freeInputs": {},
                "stackSize": 0
            }
            func = self.functions[fn_name]
            self.fn_instr = func.instructions
            self.__log_fn(func)
            for i, instr in enumerate(func.instructions):
                if (instr.asm[0] == 'sub' and 'rsp' in instr.asm[1]):
                    self.__analyze_stack(i, instr)
                elif (instr.asm[0] == 'call'):
                    self.__analyze_call(i, instr)
            
            if (self.cached["io_emulation"] != ""):
                LOG("Showing emulated IO:");
                print(self.cached["io_emulation"])
                self.cached["io_emulation"] = ""

    def __analyze_argument(self, i:int, instr:Instruction, reg:str="rdi"):
        stack_pos = None
        arg_instr = None
        i-=1;
        while (i>=0 and self.fn_instr[i].asm[0] != 'call'):
            # check for SYS V ABI calling convention
            # it ends when it finds a call instruction, it means the call setup ended (in reverse order)
            instr_s = self.fn_instr[i].asm
            if (instr_s[0] == 'mov'):
                args = instr_s[1].split(",")
                if (args[0]==reg):
                    # we have found the buffer argument
                    if (args[1] == "rax"):
                        prev_instr = self.fn_instr[i-1].asm
                        prev_instr2 = self.fn_instr[i-2].asm
                        if (prev_instr[0] == 'mov' or prev_instr[0] == 'lea'):
                            if (prev_instr[1].split(",")[0] == 'rax'):
                                stack_pos = prev_instr[1].split(",")[1]
                                arg_instr = self.fn_instr[i-1]
                                break
                        if (prev_instr[0] == 'add' or prev_instr[0] == 'sub'
                            and (prev_instr2[0] == 'mov' or prev_instr2[0] == 'lea')
                        ):
                            if (prev_instr[1].split(",")[0] == 'rax'):
                                if (prev_instr2[1].split(",")[0] == 'rax'):
                                    stack_pos = prev_instr2[1].split(",")[1]
                                    stack_pos_int = int(stack_pos.split("-")[1][:-1],16)
                                    if (prev_instr[0] == 'add'):
                                        stack_pos_int -= int(prev_instr[1].split(",")[1], 16)
                                    else:
                                        stack_pos_int += int(prev_instr[1].split(",")[1], 16)
                                    stack_pos = "[rbp-" + hex(stack_pos_int) + "]"
                                    arg_instr = self.fn_instr[i-2]
                                    break                        
                    else:
                        stack_pos = args[1]
                        arg_instr = self.fn_instr[i]
                        break
                elif (reg=="rdi" and args[0]=="edi"):
                    stack_pos = args[1]
                    arg_instr = self.fn_instr[i]
            i-=1
        return stack_pos, arg_instr

    def __analyze_buffer_overflow(self, i:int, instr:Instruction, reg:str="rdi"):
        stack_pos, arg_instr = self.__analyze_argument(i, instr, reg)
        if (stack_pos):
            stack_off = self._parse_stack_offset(stack_pos)
            if (stack_off["type"] == "rbp" or stack_off["type"] == "rsp"):
                self.__log_buffer_overflow(stack_pos, instr)
                self.stack_vulns["freeInputs"][stack_off["off"]] = instr
        return stack_pos, arg_instr

    def __analyze_scanf(self, i:int, instr:Instruction):
        stack_pos, arg_instr = self.__analyze_argument(i, instr)
        if (stack_pos):
            stack_off = self._parse_stack_offset(stack_pos)
            if (stack_off["type"] == "rip"):
                real_off = arg_instr.address + len(arg_instr.opcodes) + stack_off["off"]
                string = util_get_rodata(self.rodata, real_off)
                self.cached["io_emulation"] += "[INPUT] >> " +string+ " <<\n"
                if (string=="%s"):
                    self.__analyze_buffer_overflow(i, instr, "rsi")
                elif (string=="%d"):
                    self.__log_overunderflow(instr)
    
    def __analyze_gets(self, i, instr:Instruction):
        stack_pos, arg_instr = self.__analyze_buffer_overflow(i, instr)
        if (stack_pos):
            stack_off = self._parse_stack_offset(stack_pos)
            if (stack_off["type"] == "rip"):
                real_off = arg_instr.address + len(arg_instr.opcodes) + stack_off["off"]
                string = util_get_rodata(self.rodata, real_off)
                self.cached["io_emulation"] += string
    
    def __analyze_printf(self, i, instr:Instruction):
        stack_pos, arg_instr = self.__analyze_argument(i, instr)
        if (stack_pos):
            stack_off = self._parse_stack_offset(stack_pos)
            if (stack_off["type"] == "rbp" or stack_off["type"] == "rsp"):
                if (stack_off["off"] in self.stack_vulns["freeInputs"]):
                    self.__log_format_vuln(instr, self.stack_vulns["freeInputs"][stack_off["off"]])
            elif (stack_off["type"] == "rip"):
                real_off = arg_instr.address + len(arg_instr.opcodes) + stack_off["off"]
                string = util_get_rodata(self.rodata, real_off)
                self.cached["io_emulation"] += string
            elif (stack_off["type"] == "rod"):
                string = util_get_rodata(self.rodata, stack_off["off"])
                self.cached["io_emulation"] += string
    
    def __analyze_puts(self, i, instr:Instruction):
        stack_pos, arg_instr = self.__analyze_argument(i, instr)
        if (stack_pos):
            stack_off = self._parse_stack_offset(stack_pos)
            if (stack_off["type"] == "rip"):
                real_off = arg_instr.address + len(arg_instr.opcodes) + stack_off["off"]
                string = util_get_rodata(self.rodata, real_off)
                self.cached["io_emulation"] += string + "\n"


    def __analyze_stack(self, i:int, instr:Instruction):
        args = instr.asm[1].split(",")
        if (args[0] == 'rsp'):
            self.stack_vulns["stackSize"] = int(args[1], 16)
    
    def __analyze_call(self, i:int, instr:Instruction):
        match (instr.asm[-1]):
            # C Library functions
            case '<__isoc99_scanf@plt>':
                self.__analyze_scanf(i, instr)
            case '<gets@plt>':
                self.__analyze_gets(i, instr)
            case '<printf@plt>':
                self.__analyze_printf(i, instr)
            case '<puts@plt>':
                self.__analyze_puts(i, instr)

            # C++
            case '<_IO_printf>':
                self.__analyze_printf(i, instr)
            case '<_IO_gets>':
                self.__analyze_gets(i, instr)
            case '<_IO_scanf>':
                self.__analyze_scanf(i, instr)
            case '<_IO_puts>':
                self.__analyze_puts(i, instr)
from os import popen
import re

GCC_BLTIN_FUNCS = [
    "_start",
    "_dl_relocate_static_pie",
    "deregister_tm_clones",
    "register_tm_clones",
    "__do_global_dtors_aux",
    "frame_dummy",
]

OBJDUMP_FLAGS = [
    "-d",
    "-j .text",
    "-M intel"
]

class Instruction:
    def __init__(self, address:int, opcodes:list[int], asm:str):
        self.address = address
        self.opcodes = opcodes
        self.asm = asm

class Function:
    def __init__(self, address:int, name:str):
        self.address = address
        self.name = name
        self.instructions = []
    
    def pushnew(self, instruction:Instruction):
        self.instructions.append(instruction)


class Disassembler:
    def __init__(self, path:str):
        self.functions: dict[str, Function] = {}
        fd=popen("objdump " + " ".join(OBJDUMP_FLAGS) + " " + path)
        lines = fd.readlines()
        fd.close()
        
        self.current_function = None
        for line in lines:
            self.parse_line(line)

    def isFunctionLabel(self, line:str) -> bool:
        return re.match(r"^[0-9a-f]+ <.*>:$", line) != None

    def isInstruction(self, line:str) -> bool:
        return re.match(r"^[0-9a-f]+:", line) != None

    def parseFunctionLabel(self, line:str):
        match = re.match(r"^[0-9a-f]+ <(.*)>:$", line)
        name = match.group(1)
        address = int(line.split()[0], 16)
        if (name in GCC_BLTIN_FUNCS):
            self.current_function = None
            return
        self.current_function = Function(address, name)
        self.functions[name] = self.current_function
    
    def parseInstruction(self, line:str):
        match = re.match(r"^[0-9a-f]+:.*\t(.*)$", line)
        address = int(line.split()[0][:-1], 16)
        opcodes = []
        i=1
        while (i<len(line) and len(line[i])==2 and line[i][0] in "0123456789abcdef"):
            opcodes.append(int(line[i], 16))
            i+=1
        asm = match.group(1)
        asm = asm.split()
        i=0
        while (i<len(asm)):
            if (asm[i][0] == "#"):
                asm = asm[:i]
                break
            i+=1
        asm = (" ".join(asm)).split()
        instruction = Instruction(address, opcodes, asm)
        self.current_function.pushnew(instruction)

    def parse_line(self, line:str):
        line = line.strip()
        if (line == ""):
            return
        if (self.isFunctionLabel(line)):
            self.parseFunctionLabel(line)
            return
        elif (self.current_function and self.isInstruction(line)):
            self.parseInstruction(line)
            return
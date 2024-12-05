from os import popen
import re

from elf.blacklist import *


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
        
        self.rodata ={
            "offset": 0,
            "size": 0,
            "data": []
        }
        fd=popen("objdump -s -j .rodata " + path)
        lines = fd.readlines()
        fd.close()
        self.parse_rodata(lines)

    def get_rodata(self)->dict:
        return self.rodata

    def parse_rodata(self, lines:str):
        i=0
        while (i<len(lines) and not lines[i].strip().endswith(".rodata:")):
            i+=1
        i+=1
        if (i>=len(lines)):
            return
        data:bytes=[]
        begin_address:int=None
        for line in lines[i:]:
            line = line.strip().split('  ')
            if (len(line) < 2):
                data += [ord(' ')]*16
            else:
                line = line[:-1][0].split()
                if (not begin_address):
                    begin_address = int(line[0], 16)
                for b in line[1:]:
                    for i in range(0, len(b), 2):
                        data.append(int(b[i:i+2], 16))
        self.rodata["offset"] = begin_address
        self.rodata["size"] = len(data)
        self.rodata["data"] = data

    def isFunctionLabel(self, line:str) -> bool:
        return re.match(r"^[0-9a-f]+ <.*>:$", line) != None

    def isInstruction(self, line:str) -> bool:
        return re.match(r"^[0-9a-f]+:", line) != None

    def parseFunctionLabel(self, line:str):
        match = re.match(r"^[0-9a-f]+ <(.*)>:$", line)
        name = match.group(1)
        address = int(line.split()[0], 16)
        if (
            name in GCC_BLACKLIST
            or name.startswith("_")
            or name.startswith(".")
            or name.endswith(".cold")
            or name.endswith(".0")
            or name.startswith("dl_")
            ):
            self.current_function = None
            return
        self.current_function = Function(address, name)
        self.functions[name] = self.current_function
    
    def parseInstruction(self, line:str):
        match = re.match(r"^[0-9a-f]+:.*\t(.*)$", line)
        address = int(line.split()[0][:-1], 16)
        opcodes = []
        for op in line.split()[1:]:
            if not (len(op)==2 and op[0] in "0123456789abcdef" and op[1] in "0123456789abcdef"):
                break
            opcodes.append(int(op, 16))
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
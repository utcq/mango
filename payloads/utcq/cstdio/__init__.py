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
    def __init__(self, functions:list[Function], rodata:dict, security:dict=None, remote_info:dict=None):
        self.rodata = rodata
        self.functions = functions
        self.security = security
        self.remote_info = remote_info
        self.fn_instr = None
        self.stack_vulns = {
            "freeInputs": {},
            "stackSize": 0
        }
        self.cached = {
            "io_emulation": ""
        }
        self.vulnerabilities = {
            "buffer_overflows": [],
            "format_strings": [],
            "unterminated_strings": [],
            "canary_location": None,
            "win_functions": []
        }
        self.unterminated_buffers = {}
        
        if remote_info and remote_info.get("has_libs"):
            LOG("remote env:")
            if remote_info.get("libc_version"):
                print(f"   glibc: {STYLE_C.CYAN}{remote_info['libc_version']}{STYLE_C.END}")
            print()
        
        self.analzye()
        self.__plan_exploit()
    
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
        self.vulnerabilities["buffer_overflows"].append({
            "stack_position": target_stack,
            "instruction": source,
            "buffer_size": None,
            "read_size": None
        })
        OK(
            f"buffer overflow @ " + STYLE_C.BOLD + STYLE_C.CYAN + target_stack
            + STYLE_C.END
            + " from:\n\t"
            + STYLE_C.RED + "(" + hex(source.address) + ") " + STYLE_C.YELLOW + ' '.join(source.asm)
            + "\n"
        )

    def __log_buffer_overflow_with_size(self, target_stack:str, source:Instruction, buffer_size:int, read_size:int):
        target_stack = self.__format_stack_offset(target_stack)
        self.vulnerabilities["buffer_overflows"].append({
            "stack_position": target_stack,
            "instruction": source,
            "buffer_size": buffer_size,
            "read_size": read_size
        })
        OK(
            f"buffer overflow @ " + STYLE_C.BOLD + STYLE_C.CYAN + target_stack
            + STYLE_C.END
            + f" (buf={buffer_size}B, reads {read_size}B, overflow={read_size-buffer_size}B)"
            + " from:\n\t"
            + STYLE_C.RED + "(" + hex(source.address) + ") " + STYLE_C.YELLOW + ' '.join(source.asm)
            + "\n"
        )
    
    def __log_unterminated_string(self, print_instr:Instruction, read_instr:Instruction, buffer_location:str):
        self.vulnerabilities["unterminated_strings"].append({
            "print_instruction": print_instr,
            "read_instruction": read_instr,
            "buffer_location": buffer_location
        })
        OK(
            f"unterminated string leak @ " + STYLE_C.BOLD + STYLE_C.CYAN + buffer_location
            + STYLE_C.END
            + " filled by:\n\t"
            + STYLE_C.RED + "(" + hex(read_instr.address) + ") " + STYLE_C.YELLOW + ' '.join(read_instr.asm)
            + STYLE_C.END
            + "\n\tprinted by:\n\t"
            + STYLE_C.RED + "(" + hex(print_instr.address) + ") " + STYLE_C.YELLOW + ' '.join(print_instr.asm)
            + STYLE_C.END + "\n"
        )
    
    def __log_format_vuln(self, source:Instruction, target:Instruction):
        ret_addr_after_printf = source.address + len(source.opcodes)
        
        vuln_entry = {
            "printf_instruction": source,
            "input_instruction": target,
            "return_address": ret_addr_after_printf
        }
        
        canary_pos = (self.stack_vulns["stackSize"]//8) + 5
        
        from mango.glibc_db import get_glibc_layout, get_local_glibc_version
        
        glibc_version = None
        if self.remote_info and self.remote_info.get("libc_version"):
            glibc_version = self.remote_info["libc_version"]
        else:
            glibc_version = get_local_glibc_version()
        
        layout = get_glibc_layout(glibc_version)
        
        current_func = self.stack_vulns.get("currentFunction", "")
        offset_to_paths = {}
        
        if current_func == "main":
            base_offset = canary_pos + layout["main_ret_offset_base"]
            for i in range(-1, 2):
                if base_offset + i > canary_pos:
                    offset_to_paths[base_offset + i] = [["main"]]
        else:
            paths = self.__find_call_paths_to_main(current_func, self.call_graph)
            
            if not paths:
                offset_to_paths[canary_pos + layout["vuln_ret_offset_base"]] = [["?"]]
            else:
                for path in paths:
                    depth = len(path)
                    offset = canary_pos + layout["main_ret_offset_base"] + (depth * 4)
                    if offset not in offset_to_paths:
                        offset_to_paths[offset] = []
                    full_path = [current_func] + path
                    offset_to_paths[offset].append(full_path)

        output_parts = []
        if len(offset_to_paths) == 1:
            offset = list(offset_to_paths.keys())[0]
            leak_addrs_str = f"%{offset}$p"
        else:
            sorted_offsets = sorted(offset_to_paths.keys())
            middle_idx = len(sorted_offsets) // 2
            
            for idx, offset in enumerate(sorted_offsets):
                if idx == middle_idx:
                    output_parts.append(STYLE_C.BOLD + STYLE_C.GREEN + f"%{offset}$p" + STYLE_C.END)
                else:
                    output_parts.append(f"%{offset}$p")
        
        leak_addrs_str = " or ".join(output_parts) if output_parts else f"%{list(offset_to_paths.keys())[0]}$p"

        log_msg = (
            f"format string vulnerability from:\n\t"
            + STYLE_C.RED + "(" + hex(source.address) + ") " + STYLE_C.YELLOW + ' '.join(source.asm)
            + STYLE_C.END + "\n     input from: \n\t"
            + STYLE_C.RED + "(" + hex(target.address) + ") " + STYLE_C.YELLOW + ' '.join(target.asm)
            + STYLE_C.END
            + "\n   >>  " + STYLE_C.BLUE + "leak canary: " + STYLE_C.END + STYLE_C.UNDERLINE + f"%{canary_pos}$p" + STYLE_C.END
            + STYLE_C.BLUE + f"  |  leak code addr: " + STYLE_C.END + f"{leak_addrs_str}" + STYLE_C.END + "  <<\n"
        )
        
        vuln_entry["leak_offsets"] = list(offset_to_paths.keys())
        vuln_entry["canary_offset"] = canary_pos
        self.vulnerabilities["format_strings"].append(vuln_entry)
        
        if len(offset_to_paths) > 1:
            all_same_function = True
            first_path = list(offset_to_paths.values())[0][0]
            for paths_list in offset_to_paths.values():
                if paths_list[0] != first_path:
                    all_same_function = False
                    break
            
            if all_same_function and len(first_path) == 1:
                log_msg += STYLE_C.CYAN + f"   (Offsets based on GLIBC {glibc_version or 'default'})\n" + STYLE_C.END
            else:
                log_msg += STYLE_C.CYAN + "   Call paths:\n" + STYLE_C.END
                for offset in sorted(offset_to_paths.keys()):
                    paths_for_offset = offset_to_paths[offset]
                    unique_paths = []
                    for path in paths_for_offset:
                        if path not in unique_paths:
                            unique_paths.append(path)
                    
                    for path in unique_paths:
                        reversed_path = path[::-1]
                        path_str = " → ".join(reversed_path)
                        log_msg += f"      {STYLE_C.YELLOW}%{offset}$p{STYLE_C.END}: {path_str}\n"
        
        OK(log_msg)
    
    def __log_overunderflow(self, source:Instruction):
        OK(
            f"possible int over/underflow from:\n\t"
            + STYLE_C.RED + "(" + hex(source.address) + ") " + STYLE_C.YELLOW + ' '.join(source.asm)
            + "\n"
        )
    
    def __log_canary_location(self, offset:int, load_instr:Instruction, store_instr:Instruction):
        self.vulnerabilities["canary_location"] = {
            "offset": offset,
            "load_instruction": load_instr,
            "store_instruction": store_instr
        }
        LOG(
            f"canary @ " + STYLE_C.BOLD + STYLE_C.GREEN + f"-{hex(offset)}"
            + STYLE_C.END
            + "\n\tload: "
            + STYLE_C.RED + "(" + hex(load_instr.address) + ") " + STYLE_C.YELLOW + ' '.join(load_instr.asm)
            + STYLE_C.END + "\n\tstore: "
            + STYLE_C.RED + "(" + hex(store_instr.address) + ") " + STYLE_C.YELLOW + ' '.join(store_instr.asm)
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
        elif arg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            return {
                "type": "reg",
                "reg": arg
            }
        raise ValueError("Unknown stack offset syntax, contribute to the project, implement me! " + arg)

    def __build_call_graph(self):
        call_graph = {}
        for fn_name in self.functions:
            func = self.functions[fn_name]
            call_graph[fn_name] = []
            for instr in func.instructions:
                if instr.asm[0] == 'call':
                    target = instr.asm[-1]
                    if '<' in target and '>' in target:
                        called_func = target.split('<')[1].split('>')[0]
                        if '@plt' not in called_func and called_func in self.functions:
                            call_graph[fn_name].append(called_func)
        return call_graph
    
    def __find_call_paths_to_main(self, current_func, call_graph, visited=None):
        if visited is None:
            visited = set()
        
        if current_func in visited:
            return []
        
        if current_func == "main":
            return [[]]
        
        visited = visited | {current_func}
        paths = []
        
        for caller, callees in call_graph.items():
            if current_func in callees:
                sub_paths = self.__find_call_paths_to_main(caller, call_graph, visited)
                for sub_path in sub_paths:
                    paths.append([caller] + sub_path)
        
        return paths

    def analzye(self):
        self.call_graph = self.__build_call_graph()
        
        for fn_name in self.functions:
            func = self.functions[fn_name]
            if 'win' in fn_name.lower() or 'flag' in fn_name.lower() or 'shell' in fn_name.lower():
                self.vulnerabilities["win_functions"].append({
                    "name": fn_name,
                    "address": func.address
                })
        
        for fn_name in self.functions:
            self.stack_vulns = {
                "freeInputs": {},
                "stackSize": 0,
                "currentFunction": fn_name
            }
            func = self.functions[fn_name]
            self.fn_instr = func.instructions
            self.__log_fn(func)
            for i, instr in enumerate(func.instructions):
                if (instr.asm[0] == 'sub' and 'rsp' in instr.asm[1]):
                    self.__analyze_stack(i, instr)
                elif (instr.asm[0] == 'add' and 'rsp' in instr.asm[1]):
                    self.__analyze_stack(i, instr)
                elif (instr.asm[0] == 'mov' and 'fs:0x28' in ' '.join(instr.asm)):
                    self.__analyze_canary(i, instr)
                elif (instr.asm[0] == 'call'):
                    self.__analyze_call(i, instr)
            
            if (self.cached["io_emulation"] != ""):
                LOG("emulated IO:");
                print(self.cached["io_emulation"])
                self.cached["io_emulation"] = ""
    
    def __analyze_argument(self, i:int, instr:Instruction, reg:str="rdi"):
        stack_pos = None
        arg_instr = None
        i-=1;
        reg_variants = [reg]
        if reg.startswith('r') and len(reg) == 3:
            reg_variants.append('e' + reg[1:])
        
        
        while (i>=0 and self.fn_instr[i].asm[0] != 'call'):
            # check for SYS V ABI calling convention
            # it ends when it finds a call instruction, it means the call setup ended (in reverse order)
            instr_s = self.fn_instr[i].asm
            if (instr_s[0] == 'mov' or instr_s[0] == 'lea'):
                operands = ' '.join(instr_s[1:])
                if ',' not in operands:
                    i -= 1
                    continue
                    
                args = operands.split(',')
                dest = args[0].strip()
                
                for ptr_type in ['QWORD PTR', 'DWORD PTR', 'WORD PTR', 'BYTE PTR']:
                    if dest.startswith(ptr_type):
                        dest = dest[len(ptr_type):].strip()
                        break
                
                if ' ' in dest:
                    dest = dest.split()[-1]
                
                source = args[1].strip()
                for ptr_type in ['QWORD PTR', 'DWORD PTR', 'WORD PTR', 'BYTE PTR']:
                    if source.startswith(ptr_type):
                        source = source[len(ptr_type):].strip()
                        break
                
                if (dest in reg_variants):
                    # we have found the buffer argument
                    if (source == "rax"):
                        for j in range(i-1, max(0, i-10), -1):
                            check_instr = self.fn_instr[j].asm
                            if check_instr[0] in ['mov', 'lea']:
                                check_operands = ' '.join(check_instr[1:])
                                if ',' not in check_operands:
                                    continue
                                check_args = check_operands.split(',')
                                check_src = check_args[1].strip()
                                for ptr_type in ['QWORD PTR', 'DWORD PTR', 'WORD PTR', 'BYTE PTR']:
                                    if check_src.startswith(ptr_type):
                                        check_src = check_src[len(ptr_type):].strip()
                                        break
                                if check_args[0].strip() == 'rax':
                                    stack_pos = check_src
                                    arg_instr = self.fn_instr[j]
                                    break
                        if stack_pos:
                            break                        
                    else:
                        stack_pos = source
                        arg_instr = self.fn_instr[i]
                        break
                elif (reg=="rdi" and dest=="edi"):
                    stack_pos = source
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
                if string:
                    self.cached["io_emulation"] += "[INPUT] >> " + string + " <<\n"
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
                if string:
                    self.cached["io_emulation"] += string

    def __analyze_read_with_size(self, i, instr:Instruction, buf_reg:str="rsi", size_reg:str="rdx"):
        buf_pos, buf_instr = self.__analyze_argument(i, instr, buf_reg)
        size_pos, size_instr = self.__analyze_argument(i, instr, size_reg)
        
        
        if buf_pos and size_pos:
            buf_off = self._parse_stack_offset(buf_pos)
            
            if buf_off["type"] == "rip" and buf_instr:
                absolute_addr = buf_instr.address + len(buf_instr.opcodes) + buf_off["off"]
                buf_key = f"abs:{hex(absolute_addr)}"
            else:
                buf_key = f"{buf_off['type']}:{buf_off.get('off', buf_off.get('reg', 'unknown'))}"
            
            self.unterminated_buffers[buf_key] = {
                "instruction": instr,
                "buffer": buf_pos,
                "type": buf_off["type"],
                "buf_instr": buf_instr
            }
            
            if (buf_off["type"] == "rbp" or buf_off["type"] == "rsp"):
                self.stack_vulns["freeInputs"][buf_off["off"]] = instr
                
                read_size = None
                if size_pos.startswith("0x"):
                    read_size = int(size_pos, 16)
                elif size_pos.isdigit():
                    read_size = int(size_pos)
                
                
                if read_size:
                    buffer_size = self.__estimate_buffer_size(buf_off["off"])
                    if buffer_size and read_size > buffer_size:
                        self.__log_buffer_overflow_with_size(buf_pos, instr, buffer_size, read_size)
                    else:
                        self.__log_buffer_overflow(buf_pos, instr)
                else:
                    self.__log_buffer_overflow(buf_pos, instr)
    
    def __estimate_buffer_size(self, offset:int):
        stack_positions = sorted([pos for pos in self.stack_vulns["freeInputs"].keys() if pos < offset])
        
        if stack_positions:
            return offset - stack_positions[0]
        
        estimated = offset - 8 if offset > 8 else offset
        return estimated if estimated > 0 else None

    def __analyze_fgets(self, i, instr:Instruction):
        buf_pos, buf_instr = self.__analyze_argument(i, instr, "rdi")
        size_pos, size_instr = self.__analyze_argument(i, instr, "rsi")
        
        if buf_pos and size_pos:
            buf_off = self._parse_stack_offset(buf_pos)
            if (buf_off["type"] == "rbp" or buf_off["type"] == "rsp"):
                self.stack_vulns["freeInputs"][buf_off["off"]] = instr
                
                read_size = None
                if size_pos.startswith("0x"):
                    read_size = int(size_pos, 16)
                elif size_pos.isdigit():
                    read_size = int(size_pos)
                
                if read_size:
                    buffer_size = self.__estimate_buffer_size(buf_off["off"])
                    if buffer_size and read_size > buffer_size:
                        self.__log_buffer_overflow_with_size(buf_pos, instr, buffer_size, read_size)
        
    def __analyze_printf(self, i, instr:Instruction):
        stack_pos, arg_instr = self.__analyze_argument(i, instr)
        if (stack_pos):
            stack_off = self._parse_stack_offset(stack_pos)
            if (stack_off["type"] == "rbp" or stack_off["type"] == "rsp"):
                if (stack_off["off"] in self.stack_vulns["freeInputs"]):
                    self.__log_format_vuln(instr, self.stack_vulns["freeInputs"][stack_off["off"]])
                else:
                    self.__log_format_vuln(instr, instr)
            elif (stack_off["type"] == "rip"):
                real_off = arg_instr.address + len(arg_instr.opcodes) + stack_off["off"]
                string = util_get_rodata(self.rodata, real_off)
                if string:
                    self.cached["io_emulation"] += string
                    if "%s" in string:
                        self.__check_unterminated_string_usage(i, instr, "rsi")
            elif (stack_off["type"] == "rod"):
                string = util_get_rodata(self.rodata, stack_off["off"])
                if string:
                    self.cached["io_emulation"] += string
                    if "%s" in string:
                        self.__check_unterminated_string_usage(i, instr, "rsi")
            elif (stack_off["type"] == "reg"):
                pass
    
    def __check_unterminated_string_usage(self, i:int, instr:Instruction, reg:str="rdi"):
        buf_pos, buf_instr = self.__analyze_argument(i, instr, reg)
        if buf_pos:
            buf_off = self._parse_stack_offset(buf_pos)
            
            if buf_off["type"] == "rip" and buf_instr:
                absolute_addr = buf_instr.address + len(buf_instr.opcodes) + buf_off["off"]
                buf_key = f"abs:{hex(absolute_addr)}"
            else:
                buf_key = f"{buf_off['type']}:{buf_off.get('off', buf_off.get('reg', 'unknown'))}"
            
            if buf_key in self.unterminated_buffers:
                unterminated_info = self.unterminated_buffers[buf_key]
                self.__log_unterminated_string(instr, unterminated_info["instruction"], buf_pos)
    
    def __analyze_puts(self, i, instr:Instruction):
        stack_pos, arg_instr = self.__analyze_argument(i, instr)
        if (stack_pos):
            stack_off = self._parse_stack_offset(stack_pos)
            if (stack_off["type"] == "rip"):
                real_off = arg_instr.address + len(arg_instr.opcodes) + stack_off["off"]
                string = util_get_rodata(self.rodata, real_off)
                if string:
                    self.cached["io_emulation"] += string + "\n"
            else:
                self.__check_unterminated_string_usage(i, instr, "rdi")

    def __analyze_stack(self, i:int, instr:Instruction):
        args = instr.asm[1].split(",")
        if (args[0] == 'rsp'):
            size_value = int(args[1], 16)
            if instr.asm[0] == 'add' and size_value > 0x7fffffffffffffff:
                size_value = (0x10000000000000000 - size_value) & 0xffffffffffffffff
            self.stack_vulns["stackSize"] = size_value
    
    def __analyze_canary(self, i:int, instr:Instruction):
        load_instr = instr
        if len(instr.asm) > 1:
            dest_part = instr.asm[1].split(',')[0]
            reg = dest_part
        else:
            return
        
        for j in range(i+1, min(i+10, len(self.fn_instr))):
            next_instr = self.fn_instr[j].asm
            if next_instr[0] == 'mov' and len(next_instr) >= 4:
                stack_part = next_instr[3] if len(next_instr) > 3 else ''
                if '[rbp-' in stack_part and reg in stack_part:
                    parts = stack_part.split(',')
                    if len(parts) >= 2 and parts[1] == reg:
                        offset_str = parts[0][5:-1]
                        offset = int(offset_str, 16)
                        self.__log_canary_location(offset, load_instr, self.fn_instr[j])
                        self.stack_vulns["canary_offset"] = offset
                        return
    
    def __analyze_call(self, i:int, instr:Instruction):
        call_target = instr.asm[-1]
        match (call_target):
            # C Library functions
            case '<__isoc99_scanf@plt>':
                self.__analyze_scanf(i, instr)
            case '<gets@plt>':
                self.__analyze_gets(i, instr)
            case '<printf@plt>':
                self.__analyze_printf(i, instr)
            case '<puts@plt>':
                self.__analyze_puts(i, instr)
            case '<fgets@plt>':
                self.__analyze_fgets(i, instr)
            case '<read@plt>':
                self.__analyze_read_with_size(i, instr, "rsi", "rdx")
            case '<fread@plt>':
                self.__analyze_read_with_size(i, instr, "rdi", "rsi")

            # C++
            case '<_IO_printf>':
                self.__analyze_printf(i, instr)
            case '<_IO_gets>':
                self.__analyze_gets(i, instr)
            case '<_IO_scanf>':
                self.__analyze_scanf(i, instr)
            case '<_IO_puts>':
                self.__analyze_puts(i, instr)
            case '<_IO_fgets>':
                self.__analyze_fgets(i, instr)
            case '<_IO_read>':
                self.__analyze_read_with_size(i, instr, "rsi", "rdx")
            case '<_IO_fread>':
                self.__analyze_read_with_size(i, instr, "rdi", "rsi")

    def __plan_exploit(self):
        if not self.vulnerabilities["buffer_overflows"] and not self.vulnerabilities["format_strings"]:
            return
        
        print("="*60 + "\n")
        
        if self.security:
            print(STYLE_C.BOLD + "mitigations:" + STYLE_C.END)
            
            if self.security["pie"]:
                print(f"   {STYLE_C.RED}PIE: on{STYLE_C.END} - addrs randomized")
            else:
                print(f"   {STYLE_C.GREEN}PIE: off{STYLE_C.END} - fixed addrs")
            
            if self.security["relro"]:
                relro_color = STYLE_C.YELLOW if self.security["relro"] == "Partial" else STYLE_C.RED
                print(f"   {relro_color}RELRO: {self.security['relro']}{STYLE_C.END}")
            
            if self.security["nx"]:
                print(f"   {STYLE_C.RED}NX: on{STYLE_C.END} - no shellcode")
            else:
                print(f"   {STYLE_C.GREEN}NX: off{STYLE_C.END} - shellcode ok")
            
            print()
        
        if self.vulnerabilities["win_functions"]:
            print(STYLE_C.GREEN + "win functions:" + STYLE_C.END)
            main_func = self.functions.get("main")
            for win_func in self.vulnerabilities["win_functions"]:
                print(f"   + {STYLE_C.YELLOW}{win_func['name']}{STYLE_C.END} @ {STYLE_C.CYAN}{hex(win_func['address'])}{STYLE_C.END}", end="")
                if main_func and self.security and self.security["pie"]:
                    offset = win_func['address'] - main_func.address
                    offset_sign = "+" if offset >= 0 else ""
                    print(f" ({STYLE_C.MAGENTA}main{offset_sign}{offset}{STYLE_C.END})", end="")
                print()
            print()
        
        has_canary = self.vulnerabilities["canary_location"] is not None
        has_format_string = len(self.vulnerabilities["format_strings"]) > 0
        has_buffer_overflow = len(self.vulnerabilities["buffer_overflows"]) > 0
        
        if has_canary:
            canary_offset = self.vulnerabilities["canary_location"]["offset"]
            print(STYLE_C.RED + "canary @ " + STYLE_C.END + f"-{hex(canary_offset)}")
            print()
        
        step_num = 1
        
        if has_format_string:
            has_pie = self.security and self.security["pie"]
            fmt_vuln = self.vulnerabilities["format_strings"][0]
            ret_addr = fmt_vuln["return_address"]
            leak_offsets = fmt_vuln.get("leak_offsets", [])
            canary_offset_fmt = fmt_vuln.get("canary_offset", (self.stack_vulns["stackSize"] // 8) + 5)
            
            if leak_offsets:
                ret_addr_position = leak_offsets[len(leak_offsets) // 2]
            else:
                ret_addr_position = 17
            
            if has_canary and has_pie:
                print(STYLE_C.BOLD + f"step {step_num}: leak canary + base" + STYLE_C.END)
                print(f"   canary: " + STYLE_C.CYAN + f"%{canary_offset_fmt}$p" + STYLE_C.END)
                print(f"   code addr: " + STYLE_C.CYAN + f"%{ret_addr_position}$p" + STYLE_C.END)
                print(f"   base: " + STYLE_C.YELLOW + f"code_leak - {hex(ret_addr)}" + STYLE_C.END)
                if self.vulnerabilities["win_functions"]:
                    win_func = self.vulnerabilities["win_functions"][0]
                    main_func = self.functions.get("main")
                    if main_func:
                        offset = win_func['address'] - main_func.address
                        print(f"   win: " + STYLE_C.YELLOW + f"base + {hex(win_func['address'])}" + STYLE_C.END + f" (main{offset:+d})")
                print()
                step_num += 1
            elif has_canary:
                print(STYLE_C.BOLD + f"step {step_num}: leak canary" + STYLE_C.END)
                print(f"   payload: " + STYLE_C.CYAN + f"%{canary_offset_fmt}$p" + STYLE_C.END)
                print()
                step_num += 1
            elif has_pie:
                print(STYLE_C.BOLD + f"step {step_num}: leak base" + STYLE_C.END)
                print(f"   code addr: " + STYLE_C.CYAN + f"%{ret_addr_position}$p" + STYLE_C.END)
                print(f"   base: " + STYLE_C.YELLOW + f"code_leak - {hex(ret_addr)}" + STYLE_C.END)
                if self.vulnerabilities["win_functions"]:
                    win_func = self.vulnerabilities["win_functions"][0]
                    main_func = self.functions.get("main")
                    if main_func:
                        offset = win_func['address'] - main_func.address
                        print(f"   win: " + STYLE_C.YELLOW + f"base + {hex(win_func['address'])}" + STYLE_C.END + f" (main{offset:+d})")
                print()
                step_num += 1
        elif has_canary and not has_format_string:
            print(STYLE_C.YELLOW + "need canary leak (no fmt string)" + STYLE_C.END)
            print()

        
        if has_buffer_overflow:
            overflow = self.vulnerabilities["buffer_overflows"][0]
            print(STYLE_C.BOLD + f"step {step_num}: overflow" + STYLE_C.END)
            
            if overflow["buffer_size"] and overflow["read_size"]:
                overflow_bytes = overflow['read_size'] - overflow['buffer_size']
                print(f"   buf @ {STYLE_C.CYAN}{overflow['stack_position']}{STYLE_C.END}, size={overflow['buffer_size']}B, writes {overflow['read_size']}B (overflow {overflow_bytes}B)")
            else:
                print(f"   buf @ {STYLE_C.CYAN}{overflow['stack_position']}{STYLE_C.END}, unlimited overflow")
            print()
            step_num += 1
            
            if overflow["stack_position"]:
                stack_pos_value = int(overflow["stack_position"].replace("-", "").replace("0x", ""), 16)
                
                print(STYLE_C.BOLD + f"step {step_num}: payload" + STYLE_C.END)
                
                if has_canary:
                    canary_padding = stack_pos_value - canary_offset
                    padding_str = f"{canary_padding}B"
                    canary_str = "8B [LEAK]"
                    rbp_str = "8B"
                    
                    if self.vulnerabilities["win_functions"]:
                        win_func = self.vulnerabilities["win_functions"][0]
                        ret_str = f"{hex(win_func['address'])} → {win_func['name']}"
                    else:
                        ret_str = "<RIP>"
                    
                    print(f"   ┌──────────────────────────────────────────┐")
                    print(f"   │ {STYLE_C.CYAN}{'padding':<15}{STYLE_C.END} │ {padding_str:>22} │")
                    print(f"   ├──────────────────────────────────────────┤")
                    print(f"   │ {STYLE_C.GREEN}{'canary':<15}{STYLE_C.END} │ {canary_str:>22} │")
                    print(f"   ├──────────────────────────────────────────┤")
                    print(f"   │ {STYLE_C.YELLOW}{'saved rbp':<15}{STYLE_C.END} │ {rbp_str:>22} │")
                    print(f"   ├──────────────────────────────────────────┤")
                    print(f"   │ {STYLE_C.MAGENTA}{'return addr':<15}{STYLE_C.END} │ {ret_str:>22} │")
                    print(f"   └──────────────────────────────────────────┘")
                else:
                    padding_str = f"{stack_pos_value}B"
                    rbp_str = "8B"
                    
                    if self.vulnerabilities["win_functions"]:
                        win_func = self.vulnerabilities["win_functions"][0]
                        ret_str = f"{hex(win_func['address'])} → {win_func['name']}"
                    else:
                        ret_str = "<RIP>"
                    
                    print(f"   ┌──────────────────────────────────────────┐")
                    print(f"   │ {STYLE_C.CYAN}{'padding':<15}{STYLE_C.END} │ {padding_str:>22} │")
                    print(f"   ├──────────────────────────────────────────┤")
                    print(f"   │ {STYLE_C.YELLOW}{'saved rbp':<15}{STYLE_C.END} │ {rbp_str:>22} │")
                    print(f"   ├──────────────────────────────────────────┤")
                    print(f"   │ {STYLE_C.MAGENTA}{'return addr':<15}{STYLE_C.END} │ {ret_str:>22} │")
                    print(f"   └──────────────────────────────────────────┘")
                
                print()
                step_num += 1
        
        if self.security and self.security["pie"] and self.vulnerabilities["win_functions"] and not has_format_string:
            print(STYLE_C.YELLOW + "note: pie on but no fmt string to leak addrs" + STYLE_C.END)
            print()
        
        print("\n" + "="*60 + "\n")

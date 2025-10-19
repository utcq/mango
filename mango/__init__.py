from elf.disas import *
import modularity as modularity
from os.path import isfile as file_exists, realpath as abs_path, dirname as parent_dir
from remote_env import RemoteLibAnalyzer

class Mango:
    def __init__(self, file_path:str):
        self.path = abs_path(file_path)
        if (not file_exists(self.path)):
            raise FileNotFoundError(f"File {self.path} not found")
        self.disas = Disassembler(self.path)
        self.options={}
        self.remote_env = None

    def set_opts(self, opts:dict[str, str]):
        for key in opts:
            self.options[key] = opts[key]
        
        if opts.get("remote_libs"):
            self.remote_env = RemoteLibAnalyzer(opts["remote_libs"])
    
    def load_modules(self, modules:list[str]):
        self.modules = modularity.MangoModules(self.options["module_path"])
        self.modules.add_modules(modules)
        self.modules.load_modules()
    
    def run_analysis(self):
        remote_info = self.remote_env.get_info() if self.remote_env else None
        
        self.modules.run_analysis(
            self.disas.functions, 
            self.disas.get_rodata(), 
            self.disas.get_security(),
            remote_info
        )
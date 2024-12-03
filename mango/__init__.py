from elf.disas import *
import modularity as modularity
from os.path import isfile as file_exists, realpath as abs_path, dirname as parent_dir

class Mango:
    def __init__(self, file_path:str):
        self.path = abs_path(file_path)
        if (not file_exists(self.path)):
            raise FileNotFoundError(f"File {self.path} not found")
        self.disas = Disassembler(self.path)
        self.options={}

    def set_opts(self, opts:dict[str, str]):
        for key in opts:
            self.options[key] = opts[key]
    
    def load_modules(self, modules:list[str]):
        self.modules = modularity.MangoModules(self.options["module_path"])
        self.modules.add_modules(modules)
        self.modules.load_modules()
    
    def run_analysis(self):
        self.modules.run_analysis(self.disas.functions)
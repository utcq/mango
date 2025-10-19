from os.path import isfile as file_exists, realpath as abs_path, dirname as parent_dir
from importlib.machinery import SourceFileLoader
from sys import path as sys_path
import tomli

class MangoModules:
    def __init__(self, path:str):
        self.path = abs_path(path)
        self.modules = {}
        self.module_queue = []
        self.analysis_queue: tuple[str, dict, any] = [] # (fmt, conf, py_mod)
        sys_path.append(self.path)
        sys_path.append(parent_dir(parent_dir(parent_dir(__file__))))

        self.mod_it=0
        self.mod_size=0
    
    def add_modules(self, modules:list[str]):
        for module in modules:
            self.module_queue.append(module)
    
    def solve_deps_queue(self, parent:str, deps:list[str]):
        for dep in deps:
            if (dep in self.module_queue):
                self.module_queue.remove(dep)
            else:
                self.mod_size+=1
            self.__load_module(dep, parent)
            self.mod_it+=1

    def __load_module(self, module:str, isDep:str=None):
        author,name = module.split("/")
        module_path = f"{self.path}/{author}/{name}"
        conf_file = f"{module_path}/mod.toml"
        if (not file_exists(conf_file)):
            if (not isDep):
                raise FileNotFoundError(f"Module {author}/{name} not found")
            else:
                raise FileNotFoundError(f"Module {author}/{name}, dependency of {isDep}, not found")
        mod_conf = tomli.load(open(conf_file, 'rb'))
        if (not "MModule" in mod_conf.keys()):
            if (not isDep):
                raise AttributeError(f"Module {author}/{name} not valid, does not contain MModule")
            else:
                raise AttributeError(f"Module {author}/{name}, dependency of {isDep}, not valid, does not contain MModule")
        mod_conf = mod_conf["MModule"]
        if ("dependencies" in mod_conf.keys()):
            self.solve_deps_queue(module, mod_conf["dependencies"])
        
        py_mod = SourceFileLoader(name, f"{module_path}/__init__.py").load_module()

        self.analysis_queue.append((module, mod_conf, py_mod))

    def load_modules(self):
        self.mod_size = len(self.module_queue)
        while (self.mod_it < self.mod_size):
            self.__load_module(module=self.module_queue[self.mod_it])
            self.mod_it+=1

    def dump_module(self, fmt, mod_conf):
        print("-"*24)
        print(f"Module: {fmt}")
        if ("name" in mod_conf.keys()):
            print(f"Name: {mod_conf['name']}")
        if ("author" in mod_conf.keys()):
            print(f"Author: {mod_conf['author']}")
        if ("version" in mod_conf.keys()):
            print(f"Version: {mod_conf['version']}")
        if ("description" in mod_conf.keys()):
            print(f"Description: {mod_conf['description']}")
        print("-"*24)

    def run_analysis(self, functions:list, rodata:dict, security:dict=None, remote_info:dict=None):
        for module, conf, py_mod in self.analysis_queue:
            if "MangoRunThis" in dir(py_mod):
                self.dump_module(module, conf)
                if security is not None and remote_info is not None:
                    py_mod.MangoRunThis(functions, rodata, security, remote_info)
                elif security is not None:
                    py_mod.MangoRunThis(functions, rodata, security)
                else:
                    py_mod.MangoRunThis(functions, rodata)
                print("\n")
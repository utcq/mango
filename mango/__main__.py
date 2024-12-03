#!/usr/bin/env python3

from sys import argv
from __init__ import *

def test():
    mango_inst = Mango(argv[1])
    mango_inst.set_opts({
        "module_path": "payloads/"
    })
    mango_inst.load_modules([
        "utcq/cstdio"
    ])
    mango_inst.run_analysis()

if __name__ == "__main__":
    test()

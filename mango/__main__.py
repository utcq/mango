#!/usr/bin/env python3

from sys import argv
from __init__ import *
import argparse

def test():
    parser = argparse.ArgumentParser(description='Mango - Binary Analysis Tool')
    parser.add_argument('binary', help='Path to the binary to analyze')
    parser.add_argument('--libs', '-l', help='Path to zip file containing remote server libraries (libc.so.6, ld-linux-x86-64.so.2, etc.)')
    
    args = parser.parse_args()
    
    mango_inst = Mango(args.binary)
    mango_inst.set_opts({
        "module_path": "payloads/",
        "remote_libs": args.libs if args.libs else None
    })
    mango_inst.load_modules([
        "utcq/cstdio"
    ])
    mango_inst.run_analysis()

if __name__ == "__main__":
    test()

#!/usr/bin/python3

from collections import Counter
from os.path import basename, join
from os import listdir
from asa import CFIInfo
import pickle
from pwnlib.elf.elf import ELF
import r2pipe
from time import sleep
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <target_dir with pkl files>")
    exit()

target_dir = sys.argv[1]

for p in listdir(target_dir):
    if p.endswith(".pkl"):
        with open(join(target_dir, p), "rb") as f:
            with open(join(target_dir, p.replace(".pkl", "_pa_coverage.txt")), "w") as output:
                cfidata = list(pickle.load(f).values())
                for c in cfidata:
                    if not "oat" in c.trait and not "rust" in c.trait:
                        while True:
                            try:
                                print(f"Visiting {c.path}.")
                                full_path = c.path
                                r2 = r2pipe.open(full_path, ["-e", "bin.relocs.apply=true"])
                                r2.cmd("e search.in=bin.sections.x")
                                ins = set([r["opstr"].split()[0] for r in r2.cmdj("/afj sec")["result"]])
                                output.write(f"{full_path} -- {ins}\n")
                                sleep(0.5)
                                r2.quit()
                                del r2
                                break
                            except Exception as e:
                                print(f"Caught exception {e}, trying again.")

#!/usr/bin/python3

"""
This script is just a wrapper calling run_ghidra_headless.sh to execute the internal_analysis_ghidra.py script,
and parsing the resulting output.
"""

import subprocess
import random
import string
import os
import logging
import json

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

class SPCall:
    """Models a call to __cfi_slow_path or __cfi_slow_path_diag.
    """

    def __init__(self, addr, typeid):
        self.addr = addr
        self.typeid = typeid

    def __str__(self) -> str:
        return f"SPcall at {hex(self.addr)} for typeid {hex(self.typeid)}"

def get_spcall_icall_info(path):
    filename = os.path.join("/tmp",
                            f"asa_internal_{''.join(random.choices(string.ascii_letters, k=20))}.txt")
    log.info(f"Invoking ghidra headless analysis for {path}.")
    done = subprocess.run(["./run_ghidra_headless.sh", path, filename, path.replace("/", "_") + "_ghidra"],
                          capture_output=True)
    try:
        with open(filename) as f:
            sp_calls, icalls = json.load(f)
            os.remove(filename)

            return (
                list(map(lambda spc: SPCall(
                    spc[0],
                    # handles conversion to unsigned int
                    # also handles cases where spc[1] is None because constant propagation / decompilation failed
                    ((spc[1] if spc[1] >= 0 else spc[1] + (1 << 64))
                     if spc[1] else 0)),
                    sp_calls)),
                icalls
            )

    except FileNotFoundError as e:
        log.warning(f"Could not open result file, something went wrong when calling ghidra headless. Generated output:\n {done.stdout.decode()}\n{done.stderr.decode()}")
        return (None, None)

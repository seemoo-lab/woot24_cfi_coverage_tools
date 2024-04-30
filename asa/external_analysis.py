#!/usr/bin/python3

"""
The angr based analysis for __check_cfi and so on is defined here.
"""

import angr
import claripy
import functools
import logging
import sys

common_aborts_syms = ["__cfi_check_fail", "abort"]
# return instructions per arch
ret_instructions = {"AARCH64": ["ret"],
                    "AMD64": ["ret"]}
jump_table_instructions = {"AARCH64": ["b"],
                           "AMD64": ["jmp"]}
jump_table_entry_size = {"AARCH64": 4, "AMD64": 8}

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# The claripy solving process can produce very deep call stacks, this prevents recursion errors
sys.setrecursionlimit(10 ** 5)

class Targets:
    def __init__(self, path):
        self.path = path
        self.tables = {}

    def __str__(self) -> str:
        jump_tables = "\n".join(map(str, filter(lambda v: v.table_type == "jump", self.tables.values())))
        vtables     = "\n".join(map(str, filter(lambda v: v.table_type == "virtual", self.tables.values())))
        return f"Targets for '{self.path}'\njump_tables:\n{jump_tables}\n\nvtables:\n{vtables}"

class Table:
    def __init__(self, typeid, table_type, start, end):
        self.typeid = typeid
        self.table_type = table_type
        self.start = start
        self.end = end
        self.entries = []

    def __str__(self) -> str:
        return (f"{self.table_type}Table for {hex(self.typeid)} at {hex(self.start)} - {hex(self.end)}:\n" +
                "\n".join(map(lambda entry: "    " + str(entry), self.entries)))

class TableEntry:
    def __init__(self, addr, symbol):
        self.addr = addr
        self.symbol = symbol

    def __str__(self) -> str:
        return f"{hex(self.addr)} -> {self.symbol if self.symbol else '?'}"

def get_abort_addresses(proj):
   """This function tries to find common abort symbols and returns their addresses if successful."""
   aborts = {proj.loader.find_symbol(sym).rebased_addr for sym in common_aborts_syms if proj.loader.find_symbol(sym)}
   if len(aborts) == 0:
       log.warning(f"Could not find any abort symbols for '{proj.filename}'. Analysis can still succeed (e.g. if it encounters software trap instructions), but problems might occur otherwise.")
   return aborts


def is_jumptable(addr, proj):
    """Checks whether addr contains a jump-table by looking at the instructions there."""
    ins = proj.factory.block(addr).capstone.insns

    # Jump-table block size is 1 (maybe not always? is this arch dependent?)
    return len(ins) == 1 and ins[0].mnemonic in jump_table_instructions[proj.arch.name]


def is_finished(arch, abort_addresses, state):
    """This function returns 'finished' or 'aborted' depending on the abort detection heuristic, else 'active'."""

    # Check if this state is at a known abort address
    if state.addr in abort_addresses:
        return "aborted"

    # Check last instruction to be a return or call (they can only be last in a basic block)
    try:
        instruction = state.block().capstone.insns[-1].insn.mnemonic
    except angr.SimEngineError:
        # IndexError can occur if there is an empty block prior to hardware trap instruction
        return "aborted"
    except IndexError:
        return "aborted"

    # Check for infinite loops. These should not occur naturally, but unsupported relocations can produce them.
    if state.history.recent_bbl_addrs == [state.addr]:
        log.warning(f"Detected infinite loop in state {state}, aborting it.")
        return "aborted"

    # Return instructions are a good indicator of a successful, finished check
    if instruction in ret_instructions[arch]:
        return "finished"
    return "active"

def get_targets(path):
    """Uses angr to obtain the external allowed targets by symbolically executing the __check_cfi function.
    Returns an instance of the Targets class."""

    # silence verbose logging output from angr
    logging.getLogger("cle.backends.externs").setLevel(logging.ERROR)
    logging.getLogger("archinfo.arch").setLevel(logging.CRITICAL)
    logging.getLogger("cle.backends.tls").setLevel(logging.ERROR)
    logging.getLogger("cle.loader").setLevel(logging.ERROR)
    logging.getLogger("angr.calling_conventions").setLevel(logging.ERROR)
    logging.getLogger("pyvex.lifting.libvex").setLevel(logging.ERROR)
    logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel(logging.ERROR)

    # open a angr project and make sure that there is a __cfi_check symbol
    log.info(f"Invoking angr external analysis for {path}.")
    proj = angr.Project(path,
                        auto_load_libs=False,
                        use_sim_procedures=False)
    cfi_check = proj.loader.find_symbol("__cfi_check")
    if not cfi_check:
        log.error("Error, could not find __cfi_check symbol!")

    if proj.arch.name not in ret_instructions:
        log.error(f"Unsupported architecture {proj.arch.name}.")

    # __cfi_check takes three arguments: CallSiteTypeId, target addr, diag info
    # One can fix diag info to zero
    typeid = claripy.BVS('typeid', proj.arch.bits)
    target = claripy.BVS('target', proj.arch.bits)
    state = proj.factory.call_state(cfi_check.rebased_addr,
                                    typeid, target, claripy.BVV(0, proj.arch.bits))

    # this is the key part responsible for the symbolic execution
    simgr = proj.factory.simgr(state)
    filter_func = functools.partial(is_finished,
                                    proj.arch.name,
                                    get_abort_addresses(proj))
    while len(simgr.active) > 0:
        simgr.step(filter_func=filter_func)

    # post processing stage, build Targets object
    targets = Targets(path)

    # __cfi_check can be empty, if so there are no finished stashes
    if "finished" not in simgr.stashes:
        return targets

    for s in simgr.finished:
        base = proj.loader.min_addr
        tid = s.solver.eval_one(typeid)
        addr_min = s.solver.min(target) - base
        addr_max = s.solver.max(target) - base

        table = Table(tid, "jump" if is_jumptable(addr_min + base, proj) else "virtual", addr_min, addr_max)

        if table.table_type == "jump":
            # each pointer is a target in a jump table
            for addr in range(addr_min,
                              addr_max + jump_table_entry_size[proj.arch.name],
                              jump_table_entry_size[proj.arch.name]):
                sym = proj.loader.find_symbol(addr + base)
                sym = sym.name if sym else None
                table.entries.append(TableEntry(addr, sym))

        else:
            # the maximum would be a single vtable for each slot (unprobable due to RTTI)
            # so we can use the number end - start + 1 as upper bound
            for addr in s.solver.eval_upto(target, (addr_min - addr_max) // (proj.arch.bits // 8) + 1):
                sym = proj.loader.find_symbol(addr + base)
                sym = sym.name if sym else None
                table.entries.append(TableEntry(addr - base, sym))

        # Warn if there already was a mapping with this typeid. This can happen if there is a collision of typeids.
        # Currently, this is handled by just overwriting the old entry. The (maybe better) alternative would be to
        # map typeid to lists, but collisions are very rare.
        if tid in targets.tables:
            log.warning(f"TypeID Collision for TypeID {hex(tid)}. Overwriting old entry.")

        # store this table
        targets.tables[tid] = table
    return targets

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import FlowType
from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator
from ghidra.program.util import SymbolicPropogator
import json

options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

def find_cfi_slowpath_and_icalls():
    """Collects all calls that are either targeting __cfi_slowpath or are indirect calls / branches."""
    sp_calls = []
    icalls = []

    sp_addresses = list(map(lambda x: x.getAddress(),
                            filter(lambda s: "__cfi_slowpath" in s.getName(),
                                   currentProgram.getSymbolTable().getDefinedSymbols())))

    for ins in currentProgram.getListing().getInstructions(True):
        for pcode in ins.getPcode():
            if pcode.opcode == PcodeOp.CALL and pcode.getInput(0).getAddress() in sp_addresses:
                sp_calls.append(ins.getAddress())
            elif pcode.opcode == PcodeOp.CALLIND or pcode.opcode == PcodeOp.BRANCHIND:
                icalls.append(ins.getAddress())

    return (sp_calls, icalls)


def get_typeid(sp_call_addr):
    """Returns the typeid for a call address, i.e. it returns the first argument for the given call address."""
    func = getFunctionContaining(sp_call_addr)
    if not func:
        return None

    # FIXME: at the moment this is hardcoded for ARM64
    arg0 = currentProgram.getLanguage().getRegister("x0")
    start = func.getEntryPoint()
    eval = ConstantPropagationContextEvaluator(monitor, True)
    symEval = SymbolicPropogator(currentProgram)
    symEval.flowConstants(start, func.getBody(), eval, True, monitor)

    val = symEval.getRegisterValue(sp_call_addr, arg0)
    # val can become none if Ghidra fails to detect function boundaries.
    # In such a case, the cfi_slowpath is considered to be at the beginning of the function,
    # and Ghidra cannot reason about register values.
    if val is not None:
        return val.getValue()
    else:
        # if Ghidra fails, we cannot really do anything.
        # The code in internal_analysis.py already handles if the return value is none, so this is all we can do.
        return None

def entry():
    """Entry point for the analysis. Handles writing the output file afterwards."""

    args = list(getScriptArgs())
    if not args:
        println("Missing output file argument.")
        return

    base = currentProgram.getAddressMap().getImageBase()

    # Rebasing to 0 also converts from Address to long, which is required for serialisation
    sp_calls, icalls = find_cfi_slowpath_and_icalls()
    data = json.dumps(
        (map(lambda c: (c.subtract(base), get_typeid(c)),
             sp_calls),
         [ic.subtract(base) for ic in icalls]))
    with open(args[0], "w") as f:
        f.write(data)

entry()

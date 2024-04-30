import subprocess
import re

def has_shadow_stack(path):
    """Returns whether the binary at the given path is likely to use a shadow stack as the number of matching instructions using x18."""
    
    disassm = subprocess.run(["aarch64-linux-gnu-objdump", "-d", path], shell=False, capture_output=True)
    return len(re.findall(rb"ldr\Wx30, \[x18, #-8\]!\n", disassm.stdout))

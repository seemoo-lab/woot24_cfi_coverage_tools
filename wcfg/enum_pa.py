import os
from os.path import join, realpath
import stat
import r2pipe
import subprocess

"""
Script to enumerate PA protected files on Windows for Arm.
Expects an Windows for Arm ISO mounted at /mnt/win/.
Requires radare2 for headless analysis.
"""

for path, dirs, filenames in os.walk("/mnt/win/"):
    for fs in filenames:
        try: 
            full_path = realpath(join(path, fs), strict=True)
            if not full_path.endswith(".dll") and not full_path.endswith(".exe"):
                continue

            if not stat.S_ISREG(os.stat(full_path).st_mode):
                print(f"Skipping file '{full_path}' which is not a regular file.")
                continue

            ftype = subprocess.run(["file", full_path], capture_output=True).stdout
            if not b"Aarch64, for MS Windows" in ftype:
                print(f"I: {full_path} has type {ftype}")
                continue

            r2 = r2pipe.open(full_path)
            r2.cmd("e search.in=io.maps.x")
            ins = set([r["opstr"].split()[0] for r in r2.cmdj("/afj sec")["result"]])
            print(f"{full_path} -- {ins}")

        except ValueError as e:
            print(f"{e}")
        except PermissionError as e:
            print(f"Permission Error: {e}")
        except OSError as e:
            print(f"OS Error: {e}")

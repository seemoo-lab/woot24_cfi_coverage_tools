import subprocess
import os
from os.path import join, realpath
import stat
# import shutil

"""
Script to enumerate DLLs located in System32 that have XFG protected functions functions marked as suppressed.
"""

for path, dirs, filenames in os.walk("C:\\Windows\\System32\\"):
    for fs in filenames:
        try: 
            full_path = realpath(join(path, fs), strict=True)
            if not full_path.endswith(".dll"):
                continue

            if not stat.S_ISREG(os.stat(full_path).st_mode):
                print(f"Skipping file '{full_path}' which is not a regular file.")
                continue

            s = subprocess.run(["dumpbin", "/loadconfig", full_path], capture_output=True)
            suppressed_targets = [l.strip() for l in s.stdout.split(b"\n") if b"SX 0" in l]

            if suppressed_targets:
                # shutil.copy(full_path, "dlls")
                print(full_path)
                print(b"\n".join(suppressed_targets).decode())

        except ValueError as e:
            print(f"{e}")
        except PermissionError as e:
            print(f"Permission Error: {e}")
        except OSError as e:
            print(f"OS Error: {e}")

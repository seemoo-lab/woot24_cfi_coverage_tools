#!/usr/bin/python3

"""
Windows CFG / XFG analysis script.
Intended to be run inside a Windows guest to be analysed.
Produces `win_analysis.pkl`.
"""

import collections
from os.path import join, realpath
import os
import stat
import pefile
import struct
import pickle

class WCFGInfo:
    # flags, taken from winnt.h
    IMAGE_DLL_CHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_GUARD_XFG_ENABLED = 0x00800000
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xF0000000
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28
    # entry flags
    IMAGE_GUARD_FLAG_FID_SUPPRESSED =               0x01
    IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED =            0x02
    IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER =         0x04
    IMAGE_GUARD_FLAG_FID_XFG =                      0x08

    def get_guard_table_enty_width(self, pe):
        # see: https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata
        return 4 + ((pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags
                     & WCFGInfo.IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
                    >> WCFGInfo.IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT)

    def parse_guardcftable_entry(self, pe, entry):
        # this might break if extra flags are larger than one byte
        assert self.get_guard_table_enty_width(pe) - 4 == 1
        return struct.unpack("<IB", entry)

    def parse_guardcftable(self, pe):
        # because table_start is a absolute address, need to convert it to relative one
        table_start  = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable - pe.OPTIONAL_HEADER.ImageBase
        cnt = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount
        entry_width = self.get_guard_table_enty_width(pe)

        return [
            self.parse_guardcftable_entry(pe, pe.get_data(entry_addr, length=entry_width))
            for entry_addr in range(table_start, table_start + cnt * entry_width, entry_width)
        ]

    def extract_type_hashes(self, pe):
        type_hashes = collections.defaultdict(list)
        for addr, flags in self.guardcftable:
            if flags & self.IMAGE_GUARD_FLAG_FID_XFG:
                type_hash = int.from_bytes(pe.get_data(addr - 8, 8), "little") # hash precedes function
                type_hashes[type_hash].append(addr)
        return type_hashes

    def analyse(self, path):
        pe = pefile.PE(path, fast_load=True)
        self.machine = pe.FILE_HEADER.Machine
        self.wcfg = bool(pe.OPTIONAL_HEADER.DllCharacteristics & WCFGInfo.IMAGE_DLL_CHARACTERISTICS_GUARD_CF)
        self.executable_sections = any([section.IMAGE_SCN_MEM_EXECUTE for section in pe.sections])
        if(not self.wcfg):
            return

        # parse data directories, required to find load config
        pe.parse_data_directories()

        # check if this PE has imports, if so record the dlls
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            self.deps = [imp.dll for imp in pe.DIRECTORY_ENTRY_IMPORT]
        
        try:
            self.xfg = bool(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags & WCFGInfo.IMAGE_GUARD_XFG_ENABLED)
            if self.xfg:
                self.guardcftable = self.parse_guardcftable(pe)
                self.type_hashes = self.extract_type_hashes(pe)
        except AttributeError as e:
            print(f"Warning: could not find attribute: {e} for {path}")
            self.potentially_managed = True

    def __init__(self, path) -> None:
        self.machine = None
        self.path = path
        self.deps = []
        self.executable_sections = True
        self.wcfg = False
        self.xfg = False
        self.type_hashes = None
        self.potentially_managed = False
        self.type_hashes = []
        self.guardcftable = []
        self.analyse(path)

    def __str__(self) -> str:
        return f"WCFGInfo({self.wcfg=}, {self.xfg=})"

if __name__ == "__main__":
    pe_files = {}
    for path, dirs, filenames in os.walk("C:\\"):
        for fs in filenames:
            try:
                full_path = realpath(join(path, fs), strict=True)

                # skip files of old windows installations
                if full_path.startswith("C:\\Windows.old\\"):
                    continue

                if not stat.S_ISREG(os.stat(full_path).st_mode):
                    print(f"Skipping file '{full_path}' which is not a regular file.")
                    continue

                info = WCFGInfo(full_path)
                pe_files[full_path] = info

            except ValueError as e:
                print(f"{e}")
            except PermissionError as e:
                print(f"Permission Error: {e}")
            except OSError as e:
                print(f"OS Error: {e}")        
            except pefile.PEFormatError as e:
                pass
            except Exception as e:
                print(f"Error - Unexpected exception: {e}")
    with open("win_analysis.pkl", "wb") as f:
        pickle.dump(pe_files, f)
    print("Finished analysis.")

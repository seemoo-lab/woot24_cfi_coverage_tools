#!/usr/bin/python3

"""
This script recursively searches for ELF files that have CFI enabled and performs analysis tasks on them.
"""

import argparse
import os
import stat
from os.path import join, realpath, isabs, islink, dirname
from functools import reduce
from pwnlib.elf.elf import ELF
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
import external_analysis
import internal_analysis
import shadow_stack_analysis
import rust_analysis
import pickle
import signal
import logging
import concurrent.futures

# Global configuration variables ------------------------------
# filter out libs that are mapped automatically and do not have a full path
lib_filter = {"linux-vdso.so"}

# Define default ld paths for Android and Linux
# Additional paths can be passed using the --ldpath flag
ld_paths = {"Linux-AMD64": ["/lib/x86_64-linux-gnu/", "/lib64/"],
            "Android-AARCH64": ["/system/lib64/"]}

# executor for performing parallel analysis
executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

class BitFilterUnmatched(Exception):
    """Signals that the supplied bit_filter did not match the file."""

class CFIInfo:
    lib_cache = {}

    def __init__(self, path, root_path, analyse_deps=True, platform="Linux-AMD64", bit_filter=64, ld_paths=[], rebase_ldpaths=False):
        """Path is the path of the file to generate CFIInfo for. If parse_deps is false, no CFIInfo is generated for dependencies."""
        self.path = path
        self.root_path = root_path
        self.has_cfi_check = False
        self.has_cfi_slowpath = False
        self.shadow_stack_count = 0
        self.deps = []
        self.relro = False
        self.is_library = False
        self.targets = None
        self.spcalls, self.icalls = None, None
        self.is_elf = False
        self.trait = []
        self.arch = ''
        self.bits = 0
        self._analyse_deps = analyse_deps
        self._ld_paths = ld_paths
        self._platform = platform
        self._rebase_ldpaths = rebase_ldpaths
        self._bit_filter = bit_filter

        self.get_cfi(path)


    def __str__(self):
        spcalls = "\n".join(map(str, self.spcalls)) if self.spcalls else "No spcalls found."
        icalls = list(map(hex, self.icalls)) if self.icalls else "No icalls found."
        return f"CFIInfo(path={self.path}, has_cfi_check={self.has_cfi_check}, has_cfi_slowpath={self.has_cfi_slowpath}, deps={self.deps})\nTargets: {self.targets}\nSPcalls: {spcalls}\nIcalls: {icalls}"

    def recursive_deps(self, visited=None):
        """Returns all dependencies recursively."""
        if visited is None:
            visited = set()
            initial_call = True
        else:
            initial_call = False

        visited.add(self.path)
        return ([self] if not initial_call else []) + sum([d.recursive_deps(visited) for d in self.deps if d.path not in visited], [])

    def get_typeid_targets(self, include_libs, visited=None):
        """Returns a dict of all typeids that are in self.targets, and additionally, if include_libs is true, also in the targets of dependencies, mapped to lists of their targets.
        Visited is a set object used to record visited elements to avoid cyclic dependencies."""

        if visited is None:
            visited = set()
        typeid_targets = {}
        visited.add(self.path)

        if self.targets:
            typeid_targets = self.targets.tables

        if include_libs:
            def dict_merge_table_list(a, b):
                """If a key is in a and b, merge the table lists mapped to that key. Else, add the key to a as well.
                Assumes that a is a mapping to a list and b to the Table type (for reduce usage).
                Returns a new dict."""
                c = {}
                for k in set(a.keys()) | set(b.keys()):
                    in_a = k in a
                    in_b = k in b
                    if in_a and in_b:
                        c[k] = a[k] + b[k]
                    elif in_a:
                        c[k] = a[k]
                    elif in_b:
                        c[k] = b[k]
                    else:
                        raise ValueError()
                return c

            return reduce(dict_merge_table_list,
                          map(lambda d: d.get_typeid_targets(include_libs, visited),
                              filter(lambda d: d.path not in visited and d.targets,
                                     self.deps)),
                          {k: v.entries for k,v in typeid_targets.items()})

        return {k: v.entries for k,v in typeid_targets.items()}


    def get_deps(self, path, log=None):
        """Obtain direct dependencies by checking the corresponding ELF header section.
        This means, that these dependencies are not recursive, i.e. dependencies of dependencies are not retrieved.
        This is not too important, since the CFIInfo class works recursively itself for obtaining all targets.

        Originally, this was implemented by using ldd. However, that approach does not work cross platform."""
        with open(path, "rb") as f:
            elf = ELFFile(f)
            dyn = elf.get_section_by_name(".dynamic")

            # This is most likely a static executable in that case
            if not dyn:
                log.info(f"{path} seems to be statically linked. Skipping dependency analysis.")
                return []

            def resolve_path(dep):
                """Tries to find the full path for a library in the current dir, the ld_paths for the current platform, or the supplied additional ld_paths."""

                # if rebase is true, the root path is added anyways, so we need to prevent it from being added two times in that case
                current_dir = dirname(path) if not self._rebase_ldpaths else dirname(path).replace(self.root_path, "")
                for d in [current_dir] + ld_paths[self._platform] + self._ld_paths:
                    try:
                        if self._rebase_ldpaths:
                            d = join(self.root_path, d[1:] if isabs(d) else d)

                        p = join(d, dep)
                        if self._rebase_ldpaths and islink(p):
                            # try to fix link target
                            target = os.readlink(p)
                            p = join(self.root_path,
                                     target[1:] if isabs(target) else target)
                        return realpath(p, strict=True)
                    except FileNotFoundError:
                        pass
                else:
                    log.warning(f"Could not find library '{dep}' required by file '{path}'.")

            deps = list(
                filter(lambda t: t is not None,
                    map(lambda t: resolve_path(t.needed),
                        filter(lambda t: (t.entry.d_tag == "DT_NEEDED" and
                                          not any(fl in t.needed for fl in lib_filter)),
                               dyn.iter_tags()))))
            return deps


    def get_cfi(self, path):
        """Checks whether a given binary exports __cfi_check, and if so, obtains information about supported type identifiers and populates class fields accordingly.
        """

        try:
            e = ELF(path)
            self.is_elf = True
            self.arch = e.arch
            self.bits = e.bits

            # if this file does not match expected bit_filter, abort
            if self._bit_filter != 0 and self.bits != self._bit_filter:
                raise BitFilterUnmatched(path)

            log.info(f"Starting analysis process for ELF file {path}")
            self.has_cfi_check = any(filter(lambda x: "__cfi_check" in x, e.symbols))
            self.has_cfi_slowpath = any(filter(lambda x: "__cfi_slowpath" in x, e.symbols))
            if {"oatdata", "oatdex", "oatdexlastword", "oatlastword"}.issubset(set(e.symbols.keys())):
                self.trait.append("oat")
            if path.endswith(".ko"):
                self.trait.append("ko")
            if rust_analysis.is_rust(path, log):
                self.trait.append("rust")

            if self._analyse_deps:
                for dep in self.get_deps(path, log):
                    if dep not in CFIInfo.lib_cache:
                        d = CFIInfo(dep, self.root_path, self._analyse_deps, self._platform,
                                    self._bit_filter,self._ld_paths, self._rebase_ldpaths)
                        CFIInfo.lib_cache[dep] = d
                        self.deps.append(d)
                    else:
                        self.deps.append(CFIInfo.lib_cache[dep])

            self.relro = e.relro
            self.is_library = e.library

            # # tmp fix for these specific files
            # if path in ["/mnt/tmp/system_ext/lib64/libwfdcommonutils.so",
            #             "/mnt/tmp/system_ext/lib64/libmsp.so",
            #             "/mnt/tmp/vendor/lib64/libopenvx.so"
            #             ]:
            #     self.has_cfi_check = False
            #     self.has_cfi_slowpath = False

            # submit futures
            if self.has_cfi_check:
                ext_fut = executor.submit(external_analysis.get_targets, path)
            if self.has_cfi_slowpath:
                int_fut = executor.submit(internal_analysis.get_spcall_icall_info, path)
            ss_fut = executor.submit(shadow_stack_analysis.has_shadow_stack, path)

            # get return values
            if self.has_cfi_check:
                self.targets = ext_fut.result()
            if self.has_cfi_slowpath:
                self.spcalls, self.icalls = int_fut.result()
            self.shadow_stack_count = ss_fut.result()

            if not self.has_cfi_check and not self.has_cfi_slowpath:
                log.info(f"Skipping analysis of {path} since it has neither __cfi_check nor __cfi_slowpath.")

        except ELFError:
            # file was not an ELF file
            pass
        except FileNotFoundError as e:
            # symbolic links can lead to this
            log.warning(f"File not found: {e}")
        except ValueError as e:
            log.warning(f"ValueError {e}: for path '{path}'")


def main():
    parser = argparse.ArgumentParser(description='The Attack Surface Analyser. \nRecursively search for ELF files that have CFI enabled. Currently only cDSO CFI is detected.')
    parser.add_argument("root_dir", help="Root directory to start searching from.")
    parser.add_argument("-p", "--platform", default="Linux-AMD64", help="Platform to use, influences LD paths that are checked for dependencies (default: %(default)s). Valid values are 'Linux-AMD64' and 'Android-AARCH64'.")
    parser.add_argument("-b", "--bits", default="64", help="Filter only for executables that have the given architecture bit width. Pass zero to include all. (default: %(default)s)")
    parser.add_argument("-l", "--ldpath", default="", help="Additional paths to check for library files. List of directories separated by ':'.")
    parser.add_argument("-r", "--resume", default="", help="Resume the execution of a previous run by loading the data file (produced by -export).")
    parser.add_argument("-i", "--ignore-dirs", default="", help="Sub-paths of the root_dir to exclude from scanning. List of directory names separated by ':'. Useful when operating on live systems that have /proc, /sys and /dev directories.")
    parser.add_argument("--rebase-ldpaths", action=argparse.BooleanOptionalAction, default=False, help="Whether to rebase ldpaths to the root_path. Useful for analysing full OS images. ")
    parser.add_argument("--analyse_deps", action=argparse.BooleanOptionalAction, default=True, help="Whether to analyse dependencies of scanned files.")
    parser.add_argument("-e", "--export", default="", help="If given, write the pickled result data to the file.")

    args = parser.parse_args()

    # setup root logging to file
    global log
    logger = logging.getLogger()
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s",
                                  "%d-%m-%Y %H:%M:%S")
    file_handler = logging.FileHandler(args.root_dir.replace("/", "_") + ".log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    try:
        bits = int(args.bits)
    except ValueError:
        print("The -b / --bits argument must be numerical.")
        return

    if args.resume:
        with open(args.resume, "rb") as f:
            CFIInfo.lib_cache = pickle.load(f)
            log.info(f"Restored previous lib_cache.")

    ld_paths = args.ldpath.split(":") if args.ldpath else []
    ignore_dirs = args.ignore_dirs.split(":") if args.ignore_dirs else []
    root_dir = realpath(args.root_dir, strict=True)
    log.info(f"Searching in {root_dir} -- filter executables with {bits} bit archs")

    # set pwnlib log level to silence warnings
    pwnlog = logging.getLogger("pwnlib")
    pwnlog.setLevel(logging.ERROR)

    # setup signal handler to gracefully shutdown
    def handler(num, frame):
        log.info("Shutting down...")
        if args.export:
            with open(args.export, "wb") as f:
                pickle.dump(CFIInfo.lib_cache, f)
            log.info("Exported data.")
        exit()

    signal.signal(signal.SIGINT, handler)

    analysed_counter = 0
    for path, dirs, filenames in os.walk(args.root_dir):
        # eliminate paths to ignore
        if path == root_dir:
            for to_remove in ignore_dirs:
                try:
                    dirs.remove(to_remove)
                except ValueError:
                    log.info(f"Requested to ignore directory '{to_remove}', which does not exist.")

        # visit the individual files
        for fs in filenames:
            try:
                full_path = realpath(join(path, fs), strict=True)

                # check if this path points to anything other than a regular file (e.g. named pipe), skip if that's the case
                if not stat.S_ISREG(os.stat(full_path).st_mode):
                    log.info(f"Skipping file '{full_path}' which is not a regular file.")
                    continue

                # check if this path was already visited as a dependency
                # this also implements resuming, by just restoring lib_cache, thus skipping over already analysed items.
                if full_path in CFIInfo.lib_cache:
                    continue

                if (c := CFIInfo(full_path, root_dir, args.analyse_deps, args.platform,
                                 bits, ld_paths, args.rebase_ldpaths)) and c.is_elf:
                    log.info(f"Finished analysis for {full_path}.")
                    CFIInfo.lib_cache[full_path] = c

                    if args.export and analysed_counter == 5:
                        with open(args.export, "wb") as f:
                            pickle.dump(CFIInfo.lib_cache, f)
                            log.info("Auto exported data.")
                            analysed_counter = 0
                    elif args.export:
                        analysed_counter += 1
                else:
                    log.debug(f"Visited '{full_path}, not an ELF file.")
            except FileNotFoundError:
                log.info(f"Could not obtain real path of file '{join(path, fs)}' - maybe broken link?")
            except BitFilterUnmatched as e:
                log.debug(f"Bit filter did not match for {e}.")
            except Exception as e:
                log.warning(f"Unexpected exception occurred when analysing {join(path, fs)}: {e}")

    if args.export:
        with open(args.export, "wb") as f:
            pickle.dump(CFIInfo.lib_cache, f)
            log.info("Exported data.")
    log.info("Finished analysis.")

if __name__ == "__main__":
    main()

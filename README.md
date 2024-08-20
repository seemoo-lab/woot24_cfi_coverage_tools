# Artifacts for the 'On the Effectiveness of CFI in Practice' paper
This directory contains the artifacts for the ['On the Effectiveness of CFI in Practice'](https://www.usenix.org/system/files/woot24-becker.pdf) paper published at WOOT'24.

## Structure
- `asa`
  - `asa_graph.py` Generates the graphs related to LLVM CFI.
  - `asa.py` Main analysis script and entry point.
  - `external_analysis.py` Used by asa.py, angr-based analysis to extract targets from `__cfi_check`.
  - `gen_comparison_table.py` Code used to generate statistics in LLVM CFI-related tables from the paper.
  - `internal_analysis_ghidra.py` Headless-ghidra script to collect CFI slowpath / icalls. 
  - `internal_analysis.py` A wrapper calling `run_ghidra_headless.sh` to execute `internal_analysis_ghidra.py`.
  - `pa_coverage.py` Generates file with PA coverage information from `.pkl`
  - `run_ghidra_headless.sh` Bash script to invoke GHDira.
  - `rust_analysis.py` Used by asa.py, Rust symbol detection.
  - `shadow_stack_analysis.py` Used by asa.py, check for shadow stack.
- `asa_results/`Pre-generated data set resulting from asa.py.

- `clang` contains the source code and Makefile for the TOCTOU bypass PoC exploiting a race condition in LLVM's CDSO CFI.
  Successful execution should look like this:
  ```
  $ ./timing_attack
  Allocation at: 7fb81e61f000
  Target at: 7fb2dcf5ecc6
  Shadow base at: 7fa81de1e000
  this should not have happened.
  ```
  The last line indicates that the target function was successfully called.
  
  To confirm that without the simulated attack, CFI would have prevent this call, comment out line 28 in `timing_attack.cpp`.
  Execution should now look like this:
  ```
  $ ./timing_attack
  Allocation at: 7fa06501f000
  Target at: 7f9b177419cc
  Shadow base at: 7f906481e000
  [1]    97839 illegal hardware instruction  ./timing_attack
  ```

- `firmware_tools` contains scripts for extracting/mounting the different firmware files analysed in the paper.

- `wcfg` contains scripts related to Windows CFG and XFG.
  - `enum_dll_suppressed.py` is used to enumerate DLLs with suppressed XFG-instrumented functions on a Windows system.
    Its use-case was to determine potential targets for the XFG bypass discussed in section `5.3 Windows Study`.
  - `enum_pa.py` Used to enumerate which files use which PA instructions.
  - `enum_win.py` Windows main analysis script. Produces `win_analysis.pkl`.
  - `filter_pa_instructions.py` Script to calculate statistics of PA usage based on the output of `enum_pa.py`.
  - `win_analysis.pkl` Result from `enum_win.py`.
  - `win_graph.py` generates Figure 7 from `win_analysis.pkl`.
  - `win_stats.py` generate stats in `Table 4: Windows 11 Insider Preview CFI coverage` from `win_analysis.pkl`.
  - `xfg_bypass.cpp`Code highlighting an issue with XFG hashes and suppressed functions. Seems to be fixed in recent VisualStudio versions.


## Setup (assuming Linux host) and instructions for analysing Android LLVM usage
1. Install software requirements listed below
2. Create and activate venv
3. Install requirements.txt in it
4. Prepare the firwmare to analyse:
   1. extract image
   2. (if applicable) un-sparse image
   3. (if applicable) unpack super.img
   4. mount system.img and different sub-images to some mount point
5. Run the script, e.g., for GSI 14:
   ```bash
     mkdir outdir
     python3 asa.py -p "Android-AARCH64" --rebase-ldpaths -e outdir/gsi_14.pkl -l "/system/system_ext/apex/com.android.runtime/lib64/bionic/:/system/system_ext/apex/com.android.i18n/lib64/:/system/system_ext/apex/com.google.android.art/lib64/:/system/system_ext/apex/com.google.android.os.statsd/lib64/:/system/system_ext/apex/com.google.android.adbd/lib64/:/system/system_ext/apex/com.google.android.media/lib64/:/system/system_ext/apex/com.google.android.tethering/lib64/:/system/system_ext/apex/com.google.android.resolv/lib64/" /mnt/gsi_14_bind/
   ```
6. Prepare cache with PA data: `python3 pa_coverage.py outdir`
7. Perform arbitrary analysis on result data. For examples, see the snippets below or the code in `gen_comparison_table.py` (modify `target_dirs` as needed).
```python
with open(join(target_dir, p), "rb") as f:
    cfidata = list(pickle.load(f).values())
    
    bins = [d for d in data if not d.is_library and "ko" not in d.trait and "oat" not in d.trait and "rust" not in d.trait]
    libs = [d for d in data if     d.is_library and "ko" not in d.trait and "oat" not in d.trait and "rust" not in d.trait]
    kos  = [d for d in data if                      "ko"     in d.trait]
    
    # get protected binaries
    [b.path for b in bins if b.has_cfi_check]
```


## Setup and instructions for analysing Windows image
1. Setup Windows guest with the target image (e.g., in VM) and python
2. Install python on the guest
3. Run `enum_win.py` inside the guest to obtain result data.

## Software Requirements (for analysing LLVM usage)
- python3
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)  
  `run_ghidra_headless.sh` assumes installation to /opt/ghidra.
   It is advisable to raise `MAXMEM` in `ghidra/support/analyzeHeadless` depending on the available resources.
- [radare2](https://github.com/radareorg/radare2)  
  Used for batch analysis (r2pipe)
- [rizin](https://rizin.re/)  
  Used for batch analysis (for some functionality due to bugs in radare2)
- bindfs  
  Used for re-mounting firmware accessible to users without root.
- binutils-aarch64-linux-gnu
  Used to check for shadowstack instructions in aarch64 executables.

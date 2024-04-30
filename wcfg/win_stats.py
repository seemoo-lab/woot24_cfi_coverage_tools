from os import sysconf
import pickle
from enum_win import WCFGInfo
from collections import Counter
import statistics

ignore_dirs = ["C:\\Users\\vboxuser\\Downloads\\",
               "C:\\Users\\vboxuser\\AppData\\Local\\Programs\\Python",
               "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community",
               "C:\\Program Files (x86)\\Microsoft Visual Studio\\",
               "C:\\Windows\\assembly\\",
               "C:\\Windows\\System32\\drivers\\",
               "C:\\Windows\\System32\\DriverStore\\FileRepository\\",
               "C:\\Windows\\WinSxS\\",
               "C:\\Users\\vboxuser\\AppData\\Local\\Temp\\"]

def load_data():
    with open("win_analysis.pkl", "rb") as f:
        d = pickle.load(f) # get the full dict, useful for prot. deps lookups
        data = list(d.values())

        # pre-filter to only x64 files and exclude .mui
        data = [d for d in data
                if d.machine == 0x8664
                and d.executable_sections
                and (d.path.endswith(".exe") or d.path.endswith(".dll"))
                and not any(d.path.startswith(ign) for ign in ignore_dirs)]

        # sanity checks
        assert len([d for d in data if d.xfg and not d.wcfg]) == 0
        return d, data

if __name__ == "__main__":
    data_raw, data = load_data()


    # get base stats
    all_exe = [d for d in data if d.path.endswith(".exe")]
    all_dll = [d for d in data if d.path.endswith(".dll")]
    sys_dll = [d for d in data if d.path.endswith(".dll") and d.path.startswith("C:\\Windows\\System32\\")]
    for i, data_set in enumerate([all_exe, all_dll, sys_dll, data]):

        print(["exe", "dll", "sys dll", "combined"][i])
        unprotected = [d for d in data_set if not d.wcfg]
        print(f"Unprotected: {len(unprotected)} ({len(unprotected) / len(data_set) * 100} %)")

        wcfg_protected = [d for d in data_set if d.wcfg and not d.xfg]
        xfg_protected = [d for d in data_set if d.xfg]
        print(f"only wcfg: {len(wcfg_protected)} ({len(wcfg_protected) / len(data_set) * 100} %), xfg protected: {len(xfg_protected)} ({len(xfg_protected) / len(data_set) * 100} %)")

        assert len(unprotected) + len(wcfg_protected) + len(xfg_protected) == len(data_set)

        # eq class size geometric mean
        sizes = sum([[len(hs) for hs in d.type_hashes.values()] for d in data_set if d.xfg], [])
        print(f"eq class size geometric mean: {statistics.geometric_mean(sizes)}")

    # investigate most common deps, to see if they are protected
    # cnt = Counter(sum([[d.lower() for d in x.deps] for x in data if x.wcfg], []))
    # for dll, _ in cnt.most_common(100):
    #     dll_candidates = [cand for cand in data if cand.path.endswith(dll.decode())]
    #     if not dll_candidates:
    #         print(f"Found no candidate for {dll}")
    #         continue

    #     print(dll, any([c.wcfg for c in dll_candidates]), any([c.xfg for c in dll_candidates]))
        
    # check how many tables contain mixed entries
    prc = []
    for d in data:
        if d.xfg:
            entries_xfg = [entry for entry in d.guardcftable if entry[1] & WCFGInfo.IMAGE_GUARD_FLAG_FID_XFG]
            prc.append(len(entries_xfg) / len(d.guardcftable) * 100)
    print("avg percentage of xfg entries in xfg marked PEs", statistics.mean(prc))

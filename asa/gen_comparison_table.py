#!/usr/bin/python3

from collections import Counter
from os.path import basename, join
from os import listdir
import statistics
from asa import CFIInfo
import pickle
from asa_graph import print_stats, get_pbins_with_uplib_deps
import sys

s20_prec = ["G980FXXSIHWGA", "G980FXXSFHWB1", "G980FXXUFGVJE", "G980FXXSFFVIB", "G980FXXUEFVDB", "G980FXXSCEUL7", "G980FXXSCDUJ5", "G980FXXS8DUE4", "G980FXXU5CTKG", "G980FXXU5BTJ3", "G980FXXU2ATE6", "G980FXXU1ATBM"]

umi_prec = ["V11.0.9.0.QJBEUXM", "V11.0.18.0.QJBEUXM", "V12.0.6.0.QJBEUXM", "V12.2.4.0.RJBEUXM", "V12.5.2.0.RJBEUXM", "V12.5.8.0.RJBEUXM", "V13.0.4.0.SJBEUXM", "V13.0.10.0.SJBEUXM", "V14.0.1.0.TJBEUXM", "V14.0.2.0.TJBEUXM"]

def resolve_name(n):
    if "gsi_" in n:
        return n.replace("_", " ").replace(".pkl", "").upper()

    if "SM" in n:
        return n.split("_")[-1].replace("G980FXX", "S20 ").replace(
            ".pkl",
            f" ({12 - s20_prec.index(n.replace('.pkl', '').replace('SM-G980F_BTB_', ''))})"
        )

    if n.startswith("V"):
        return "Mi 10 " + ".".join(n.split(".")[:3])
    
    return {

        "panther.pkl": "Google Pixel 7",
        "v25.pkl": "Vivo V25",
        "s22.pkl": "Samsung Galaxy S22",
        "fuxi.pkl": "Xiaomi 13",
        "r8.pkl": "Oppo Reno 8 5G",
        "graphene.pkl": "GrapheneOS Pixel 7",
    }[n]

        
def print_table_row(data, cache):
    prcnt = lambda x,y: round(len(x) / len(y) * 100, 2) if len(y) > 0 else "n/a"
    
    bins = [d for d in data if not d.is_library and "ko" not in d.trait and "oat" not in d.trait and "rust" not in d.trait]
    libs = [d for d in data if     d.is_library and "ko" not in d.trait and "oat" not in d.trait and "rust" not in d.trait]
    kos  = [d for d in data if                      "ko"     in d.trait]

    # llvm cfi
    pbins, plibs, pkos = (prcnt([b for b in bins if b.has_cfi_check], bins),
                          prcnt([l for l in libs if l.has_cfi_check], libs),
                          prcnt([k for k in kos  if k.has_cfi_check], kos))
    
    # shadow stack
    sspbins, ssplibs, sspkos = (prcnt([b for b in bins if b.shadow_stack_count], bins),
                                prcnt([l for l in libs if l.shadow_stack_count], libs),
                                prcnt([k for k in kos  if k.shadow_stack_count], kos))

    # pa
    papbins, paplibs, papkos = (prcnt([b for b in bins if cache[b.path] >= {'paciasp', 'autiasp'}], bins),
                                prcnt([l for l in libs if cache[l.path] >= {'paciasp', 'autiasp'}], libs),
                                prcnt([k for k in kos  if cache[k.path] >= {'paciasp', 'autiasp'}], kos))
        
    print(f"{resolve_name(p)} & {len(bins)} & {len(libs)} & {len(kos)} & {pbins} & {plibs} & {pkos} & {sspbins} & {ssplibs} & {sspkos} & {papbins} & {paplibs} & {papkos} \\\\")

# sorting list of precedence so one can tell the order
def image_order(i):
    if "gsi" in i:
        return (2, i)
    elif "G980F" in i:
        return (3, -s20_prec.index(i.replace(".pkl", "").replace("SM-G980F_BTB_", "")))
    elif i.startswith("V"):
        return (4, umi_prec.index(i.replace(".pkl", "")))
    else:
        return (1, i)
    

cmd = "overview" if len(sys.argv) <= 1 else sys.argv[1]

target_dirs = ["../../asa_results/gsi_results/",
               "../../asa_results/misc_results/",
               "../../asa_results/graphene_results/",
               "../../asa_results/s20_results/",
               "../../asa_results/umi_results/",
               ]

for target_dir in target_dirs:
    for p in sorted(filter(lambda x: x.endswith(".pkl"), listdir(target_dir)), key=image_order):
            with open(join(target_dir, p), "rb") as f:
                cfidata = list(pickle.load(f).values())

                # table 2
                if cmd == "overview":
                    cache = dict()
                    with open(join(target_dir, p.replace(".pkl", "_pa_coverage.txt"))) as cache_file:
                        for l in cache_file:
                            n, pa = l.strip().split(" -- ")
                            pa = eval(pa)

                            _, _, vendor, *rest = n.split("/", 3)
                            vendor = vendor.replace("_bind", "")
                            cache[n] = pa
                    print_table_row(cfidata, cache)
                # table 3
                elif cmd == "unprot-dep":
                    unprot = [x for _,_,x in get_pbins_with_uplib_deps(d for d in cfidata if d.has_cfi_check and not "ko" in d.trait and not d.is_library)]
                    min_unprot = min(unprot)
                    max_unprot = max(unprot)
                    av_unprot = sum(unprot) / len(unprot)
                    print(f"{resolve_name(p)} & {round(min_unprot, 2)} & {round(av_unprot, 2)} & {round(max_unprot, 2)}")
                elif cmd == "reachable":              
                    # means over all targets without deps, reachable targets without deps, reachable targets with deps for all binaries that have spcalls
                    func = statistics.geometric_mean
                    def with_prot_deps(ci):
                        return any(d.has_cfi_check for d in ci.recursive_deps())

                    all_targets_no_deps = func(sum([list(map(len, ci.get_typeid_targets(False).values()))
                                                               for ci in cfidata if not ci.is_library and "ko" not in ci.trait and ci.spcalls and with_prot_deps(ci)],
                                                              start=[]))

                    all_targets_deps = func(sum([list(map(len, ci.get_typeid_targets(True).values()))
                                                               for ci in cfidata if not ci.is_library and "ko" not in ci.trait and ci.spcalls and with_prot_deps(ci)],
                                                              start=[]))

                    def filter_reachable(targets, spcalls):
                        spcall_tids = set(s.typeid for s in spcalls) # if s.typeid != 0)

                        return [
                            t for tid, t in targets
                            if tid in spcall_tids
                        ]
                    reachable_targets_no_deps = func(sum([list(map(len, filter_reachable(ci.get_typeid_targets(False).items(),
                                                                                         ci.spcalls)))
                                                          for ci in cfidata if not ci.is_library and "ko" not in ci.trait and ci.spcalls and with_prot_deps(ci)],
                                                         start=[]))

                    reachable_targets_deps = func(sum([list(map(len, filter_reachable(ci.get_typeid_targets(True).items(),
                                                                                      ci.spcalls)))
                                                          for ci in cfidata if not ci.is_library and "ko" not in ci.trait and ci.spcalls and with_prot_deps(ci)],
                                                         start=[]))            
                    print(f"{resolve_name(p)} & {round(all_targets_no_deps, 5)} & {round(all_targets_deps, 5)} & {round(reachable_targets_no_deps, 5)} & {round(reachable_targets_deps, 5)} \\\\")

                # exec_size_cache = {}
                # def get_exec_size(path):
                #     if path in exec_size_cache:
                #         return exec_size_cache[path]
                #     e = ELF(path)
                #     exec_size = sum(seg.header.p_memsz for seg in e.executable_segments)
                #     exec_size_cache[path] = exec_size
                #     return exec_size

                # for b, deps in [(ci.path, ci.recursive_deps()) for ci in cfidata if not ci.is_library and ci.spcalls and with_prot_deps(ci)]:
                #     deps_sizes = []
                #     for d in deps:
                #         if d.has_cfi_check:
                #             deps_sizes.append(get_exec_size(d.path))
                #     print(f"{b} - {get_exec_size(b)} vs {statistics.mean(deps_sizes)}")


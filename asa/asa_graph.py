#!/usr/bin/python3

"""
This script contains functions for operating on the analysis result data to produce statistics and graphs.
"""

from collections import Counter
from os.path import basename, join
from asa import CFIInfo
import pickle
import matplotlib as mpl
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from pwnlib.elf.elf import ELF
import numpy as np
import os
import statistics
from matplotlib.ticker import FormatStrFormatter

# copied from gen_comparison table, can't include due to circular import
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


def get_by_name(cfidata, name):
    """Returns a CFIInfo object by name or None if not found."""
    for ci in cfidata:
        if ci.path.endswith(name):
            return ci
    return None


def protected_unprotected(cfidata):
    """Sorts into unprotected vs protected (has at least __cfi_check) and library or not."""

    plibs, uplibs, pbins, upbins = [], [], [], []
    for cfidata in cfidata:
        if cfidata.is_library:
            (plibs if cfidata.has_cfi_check else uplibs).append(cfidata)
        else:
            (pbins if cfidata.has_cfi_check else upbins).append(cfidata)

    return (plibs, uplibs, pbins, upbins)


def get_failed_const_prop_ratio(cfidata):
    """Returns the ratio of failed constant propagation in percent per CFIInfo that have cfi_slowpath.
    Ignores fully crashed analysis runs (where cfi.spcalls is None)."""
    return [(len([c for c in cfi.spcalls if c.typeid == 0]) / len(cfi.spcalls) * 100)
            if len(cfi.spcalls) else 0
            for cfi in cfidata
            if (cfi.has_cfi_slowpath and
                cfi.spcalls is not None)]


def get_failed_ghidra_analysis(cfidata):
    """Returns CFIInfo entries where cfi.has_cfi_slowpath is true but spcalls are None."""
    return [cfi for cfi in cfidata
            if (cfi.has_cfi_slowpath and cfi.spcalls is None)]


def get_pbins_with_uplib_deps(pbins):
    """Find protected binaries that have unprotected libraries as dependencies.
    Also removes duplicate basenames."""

    res = []
    visited = set()
    for ci in pbins:
        if basename(ci.path) in visited:
            continue
        visited.add(basename(ci.path))
        rd = ci.recursive_deps()
        udeps = [d for d in rd if not d.has_cfi_check]
        if udeps:
            res.append((ci, udeps, len(udeps) / len(rd) * 100))
    return sorted(res, key=lambda x: x[2])


def metrics(cfidata, path_replacements={}):
    """Calculates the following metrics for slow_path calls and a coarse-grained scheme where each target is allowed:
    - Average Indirect Target Reduction (AIR)
    -
    Path replacement can be used to adjust the path used for obtaining the executable section size."""

    exec_size_cache = {}
    def get_exec_size(path):
        if path in exec_size_cache:
            return exec_size_cache[path]
        e = ELF(path)
        exec_size = sum(seg.header.p_memsz for seg in e.executable_segments)
        exec_size_cache[path] = exec_size
        return exec_size

    def fix_path(path):
        for val, repl in path_replacements.items():
            path = path.replace(val, repl)
        return path

    paths, air, aia, rair, qs = [], [], [], [], []
    for ci in cfidata:
        if (ci.spcalls and ci.has_cfi_check and not ci.is_library
            and not ci.path.endswith(".ko")):
            targets = ci.get_typeid_targets(True)
            file_path = fix_path(ci.path)
            deps = ci.recursive_deps()

            # Variable names are chosen as they are in the formula where applicable
            S = (get_exec_size(file_path) + sum(get_exec_size(fix_path(c.path)) for c in deps))
            n = len(ci.spcalls)
            uplib_targets = sum(get_exec_size(fix_path(c.path))
                                for c in deps if not c.has_cfi_check)
            # The coarse grained scheme uses the same target set for each slow_path call
            Tj_prime = len(sum(targets.values(), [])) + uplib_targets

            air_sum = aia_sum = rair_sum = 0
            for sp in ci.spcalls:
                Tj = (len(targets.get(sp.typeid, [])) + uplib_targets)
                air_sum += 1 - Tj / S
                aia_sum += Tj
                rair_sum += 1 - (Tj / Tj_prime)

            # loop independent, always constant terms
            air_baseline = (1 - Tj_prime / S)
            aia_baseline = Tj_prime * n
            LC = max(len(ts) for ts in targets.values()) + uplib_targets
            qs_v = len(targets.keys()) / LC
            # data for manual analysis
            up_p_size_ratio = sum(get_exec_size(fix_path(d.path)) for d in deps if d.has_cfi_check) / sum(get_exec_size(fix_path(d.path)) for d in deps if not d.has_cfi_check)
            # store results for this file
            paths.append(ci.path)
            air.append((air_baseline, air_sum / n, up_p_size_ratio))
            aia.append((aia_baseline, aia_sum / n))
            rair.append((None, rair_sum / n)) # has no baseline, already compares against it
            qs.append((1 / Tj_prime, qs_v))
    return (paths, air, aia, rair, qs)


def p_up_ratio_plot(cfidata, sep_vendor=False, prefix_path="", export_mode=False, filename="ratio.pgf"):
    """Generates a Pie chart for the protected / unprotected ratio.
    If sep_vendor is true, filter also in vendor binaries / libs, advisable to then use prefix_path so that after the prefix is removed, one gets /vendor as root dir for vendor binaries and libraries."""
    plibs, uplibs, pbins, upbins = protected_unprotected(cfidata)

    # important: the order is difference than the return value from protected_unprotected
    # it must match the category labels below
    cat_data = (pbins, upbins, plibs, uplibs)
    total = sum(map(len, cat_data))
    categories = ("Protected Binaries", "Unprotected Binaries", "Protected Libraries", "Unprotected Libraries")

    if not sep_vendor:
        data = list(map(len, cat_data))
        explode = [0,0,0.15,0]
        colors = ['#4393c3', '#d6604d', '#92c5de', '#f4a582']
    else:
        data = [
            len([cfiinfo
                 for cfiinfo in category
                 if cfiinfo.path.replace(prefix_path, "").startswith("/vendor/") == vendor])
            for category in cat_data
            for vendor in (False, True)
        ]

        colors = ['#4393c3','#2166ac','#d6604d','#b2182b','#d1e5f0','#92c5de','#fddbc7','#f4a582']
        categories = [cat.replace(" ", " Vendor " if vendor else " ")
                      for cat in categories
                      for vendor in (False, True)]
        explode = [0,0.15,0,0,0,0,0,0]

    def fmt(v):
        percentile = v / total * 100
        return "{:.1f}\\% ({:d})".format(percentile, v)

    fig, ax = plt.subplots()
    wedges, labels = ax.pie(data,
                            colors=colors,
                            startangle=35 if sep_vendor else -15,
                            labeldistance=0.85 if sep_vendor else 0.7,
                            rotatelabels=sep_vendor,
                            explode=explode)

    kw = dict(arrowprops=dict(arrowstyle="-"), zorder=0, va="center", fontsize=13)
    for i, p in enumerate(wedges):
        ang = (p.theta2 - p.theta1)/2. + p.theta1
        y = np.sin(np.deg2rad(ang))
        x = np.cos(np.deg2rad(ang))
        horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
        connectionstyle = "angle,angleA=0,angleB={}".format(ang)
        kw["arrowprops"].update({"connectionstyle": connectionstyle})
        ax.annotate(f"{categories[i]}\n{fmt(data[i])}",
                    xy=(x, y), xytext=(1.35*np.sign(x), 1.5*y),
                    horizontalalignment=horizontalalignment, **kw)

    # export graph for use in latex
    if export_mode:
        plt.axis("off")
        ax.get_xaxis().set_visible(False)
        ax.get_yaxis().set_visible(False)
        fig.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0.3)
    else:
        ax.set_title("Protection Levels of Binaries and Libraries", fontdict={"fontsize":"15"})
        plt.show()


def eqclass_sizes_scatter_plot(cfidata, xl, export_mode=False, filename="eqclass_sizes.pgf"):
    """Plots the equivalence class sizes by number of occurrences as scatter plot.
    xl is the xlim value if not None, useful to exclude large outliers."""

    eqclass_sizes = Counter(sum([list(map(len,
                                        ci.get_typeid_targets(False).values()))
                               for ci in cfidata],
                              start=[]))

    with sns.axes_style("ticks"):
        x = list(eqclass_sizes.keys())
        y = list(eqclass_sizes.values())

        print("eqclass size average:",
              sum([size * occ for size,occ in eqclass_sizes.items()]) / sum(eqclass_sizes.values()))


        jp = sns.jointplot(x=x, y=y,
                           kind="scatter",
                           color="#2166ac")
        axes = jp.figure.axes
        jp.set_axis_labels(f'Equivalence Class Size', 'Number of occurrences (log scale)')

        plt.yscale("log")
        if xl:
            print(sorted(filter(lambda y: y[0] >= xl, eqclass_sizes.items()), key=lambda x: x[0]))
            plt.xlim(0, xl)
        plt.grid()

        if export_mode:
            jp.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0)
        else:
            plt.show()

def eqclass_sizes_scatter_plot_combined(cfidata_list, filename="eqclass_sizes_combined.pgf"):
    """Plots the equivalence class sizes by number of occurrences as scatter plot, combining different firmware images into single graph..
    xl is the xlim value if not None, useful to exclude large outliers."""


    eqclass_sizes = [(Counter(sum([list(map(len,
                                        ci.get_typeid_targets(False).values()))
                                  for ci in cfidata],
                                  start=[])),
                      resolve_name(img))
                     for cfidata, img in cfidata_list]

    with sns.axes_style("ticks"):

        data = [(k, v, es[1]) for es in eqclass_sizes for k,v in es[0].items()]
        df = pd.DataFrame(data, columns = ["size", "count", "Firmware Image"])
        # print(df)

        # derived from sns.color_palette("hls", 6)
        palette = [(0.8287999999999999, 0.86, 0.33999999999999997), (0.33999999999999997, 0.86, 0.3712), (0.33999999999999997, 0.8287999999999999, 0.86), (0.99, 0.11, 0.11), (0.3712, 0.33999999999999997, 0.86), (0.86, 0.33999999999999997, 0.8287999999999999)]
        jp = sns.relplot(df,
                         height=5,
                         aspect=1.2,
                         x="size",
                         y="count",
                         hue="Firmware Image",
                         kind="scatter",
                         s=25, # size of dots
                         style="Firmware Image", # generate different markers
                         # markers=["D", "v", "s", "X", "P", "p"] # types of markers
                         )
        jp.legend.remove()
        plt.legend(title="Firmware Image", loc="upper right", bbox_to_anchor=[0.48, 0.48, 0.5, 0.5], facecolor="white", framealpha=1, fontsize=8, title_fontsize=9)
        jp.set_axis_labels(f'Equivalence Class Size (log scale)', 'Number of occurrences (log scale)')
        plt.yscale("log")
        plt.xscale("log")
        plt.grid()

        jp.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0)

def eqclass_sizes_scatter_plot_deps(cfidata, xl=0, yl=0, show_legend=True, export_mode=False, filename="eqset_sizes_bins.pgf"):
    """Plots the reachable (i.e. with associated slowpath call) eqclass sizes of binaries with and without dependencies."""

    def filter_reachable(targets, spcalls):
        spcall_tids = set(s.typeid for s in spcalls) # if s.typeid != 0)

        return [
            targets for tid, targets in targets
            if tid in spcall_tids
        ]

    df = pd.DataFrame(
        data=[(size,
               count,
               basename(ci.path).replace("_", "\\_"))
              for ci in cfidata if ci.has_cfi_slowpath
              for size, count in Counter(
                      map(len,
                          filter_reachable(
                              ci.get_typeid_targets(True).items(),
                              ci.spcalls))
              ).items()],
        columns = ["size", "count", "binary"])

    print("average eq class size with deps", (df["count"] * df["size"]).sum() / df["count"].sum())

    with sns.axes_style("ticks"):
        jp = sns.jointplot(df,
                           x="size",
                           y="count",
                           hue="binary",
                           kind="scatter",
                           color="#4CB391")
        jp.set_axis_labels(f'Equivalence Class Size (Log Scale)', 'Number of occurrences')
        if not show_legend:
            jp.figure.axes[0].get_legend().remove()
        bot, top = plt.ylim()
        plt.ylim(0, top if not yl else yl)
        jp.figure.axes[0].minorticks_on()
        plt.xscale("log")

        if xl:
            plt.xlim(0, xl)
        plt.grid()

        if export_mode:
            jp.figure.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0)
        else:
            plt.show()

def eqclass_deps_impact(binary, xl=0, yl=0, show_legend=True, filename="eqset_sizes_bins.pgf"):
    """Plots the reachable (i.e. with associated slowpath call) eqclass sizes of binaries with and without dependencies."""

    def filter_reachable(targets, spcalls):
        spcall_tids = set(s.typeid for s in spcalls)

        return [
            t for tid, t in targets
            if tid in spcall_tids
        ]

    df = pd.DataFrame(
        data=[(size,
               with_deps,
               count)
              for with_deps in [True, False]
              for size, count in Counter(
                      map(len,
                          filter_reachable(
                              binary.get_typeid_targets(with_deps).items(),
                              binary.spcalls))
              ).items()],
        columns = ["size", "with\\_deps", "count"])

    with sns.axes_style("ticks"):
        jp = sns.jointplot(df,
                           x="size",
                           y="count",
                           hue="with\\_deps",
                           kind="scatter",
                           color="#4CB391")
        jp.set_axis_labels(f'Equivalence Class Size (Log Scale)', 'Number of occurrences')
        if not show_legend:
            jp.figure.axes[0].get_legend().remove()
        bot, top = plt.ylim()
        plt.ylim(0, top if not yl else yl)
        jp.figure.axes[0].minorticks_on()
        plt.xscale("log")

        if xl:
            plt.xlim(0, xl)
        plt.grid()

        jp.figure.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0)




def eqclass_sizes_distribution(cfidata, export_mode=False, filename="eqclass_sizes_distrib.pgf"):
    """Plots the equivalence class sizes by number of occurrences as scatter plot."""

    eqclass_sizes = sum([list(map(len,
                                  ci.get_typeid_targets(False).values()))
                         for ci in cfidata],
                        start=[])

    with sns.axes_style("ticks"):
        jp = sns.displot(eqclass_sizes,
                         stat="density",
                         kind="kde",
                         color="#2166ac")
        axes = jp.figure.axes
        jp.set_axis_labels(f'Equivalence Class Size', 'Number of occurrences (log scale)')

        plt.grid()
        if export_mode:
            jp.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0)
        else:
            plt.show()


def bins_uplib_barplot(cfidata, export_mode=False, filename="unprot_deps.pgf"):
    """Plots the percentage of unprotected dependency libs as bar plot."""

    def shorten_name(n):
        threshold = 20
        if len(n) > threshold:
            n = "..." + n[-17:]
        return n.replace("_", "\\_").replace("@", "\\@")

    bins, _, deps_ratio = list(zip(*get_pbins_with_uplib_deps(cfidata)))
    bins = [basename(b.path) if not export_mode else shorten_name(basename(b.path))
            for b in bins]
    with sns.axes_style("ticks"):
        fig, ax = plt.subplots(figsize=(8,3))
        sns.barplot(x=bins, y=list(deps_ratio),
                    palette=sns.color_palette("blend:#2166ac,#4393c3,#d6604d,#b2182b", len(bins)),
                    ax=ax)
        plt.xticks(rotation=90)
        ax.set_ylabel('Unprotected dependencies in percent')
        plt.grid()

        if export_mode:
            fig.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0)
        else:
            plt.show()


def print_stats(cfidata, path_replacement={}):
    """Calculate and print some numerical / textual stats."""

    plibs, uplibs, pbins, upbins = protected_unprotected(cfidata)
    print(f"{len(plibs)} protected / {len(uplibs)} unprotected libraries.")
    print(f"{len(pbins)} protected / {len(upbins)} unprotected binaries.")
    # print(f"\nProtected libraries:\n" + "\n".join(map(lambda l: l.path, plibs)))
    # print(f"\nProtected binaries:\n" + "\n".join(map(lambda l: l.path, pbins)))

    failed_analysis = get_failed_ghidra_analysis(cfidata)
    print(f"\nNumber of failed Ghidra analysis runs: {len(list(failed_analysis))}")

    prop_fail = get_failed_const_prop_ratio(cfidata)
    print(f"\nAverage constant propagation failure rate: {sum(prop_fail) / len(prop_fail)}")

    no_relro = [b.path for b in plibs + pbins
                if not b.relro and not b.path.endswith(".ko")]
    print(f"No relro: {no_relro}")

    up_deps = get_pbins_with_uplib_deps(pbins)
    print(f"\nBinaries that have dependencies on unprotected libraries ({len(up_deps)} / {len(pbins)}):")
    for binary, _, percentage in up_deps:
        print(f"{binary.path} ({percentage}%)")

    print("Air values:")
    for name, metric in zip(["AIR", "AIA", "RAIR", "QS"],
                            metrics(cfidata, path_replacement)[1:]):
        baseline, v, *_ = list(zip(*metric)) # allow additional fields for manual analysis
        avg_v = sum(v) / len(v)
        min_v = min(v)
        max_v = max(v)
        print(f"{name} -- Avg: {avg_v}, {min_v}, {max_v}")
        if any(baseline):
            avg_bl = sum(baseline) / len(baseline)
            min_bl = min(baseline)
            max_bl = max(baseline)
            print(f"{name} Baseline -- Avg: {avg_bl}, {min_bl}, {max_bl}")
        print()


def get_data_eval(data, cache):
    # Data processing taken from gen_comparison table
    prcnt = lambda x,y: round(len(x) / len(y) * 100, 2) if len(y) > 0 else 1000 # use 1000 to detect these cases, there should not be n/a here.

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
    return (pbins, plibs, papbins, paplibs)

def dev_over_time(cfidata_list, export_mode=True, filename="dev_over_time.pgf"):
    with sns.axes_style("ticks"):
        # fill this data
        pbins_percent = []
        plibs_percent = []
        papbins_percent = []
        paplibs_percent = []

        for data in cfidata_list:
            # get the pa cache (change this path below if doing other image series)
            cache = dict()
            img_path = data[0].path.split("/")[2].replace("_fac_bind", "")
            with open(join("../../asa_results/s20_results/", img_path + "_pa_coverage.txt")) as cache_file:
                for l in cache_file:
                    n, pa = l.strip().split(" -- ")
                    pa = eval(pa)

                    _, _, vendor, *rest = n.split("/", 3)
                    vendor = vendor.replace("_bind", "")
                    cache[n] = pa

            pbins, plibs, papbins, paplibs = get_data_eval(data, cache)
            pbins_percent.append(pbins)
            plibs_percent.append(plibs)
            papbins_percent.append(papbins)
            paplibs_percent.append(paplibs)

        df = pd.DataFrame({
            "Prot. Binaries": pbins_percent,
            "Prot. Libraries" : plibs_percent,
            "PA prot. Binaries" : papbins_percent,
            "PA prot. Libraries" : paplibs_percent})

        jp = sns.lineplot(data=df, drawstyle='steps-post')
        axes = jp.figure.axes
        # jp.set_axis_labels(f'Equivalence Class Size', 'Number of occurrences (log scale)')
        plt.grid()

        jp.set_xticks(range(12)) # <--- set the ticks first
        jp.set_xticklabels(list(range(1, 13)))

        # move 1 to left side
        plt.xlim(0, 11)

        # hardcode Android release labels
        plt.axvline(3, color="black", linewidth=0.5)
        plt.text(3.1, 11, 'Android 11',rotation=90)

        plt.axvline(6, color="black", linewidth=0.5)
        plt.text(6.1, 16, 'Android 12',rotation=90)

        plt.axvline(9, color="black", linewidth=0.5)
        plt.text(9.1, 16, 'Android 13',rotation=90)

        if export_mode:
            plt.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0)
        else:
            plt.show()

def dev_over_time_bars(cfidata_list, target_series='gsi', export_mode=True, filename="dev_over_time.pgf"):
    with sns.axes_style("ticks"):
        # fill this data
        pbins_percent = []
        plibs_percent = []
        papbins_percent = []
        paplibs_percent = []

        for data in cfidata_list:
            # get the pa cache (change this path below if doing other image series)
            cache = dict()
            match target_series:
                case "gsi":
                    img_path = data[0].path.split("/")[2].replace("_bind", "")
                case "s20":
                    img_path = data[0].path.split("/")[2].replace("_fac_bind", "")
                case "umi":
                    img_path = data[0].path.split("/")[2].split("_")[4]
            
            with open(join(f"../../asa_results/{target_series}_results/", img_path + "_pa_coverage.txt")) as cache_file:
                for l in cache_file:
                    n, pa = l.strip().split(" -- ")
                    pa = eval(pa)

                    _, _, vendor, *rest = n.split("/", 3)
                    vendor = vendor.replace("_bind", "")
                    cache[n] = pa

            pbins, plibs, papbins, paplibs = get_data_eval(data, cache)
            pbins_percent.append(pbins)
            plibs_percent.append(plibs)
            papbins_percent.append(papbins)
            paplibs_percent.append(paplibs)

        # setup values for different datasets
        match target_series:
            case "gsi":
                versions = [10, 11, 12, 13, 14]
                partition_by_release = lambda x: x
            case "s20":
                versions = [10, 11, 12, 13]

                # offsets are hardcoded for S20
                def partition_by_release(coll):
                    offsets = [0, 3, 6, 9, 12]
                    return map(statistics.mean,
                        [coll[offsets[i-1]:offsets[i]]
                         for i in range(1, len(offsets))])
            case "umi":
                versions = [10, 11, 12, 13]

                # offsets are hardcoded for M10
                def partition_by_release(coll):
                    offsets = [0, 3, 6, 8, 10]
                    return map(statistics.mean,
                        [coll[offsets[i-1]:offsets[i]]
                         for i in range(1, len(offsets))])            

        df = pd.DataFrame({
            "Release" : [f"Android {v}" for v in versions],
            "Prot. Binaries": partition_by_release(pbins_percent),
            "Prot. Libraries" : partition_by_release(plibs_percent),
            "PA prot. Binaries" : partition_by_release(papbins_percent),
            "PA prot. Libraries" : partition_by_release(paplibs_percent)}).melt(id_vars='Release', var_name="Protection Mechanism", value_name="Coverage Percentage")

        # apparently it is not enough to do this earlier?
        mpl.rcParams["font.family"] = "serif"
        
        ax = sns.barplot(data=df, x='Release', y="Coverage Percentage", hue='Protection Mechanism', palette=sns.color_palette("muted"))

        # Make sure all labels are in float format (to enforce uniform graph height)
        ax.yaxis.set_major_formatter(FormatStrFormatter('%.2f'))
        
        if export_mode:
            # set same scale for different images next to each other
            if target_series in ["umi", "s20"]:
                plt.ylim(0, 45)

            # apparently it is not enough to do this earlier?
            mpl.rcParams["font.family"] = "serif"
            plt.savefig(f"gfx/{filename}", backend="pgf", bbox_inches='tight', pad_inches = 0)
            plt.clf()
        else:
            plt.show()


if __name__ == "__main__":
    # Setup export parameters
    mpl.use("pgf")
    mpl.rcParams.update({
        "pgf.texsystem": "pdflatex",
        'font.family': 'serif',
        'text.usetex': True,
        'pgf.rcfonts': True,
    })

    # load all cfidata
    cfidata = {}
    for path, dirs, filenames in os.walk("../../asa_results/"):
        for filename in filenames:
            if not filename.endswith(".pkl") or "/old" in path:
                continue

            p = join(path, filename)
            with open(p, "rb") as f:
                cfidata[filename] = list(pickle.load(f).values())
    # print(cfidata.keys())

    # generate combined scatter plot (filter out all the "timeseries" data)
    include_list = {"gsi_14.pkl", "fuxi.pkl", "panther.pkl", "r8.pkl", "s22.pkl", "v25.pkl", "V14.0.2.0.TJBEUXM.pkl", "SM-G980F_BTB_G980FXXSIHWGA.pkl"}
    cfidata_list = [([c for c in v if c.has_cfi_check and "ko" not in c.trait], k)
                     for k, v in cfidata.items() if k in include_list]
    eqclass_sizes_scatter_plot_combined(cfidata_list)

    # generate dev_over_time plot
    def sort_s20(x):
        k, _ = x
        if "SM-" in k:
            return -s20_prec.index(k.replace(".pkl", "").replace("SM-G980F_BTB_", ""))
        else:
            return 1000

    def sort_m10(x):
        # sort by int values
        k, _ = x
        if "BEUXM" in k:
            parts = k.split(".")
            return [parts[0], *map(int, parts[1:4])]
        else:
            # these are filtered out anyway later
            return ["1000"] 

    s20_data = [v for k,v in sorted(cfidata.items(), key=sort_s20)
                if "SM-G980F" in k]

    m10_data = [v for k,v in sorted(cfidata.items(), key=sort_m10)
                if "BEUXM" in k]

    gsi_data = [v for k,v in sorted(cfidata.items())
                if "gsi" in k]

    dev_over_time_bars(s20_data, 's20', True, "dev_over_time_s20.pgf")
    dev_over_time_bars(gsi_data, 'gsi', True, "dev_over_time_gsi.pgf")
    dev_over_time_bars(m10_data, 'umi', True, "dev_over_time_m10.pgf")

from enum_win import WCFGInfo
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib as mpl
from collections import Counter
from pandas import DataFrame
from win_stats import load_data


def eqclass_sizes_scatter_plot(wcfginfo, xl=None, filename="eqclass_sizes_win.pgf"):
    """Plots the equivalence class sizes by number of occurrences as scatter plot.
    xl is the xlim value if not None, useful to exclude large outliers."""

    eqclass_sizes = Counter(sum([list(map(len, inf.type_hashes.values())) for inf in wcfginfo], start=[]))
    print(len(eqclass_sizes))

    with sns.axes_style("ticks"):

        df = DataFrame({"x": list(eqclass_sizes.keys()), "y": list(eqclass_sizes.values())})

        # print("eqclass size average:",
        #       sum([size * occ for size,occ in eqclass_sizes.items()]) / sum(eqclass_sizes.values()))

        print(df)
        jp = sns.relplot(df, x="x", y="y",
                         height=5,
                         aspect=1.2,
                         s=20, # size of dots
                         kind="scatter",
                         color="#2166ac")
        axes = jp.figure.axes
        # jp.legend.remove()
        # plt.legend(title="Firmware Image", loc="upper right", bbox_to_anchor=[0.48, 0.48, 0.5, 0.5], facecolor="white", framealpha=1, fontsize=8, title_fontsize=9)
        jp.set_axis_labels(f'Equivalence Class Size (log scale)', 'Number of occurrences (log scale)')
        plt.yscale("log")
        plt.xscale("log")
        plt.grid()

        jp.savefig(f"gfx/{filename}", bbox_inches='tight', pad_inches = 0, dpi=500)

with open("win_analysis.pkl", "rb") as f:
    _, data = load_data()

    # Setup export parameters
    mpl.use("pgf")
    mpl.rcParams.update({
        "pgf.texsystem": "pdflatex",
        'font.family': 'serif',
        'text.usetex': True,
        'pgf.rcfonts': False,
    })

    eqclass_sizes_scatter_plot([i for i in data if i.xfg])

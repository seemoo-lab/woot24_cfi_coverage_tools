#!/usr/bin/python3
"""
Script to calculate some statistics of PA usage.
Consumes pa_files.txt created by running: python3 enum_pa.py > pa_files.txt
"""

pa_instructions = [ "pacda", "pacdb", "pacdza", "pacdzb", "pacga", "pacia1716", "pacia", "paciasp", "paciaz", "pacib1716", "pacib", "pacibsp", "pacibz", "paciza", "pacizb", "autda", "autdb", "autdza", "autdzb", "autia1716", "autia", "autiasp", "autiaz", "autib1716", "autib", "autibsp", "autibz", "autiza", "autizb", "xpaclri", "xpaci", "xpacd", "retaa", "retab", "braa", "brab", "blraa", "blrab", "braaz", "brabz", "blraaz", "blrabz", "eretaa", "eretab", "ldraa", "ldrab"]
pa_instructions = ["'" + ins + "'" for ins in pa_instructions]

# adjust to remove false positives -- remove line below for including all instructions
pa_instructions = ["'pacibsp'", "'autibsp'", "'xpaclri'"]

def find_files_with_ins(lines, ins):
    fs = []
    for l in lines:
        f, i = l.split("--")
        if ins in i:
            fs.append(f)
    return fs

def files_with_ins(ls):
    return len([l for l in ls if any(ins in l for ins in pa_instructions[:2])])

def files_without_ins(ls):
    return len([l for l in ls if not any(ins in l for ins in pa_instructions[:2])])

def are_pacibsp_and_autibsp_paired(ls):
    return all(l for l in ls if pa_instructions[0] in l and pa_instructions[1] in l)

def files_with_xpaclri_but_no_other(lines):
    return [l for l in lines if pa_instructions[2] in l and not
            (pa_instructions[0] in l or pa_instructions[1] in l)]

def ins_frequency(ls):
    from collections import Counter
    cnt = Counter({k: 0 for k in pa_instructions})

    for l in ls:
        for ins in pa_instructions:
            if ins in l:
                cnt[ins] += 1
    for k in list(cnt.keys()):
        if not cnt[k]:
            del cnt[k]
    return cnt

with open("pa_files.txt") as f:
    lines = f.readlines()
    ls = [l.split("--")[-1] for l in lines]

    print(ins_frequency(ls))
    wi = files_with_ins(ls)
    woi = files_without_ins(ls)
    print(f"Files with PA: {wi} vs. {woi} ({wi / (wi + woi) * 100}%)")
    print(f"pacibsp and autibsp paired? {are_pacibsp_and_autibsp_paired(ls)}")
    print(f"Files with only xpaclri: {len(files_with_xpaclri_but_no_other(lines))}")

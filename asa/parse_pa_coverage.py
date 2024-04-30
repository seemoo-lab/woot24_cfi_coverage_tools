from os import listdir

cache = dict()
with open("android_pa_coverage.txt") as f:
    for l in f:
        n, pa = l.strip().split(" -- ")
        pa = eval(pa)

        _, _, vendor, *rest = n.split("/", 3)
        vendor = vendor.replace("_bind", "")        
        cache[n] = pa

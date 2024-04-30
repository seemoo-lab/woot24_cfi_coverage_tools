import rzpipe

def is_rust(path, log):
    """Returns true if the binary at the given path is likely to be a Rust executable by checking its exports."""

    try:
        rz = rzpipe.open(path)
        res = "__rust_alloc\n" in rz.cmd("is~__rust_alloc")
        rz.quit()
        return res
    except Exception as e:
        log.warning(f"Rust analysis encountered exception {e} for path {path}")

#!/bin/bash

all_images=$(fdfind "^boot.img")

while IFS= read -r line; do
    echo
    echo
    echo
    echo
    echo "... $line ..."
    ./extract-ikconfig "$line" | rg -i "cfi"
    python3 extract_bootimg.py --boot_img "$line"

    cd out/
    type=$(file "out/kernel")
    
    case $type in
        gzip)
            mv kernel kernel.gz
            gunzip kernel.gz
            ;;
        LZ4)
            mv kernel kernel.lz4
            lz4 kernel.lz4
            ;;
    esac
    strings kernel | rg -i "cfi"
    cd ../
    rm -r out/
done <<< "$all_images"

#!/bin/bash

for img in s20_images/*.zip; do
    echo
    echo
    echo
    echo
    echo "Img:" "$img"

    ap_file=$(unzip -l "$img" | rg AP |  tr -s ' ' | cut -d " " -f 4)
    # echo "ap_file" "$ap_file"
    unzip -j "$img" "$ap_file" -d /tmp/
    tar -C /tmp/ -xf "/tmp/$ap_file" "boot.img.lz4"
    lz4 /tmp/boot.img.lz4 /tmp/boot.img
    ./extract-ikconfig "/tmp/boot.img" | rg -i "cfi"
    python3 extract_bootimg.py --boot_img "/tmp/boot.img" --out /tmp
    type=$(file "/tmp/kernel")
    
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
    strings /tmp/kernel | rg -i "cfi"
done

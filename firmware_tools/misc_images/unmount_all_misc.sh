#!/bin/bash

mountpoints=("gsi_bind" "gsi"
             "panther_bind" "panther"
             "s22_bind" "s22"
             "fuxi_bind" "fuxi"
             "v25_bind" "v25"
             "r8_bind" "r8")

for mp in "${mountpoints[@]}";
do
    echo "unmount /mnt/$mp"
    sudo umount -R "/mnt/$mp"
done

# clear folders
folders=("gsi" "gsi_bind" "panther" "panther_bind" "s22" "s22_bind" "fuxi" "fuxi_bind" "v25" "v25_bind" "r8" "r8_bind")
for f in "${folders[@]}";
do
    sudo rm -r "/mnt/$f"
done

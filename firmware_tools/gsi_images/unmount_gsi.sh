#!/bin/bash

base=("gsi_10" "gsi_11" "gsi_12" "gsi_13" "gsi_14")
for i in "${base[@]}";
do
    echo "$i"
    sudo umount "/mnt/${i}_bind"
    sudo umount "/mnt/$i"
    sudo rm -r "/mnt/$i"
done


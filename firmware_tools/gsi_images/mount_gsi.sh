#!/bin/bash

base=("gsi_10" "gsi_11" "gsi_12" "gsi_13" "gsi_14")
for i in "${base[@]}";
do
    echo "$i"
    sudo mkdir -p "/mnt/$i"
    sudo mkdir -p "/mnt/${i}_bind"
    sudo mount -o loop,ro "$i/system.img" "/mnt/$i"
    sudo bindfs -p a+rwx --multithreaded -u $USER -g $USER "/mnt/$i" "/mnt/${i}_bind" # make it readable by the user
done

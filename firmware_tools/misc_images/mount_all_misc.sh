#!/bin/bash

# GSI Image
sudo mkdir -p /mnt/gsi /mnt/gsi_bind/
sudo mount -o loop,ro ./gsi_gms_arm64-exp-T3B1.230224.005-9723149-85eb7259/system.img /mnt/gsi/
sudo bindfs -p a+rwx --multithreaded -u $USER -g $USER /mnt/gsi /mnt/gsi_bind/ # make it readable by the user

# Google Panther
sudo mkdir -p /mnt/panther /mnt/panther_bind /mnt/panther/vendor_dlkm/
dir="./misc_firmware/panther-t3b2.230316.003-factory-c65097bc/panther-t3b2.230316.003/image-panther-t3b2.230316.003"
sudo mount -o loop,ro "$dir/system.img" /mnt/panther/
sudo mount -o loop,ro "$dir/product.img" /mnt/panther/product/
sudo mount -o loop,ro "$dir/system_dlkm.img" /mnt/panther/system_dlkm/
sudo mount -o loop,ro "$dir/system_ext.img" /mnt/panther/system_ext/
# sudo mount -o loop,ro "$dir/system_other.img" /mnt/panther/system/ # this is a bad idea, shadows original system folder
sudo mount -o loop,ro "$dir/vendor_dlkm.img" /mnt/panther/vendor_dlkm/
sudo mount -o loop,ro "$dir/vendor.img" /mnt/panther/vendor/
sudo bindfs -p a+rwx --multithreaded -u $USER -g $USER /mnt/panther /mnt/panther_bind/ # make it readable by the user

# Samsung
sudo mkdir -p /mnt/s22 /mnt/s22_bind
dir="./misc_firmware/S901BXXU3CWAI_S901BOXM3CWAI_EUX/unpacked"
sudo mount -o loop,ro "$dir/system.img"      /mnt/s22/
sudo mount -o loop,ro "$dir/cache.img"       /mnt/s22/cache
sudo mount -o loop,ro "$dir/odm.img"         /mnt/s22/odm
sudo mount -o loop,ro "$dir/omr.img"         /mnt/s22/omr
sudo mount -o loop,ro "$dir/optics.img"      /mnt/s22/optics
sudo mount -o loop,ro "$dir/prism.img"       /mnt/s22/prism
sudo mount -o loop,ro "$dir/product.img"     /mnt/s22/product
sudo mount -o loop,ro "$dir/userdata.img"    /mnt/s22/data
sudo mount -o loop,ro "$dir/vendor.img"      /mnt/s22/vendor
sudo mount -o loop,ro "$dir/vendor_dlkm.img" /mnt/s22/vendor_dlkm
sudo bindfs -p a+rwx --multithreaded -u $USER -g $USER /mnt/s22 /mnt/s22_bind/ # make it readable by the user

# Xiamoi
sudo mkdir -p /mnt/fuxi /mnt/fuxi_bind
dir="./misc_firmware/fuxi_eea_global_images_V14.0.15.0.TMCEUXM_13.0/images/unpacked"
sudo mount -t erofs -o loop "$dir/system_a.img"      /mnt/fuxi
sudo mount -t erofs -o loop "$dir/mi_ext_a.img"      /mnt/fuxi/mi_ext
sudo mount -t erofs -o loop "$dir/odm_a.img"         /mnt/fuxi/odm
sudo mount -t erofs -o loop "$dir/product_a.img"     /mnt/fuxi/product
sudo mount -t erofs -o loop,ro "$dir/system_a.img"      /mnt/fuxi/system
sudo mount -t erofs -o loop "$dir/system_ext_a.img"  /mnt/fuxi/system_ext
sudo mount -t erofs -o loop "$dir/vendor_a.img"      /mnt/fuxi/vendor
sudo mount -t erofs -o loop "$dir/vendor_dlkm_a.img" /mnt/fuxi/vendor_dlkm
sudo mount -t erofs -o loop "$dir/cust.img"          /mnt/fuxi/cust
sudo mount -o loop "$dir/userdata.img"               /mnt/fuxi/data
sudo bindfs -p a+rwx --multithreaded -u $USER -g $USER /mnt/fuxi /mnt/fuxi_bind/ # make it readable by the user

# Vivo V25
sudo mkdir -p /mnt/v25 /mnt/v25_bind
dir="./misc_firmware/PD2215F_EX_A_13.1.13.5.W30.V000L1-update-full_1672816959/merged/"
sudo mount -o loop,ro "$dir/system.new.dat"   /mnt/v25/
sudo mount -o loop,ro "$dir/vendor.new.dat"   /mnt/v25/vendor
sudo mount -o loop,ro "$dir/product.img"      /mnt/v25/product
sudo mount -o loop,ro "$dir/dyn.img"          /mnt/v25/system/dyn
sudo bindfs -p a+rwx --multithreaded -u $USER -g $USER /mnt/v25 /mnt/v25_bind/ # make it readable by the user

# Oppo Reno 8
sudo mkdir -p /mnt/r8 /mnt/r8_bind
dir="./misc_firmware/CPH2359_MT6893_EX_11_A.18_221121/CPH2359_MT6893_EX_11_A.18_221121/Firmware/IMAGES/unpacked/"
sudo mount -o loop,ro "$dir/system.img"          /mnt/r8/
sudo mount -o loop,ro "$dir/odm.img"             /mnt/r8/odm/
sudo mount -o loop,ro "$dir/system_ext.img"      /mnt/r8/system_ext/
sudo mount -o loop,ro "$dir/vendor.img"          /mnt/r8/vendor/
sudo mount -o loop,ro "$dir/product.img"         /mnt/r8/product/
# not really relevant - not that large, and not part of the system.img
# sudo mount -o loop,ro "$dir/oplusreserve2.img" /mnt/r8/oplusreserve2/
sudo mount -o loop,ro "$dir/userdata.img"        /mnt/r8/data/
sudo mount -o loop,ro "$dir/my_bigball.img"      /mnt/r8/my_bigball/
sudo mount -o loop,ro "$dir/my_stock.img"        /mnt/r8/my_stock/
sudo mount -o loop,ro "$dir/my_product.img"      /mnt/r8/my_product/
sudo mount -o loop,ro "$dir/my_heytap.img"       /mnt/r8/my_heytap/
sudo mount -o loop,ro "$dir/my_preload.img"      /mnt/r8/my_preload/
sudo mount -o loop,ro "$dir/my_region.img"       /mnt/r8/my_region/
sudo bindfs -p a+rwx --multithreaded -u $USER -g $USER /mnt/r8 /mnt/r8_bind/ # make it readable by the user

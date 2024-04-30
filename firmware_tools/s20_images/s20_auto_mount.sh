#!/bin/bash

firmware_list=("SM-G980F_BTB_G980FXXS8DUE4_fac" "SM-G980F_BTB_G980FXXSCDUJ5_fac" "SM-G980F_BTB_G980FXXSCEUL7_fac" "SM-G980F_BTB_G980FXXSFFVIB_fac" "SM-G980F_BTB_G980FXXSFHWB1_fac" "SM-G980F_BTB_G980FXXSIHWGA_fac" "SM-G980F_BTB_G980FXXU1ATBM_fac" "SM-G980F_BTB_G980FXXU2ATE6_fac" "SM-G980F_BTB_G980FXXU5BTJ3_fac" "SM-G980F_BTB_G980FXXU5CTKG_fac" "SM-G980F_BTB_G980FXXUEFVDB_fac" "SM-G980F_BTB_G980FXXUFGVJE_fac")

case $1 in
    mount)
        for i in "${firmware_list[@]}"; do
            # extract images if not existing
            if [ ! -d "$i" ]; then
	        mkdir "$i"
                unzip "$i.zip" -d "$i"

                for t in "$i"/*.tar.md5; do
                    [ -f "$t" ] || break
                    tar -C "$i" -xvf "$t"
                done
                lz4 -m "$i"/*.img.lz4

                # unsparse images
                sparse_img=("cache.img" "omr.img" "optics.img" "prism.img" "super.img" "userdata.img")
                for s in "${sparse_img[@]}"; do
                    mv "$i/$s" "$i/$s.packed"
                    ../android-simg2img/simg2img "$i/$s.packed" "$i/$s"
                done

                # unpack super image
                ../lpunpack "$i/super.img" "$i"
            fi
            
            # start mounting images
            images=("system.img" "cache.img" "odm.img" "omr.img" "optics.img" "prism.img" "product.img" "userdata.img" "vendor.img")
            sudo mkdir -p "/mnt/$i" "/mnt/${i}_bind/"

            # for img in "${images[@]}"; do
            #     if [ ! -d "/mnt/$i/$mp" ]; then
            #         echo "Making folder" "/mnt/$i/$mp"
            #         sudo mkdir -p "/mnt/$i/$mp"
            #     fi
            # done

            for img in "${images[@]}"; do
                # get mounting point
                mp=$(sudo blkid "$i/$img" | cut -d " " -f 2 | cut -d "\"" -f 2)
                
                echo "Mounting" "$i/$img" "to" "/mnt/$i/$mp"
                sudo mount -o loop,ro "$i/$img" "/mnt/$i/$mp"
            done
            sudo bindfs -p a+rwx --multithreaded -u "$USER" -g "$USER" "/mnt/$i" "/mnt/${i}_bind/" # make it readable by the user
        done
        ;;
    
    unmount)
        for i in "${firmware_list[@]}"; do
            # reversed list from above without system.img
            images=("vendor.img" "userdata.img" "product.img" "prism.img" "optics.img" "omr.img" "odm.img" "cache.img")
            for img in "${images[@]}"; do
                # get mounting point
                mp=$(sudo blkid "$i/$img" | cut -d " " -f 2 | cut -d "\"" -f 2)
                # echo trying to unmount "/mnt/$i/$mp"
                sudo umount "/mnt/$i/$mp"
            done
            
            sudo umount "/mnt/${i}_bind"
            sudo umount "/mnt/${i}"

            sudo rm -r "/mnt/${i}_bind"
            sudo rm -r "/mnt/${i}"
        done
        ;;
    *)
        echo "Argument must be either mount or unmount."
      ;;
esac

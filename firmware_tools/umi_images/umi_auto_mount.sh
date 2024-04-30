#!/bin/bash

firmware_list=("umi_eea_global_images_V11.0.9.0.QJBEUXM_20200321.0000.00_10.0_eea" "umi_eea_global_images_V11.0.18.0.QJBEUXM_20200715.0000.00_10.0_eea" "umi_eea_global_images_V12.0.6.0.QJBEUXM_20201020.0000.00_10.0_eea" "umi_eea_global_images_V12.2.4.0.RJBEUXM_20210110.0000.00_11.0_eea" "umi_eea_global_images_V12.5.2.0.RJBEUXM_20210707.0000.00_11.0_eea" "umi_eea_global_images_V12.5.8.0.RJBEUXM_20220120.0000.00_11.0_eea" "umi_eea_global_images_V13.0.4.0.SJBEUXM_20220420.0000.00_12.0_eea" "umi_eea_global_images_V13.0.10.0.SJBEUXM_20230112.0000.00_12.0_eea" "umi_eea_global_images_V14.0.1.0.TJBEUXM_20230403.0000.00_13.0_eea" "umi_eea_global_images_V14.0.2.0.TJBEUXM_20230517.0000.00_13.0_eea")

case $1 in
    mount)
        for i in "${firmware_list[@]}"; do
            # extract images if not existing
            if [ ! -d "$i" ]; then
                # extract image
                tar -xvf "$i.tgz"
                
                # unsparse images
                sparse_img=("cache.img" "cust.img" "metadata.img" "super.img" "userdata.img")
                for s in "${sparse_img[@]}"; do
                    mv "$i/images/$s" "$i/images/$s.packed"
                    ../android-simg2img/simg2img "$i/images/$s.packed" "$i/images/$s"
                done

                # unpack super image
                ../lpunpack "$i/images/super.img" "$i/images"
            fi

            # start mounting images
            images=("system.img" "cache.img" "cust.img" "metadata.img" "odm.img" "product.img" "vendor.img" "userdata.img")
            sudo mkdir -p "/mnt/$i" "/mnt/${i}_bind/"

            for img in "${images[@]}"; do
                has_label=$(sudo blkid "$i/images/$img" | rg LABEL)

                if [ "$has_label" = "" ]; then
                    # some images have no label (e.g., metadata)
                    echo "Info: $img has no label. Using image name instead."
                    mp=$(basename "$img" ".img")
                else
                    # get mounting point
                    mp=$(sudo blkid "$i/images/$img" | cut -d " " -f 2 | cut -d "\"" -f 2)
                fi
                
                echo "Mounting" "$i/images/$img" "to" "/mnt/$i/$mp"
                sudo mount -o loop,ro "$i/images/$img" "/mnt/$i/$mp"
            done
            sudo bindfs -p a+rwx --multithreaded -u "$USER" -g "$USER" "/mnt/$i" "/mnt/${i}_bind/" # make it readable by the user
        done
        ;;
    
    unmount)
        for i in "${firmware_list[@]}"; do
            # reversed list from above without system.img
            images=("userdata.img" "vendor.img" "product.img" "odm.img" "metadata.img" "cust.img" "cache.img")
            for img in "${images[@]}"; do
                has_label=$(sudo blkid "$i/images/$img" | rg LABEL)
                if [ "$has_label" = "" ]; then
                    # some images have no label (e.g., metadata)
                    echo "Info: $img has no label. Using image name instead."
                    mp=$(basename "$img" ".img")
                else
                    # get mounting point
                    mp=$(sudo blkid "$i/images/$img" | cut -d " " -f 2 | cut -d "\"" -f 2)
                fi
                
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

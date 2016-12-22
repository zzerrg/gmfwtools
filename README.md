# gmfwtools
GM8136/GM8135S firmware tools

At this moment this repository contains only one tool - ``gm_app_fw.py`` to work with "APPLICATION"
partition of the firmware of IP/Web survilance cameras based on Gwell Media SoCs.

Full firmware image includes nsboot, u-boot, kernel, rootfs, app and rom partitions.
I mean "full firmware" is a full image of SPI flash 16MB or 8MB in size.

"APP" firmware is  JFFS2 filesystem image max 4MB in size with 32 bytes header.
The header contains some useful information like MD5+DES signature of the JFFS2 filesystem,
firmware version, UNIX timestamp of the image and some supplementary attributes.

``gm_app_fw.py`` tools support VERIFY, UNPACK, MOUNT, PACK actions on the firmware.

## Verify signature of the 'npcupg' firmware

At this moment ``gm_app_fw.py`` contains DES key to check signature of FW version 14.

    $ ./gm_app_fw.py -f ../npcupg_14.00.00.75.bin -v
    fw_ver : 14.00.00.75
    fs size: 3126713
    csum   : 784b58459a68c5d53aebc572ab39e558
    sig ok : True

On other versions it fails:

    $ ./gm_app_fw.py -f ../npcupg_gm_21.00.00.21\(4464\).bin -v
    fw_ver : 21.00.00.21
    fs size: 2328029
    csum   : 01010b1e49e515f32831f85bf0315c36
    sig ok : False

    $ ./gm_app_fw.py -f ../npcupg_13.00.00.99\(4486\)_HiSilicon.bin -v
    fw_ver : 13.00.00.99
    fs size: 3047483
    csum   : d3cf90f06004c787ddbcf41b5f4e27d9
    sig ok : False


FW ver 19 contains "APP" image at offset 0x40000

    $ ./gm_app_fw.py -f ../npcupg_gm_small_wireless_19.05.00.19.bin.rom -O 0x40000 -v
    fw_ver : 19.05.00.19
    fs size: 2404545
    csum   : 0d6f3a2c3ec1ef3d2be78707357d37ba
    sig ok : False


Also it recognized header of FW version 13, 19, 21 but can't verify the
signature nor pack and sign modified JFFS2 image.

## Unpack 'npcupg' firmware

Unpack action extracts JFFS2 image of the "APP" fw filesystem:

    $ ./gm_app_fw.py -f ./npcupg_14.00.00.75.bin -u
    Write APP JFFS image into app_14.00.00.75.jffs
    Write APP EXEC image into upg_14.00.00.75.elf

    $ file app_14.00.00.75.jffs
    app_14.00.00.75.jffs: Linux jffs2 filesystem data little endian

## Mount 'npcupg' firmware

Mount action is similar to unpack -- it extracts JFFS2 image.
Instead it loads *mtdram* and *mtdblock* kernel modules,
writes JFFS2 image into ``/dev/mtdblock0`` device and mounts it:

    # ./gm_app_fw.py -f ./npcupg_14.00.00.75.bin -m
    modprobe mtdram total_size=16384 erase_size=64
    modprobe mtdblock
    mount -t jffs2 /dev/mtdblock0 /mnt/fw_app

    # ls /mnt/fw_app/ |head -5
    dhcp.script
    gwellipc
    img
    language
    minihttpd.conf

    # df -h /mnt/fw_app/
    Filesystem      Size  Used Avail Use% Mounted on
    /dev/mtdblock0   16M  3.5M   13M  22% /mnt/fw_app

*Please note*: this command requires root privileges on Linux.

## Pack and sign 'npcupg' firmware from JFFS2 image

    $ ./gm_app_fw.py -f npcupg_gm_75a.bin -p -j npc-v75-1.jffs2.img -e upg_14.00.00.75.elf -V 14.0.0.76
    Pack npc-v75-1.jffs2.img + upg_14.00.00.75.elf into FW image ...
    Build FW version 14.0.0.76
    Calculated fw_sig: 42047b324f94f04cbf078a81e61b7cb6

    $ ./gm_app_fw.py -f npcupg_gm_75a.bin -v
    fw_ver : 14.00.00.76
    jffs sz: 3323528
    exec sz: 6945
    csum   : 42047b324f94f04cbf078a81e61b7cb6
    sig ok : True


## Firmware versions

1. GM8136/GM8135S SoC family  uses firmware version 14
2. HiSilicon SoC family uses firmware version 13
3. ??? SoC family uses firmware version 21
4. There is firmware version 19, which has "application" firmware partition on offset 0x40000


## Feedback

4pda.ru topic where GM8136 based WiFi cameras are discuessed:  https://goo.gl/l1OFps


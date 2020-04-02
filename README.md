# Building

## OpenWrt components
```
cd openwrt
cp config-elemental-3.18 .config
make oldconfig
make -j1 BOARD=elemental-3.18 OPENWRT_EXTRA_BOARD_SUFFIX=_3.18
```

## Kernel

If you want to rebuild the Meraki kernel exactly as shipped, use the branch `meraki_stock`

Using `master` will result in a kernel that expects a different partition layout, suitable for booting entirely from NOR.

The example below uses the OpenWrt cross compilation environment. If you already have a mips cross compiler installed, modify the CROSS_COMPILE path accordingly.

```
cd linux-3.18
make CROSS_COMPILE=../openwrt/staging_dir_mipsel_nofpu_3.18/bin/mipsel-linux-musl- ARCH=mips msxx_defconfig
make CROSS_COMPILE=../openwrt/staging_dir_mipsel_nofpu_3.18/bin/mipsel-linux-musl- ARCH=mips prepare
make CROSS_COMPILE=../openwrt/staging_dir_mipsel_nofpu_3.18/bin/mipsel-linux-musl- ARCH=mips vmlinux
../openwrt/staging_dir_mipsel_nofpu_3.18/bin/mipsel-linux-musl-objcopy -O binary -S vmlinux vmlinux.bin
```

Use `vmlinux.bin` with build scripts to generate a flashable image.

`readelf -h vmlinux` will provide you the correct kernel entry point address to put in the header.

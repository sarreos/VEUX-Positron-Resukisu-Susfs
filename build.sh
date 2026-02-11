# bbg
wget -O- https://github.com/vc-teahouse/Baseband-guard/raw/main/setup.sh | bash
sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /baseband_guard/! s/selinux/selinux,baseband_guard/ } }' security/Kconfig
# resukisu
curl -LSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/main/kernel/setup.sh" | bash
bash backport_patches.sh
bash backport_selinux_patches.sh
bash susfs_inline_hook_patches.sh
DEFCONFIG="veux_defconfig"
make O=out ARCH=arm64 $DEFCONFIG
make -j$(nproc --all) O=out \
    ARCH=arm64 \
    LLVM=1 \
    LLVM_IAS=1 \
    CLANG_TRIPLE=aarch64-linux-gnu- \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CROSS_COMPILE_ARM32=arm-linux-gnueabi- \

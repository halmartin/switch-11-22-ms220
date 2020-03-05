include $(TOPDIR)/rules.mk

ifeq ($(BR2_LIBC_UCLIBC),y)
#############################################################
#
# uClibc (the C library)
#
#############################################################

#ifeq ($(BR2_UCLIBC_VERSION_SNAPSHOT),y)
# Be aware that this changes daily....
#UCLIBC_DIR:=$(TOOL_BUILD_DIR)/uClibc
#UCLIBC_DEV_DIR:=$(TOOL_BUILD_DIR)/uClibc_dev
#UCLIBC_SOURCE:=uClibc-$(strip $(subst ",, $(BR2_USE_UCLIBC_SNAPSHOT))).tar.bz2
#"
#UCLIBC_SITE:=http://www.uclibc.org/downloads/snapshots
#UCLIBC_VER:=PKG_VERSION:=0.${shell date +"%G%m%d"}
#else
UCLIBC_VER:=$(subst ",,$(BR2_UCLIBC_VERSION))
ifeq ($(BR2_UCLIBC_VERSION),"1.0.17") # "
UCLIBC_NAME:=uClibc-ng
UCLIBC_MD5:=996385659b564c341323c1febeaa37b9
else
UCLIBC_NAME:=uClibc
UCLIBC_MD5:=a338aaffc56f0f5040e6d9fa8a12eda1
endif
UCLIBC_DIR:=$(TOOL_BUILD_DIR)/$(UCLIBC_NAME)-$(UCLIBC_VER)
UCLIBC_SOURCE:=$(UCLIBC_NAME)-$(UCLIBC_VER).tar.bz2
#UCLIBC_SITE:=http://www.uclibc.org/downloads
UCLIBC_SITE:=https://dl.meraki.net/
#endif

ifeq ($(BR2_LINUX_VERSION),"2.6.16.16")
UCLIBC_TARGET_ARCH:=$(shell echo $(ARCH) | sed -e s'/-.*//' \
		-e 's/i.86/i386/' \
		-e 's/sparc.*/sparc/' \
		-e 's/arm.*/arm/g' \
		-e 's/m68k.*/m68k/' \
		-e 's/ppc/powerpc/g' \
		-e 's/v850.*/v850/g' \
		-e 's/sh64/sh/' \
		-e 's/sh[234].*/sh/' \
		-e 's/mips.*/mips/' \
		-e 's/mipsel.*/mips/' \
		-e 's/cris.*/cris/' \
		-e 's/x86_64/x86/' \
)
else
UCLIBC_TARGET_ARCH:=$(shell echo $(ARCH) | sed -e s'/-.*//' \
		-e 's/i.86/x86/' \
		-e 's/sparc.*/sparc/' \
		-e 's/arm.*/arm/g' \
		-e 's/m68k.*/m68k/' \
		-e 's/ppc/powerpc/g' \
		-e 's/v850.*/v850/g' \
		-e 's/sh64/sh/' \
		-e 's/sh[234].*/sh/' \
		-e 's/mips.*/mips/' \
		-e 's/mipsel.*/mips/' \
		-e 's/cris.*/cris/' \
		-e 's/x86_64/x86/' \
)
endif

ifeq ($(BR2_POWERPC_E500),y)
UCLIBC_CONFIG_ARCH := powerpc_e500
else ifeq ($(BR2_WIRED_POWERPC),y)
UCLIBC_CONFIG_ARCH := wired_powerpc
else
UCLIBC_CONFIG_ARCH := $(ARCH)
endif

$(DL_DIR)/$(UCLIBC_SOURCE):
	mkdir -p $(DL_DIR)
	$(SCRIPT_DIR)/download.pl $(DL_DIR) $(UCLIBC_SOURCE) $(UCLIBC_MD5) $(UCLIBC_SITE)

$(UCLIBC_DIR)/.unpacked: $(DL_DIR)/$(UCLIBC_SOURCE)
	mkdir -p $(TOOL_BUILD_DIR)
	bzcat $(DL_DIR)/$(UCLIBC_SOURCE) | tar -C $(TOOL_BUILD_DIR) $(TAR_OPTIONS) -
	$(PATCH) $(UCLIBC_DIR) ./patches/$(UCLIBC_VER)
	touch $(UCLIBC_DIR)/.unpacked

$(UCLIBC_DIR)/.configured: $(UCLIBC_DIR)/.unpacked
	$(SED) 's,^CROSS=.*,CROSS=$(TARGET_CROSS),g' $(UCLIBC_DIR)/Rules.mak
	$(CP) ./configs/$(UCLIBC_VER)/config.$(UCLIBC_CONFIG_ARCH) $(UCLIBC_DIR)/.config
	$(SED) 's,^KERNEL_SOURCE=.*,KERNEL_SOURCE=\"$(LINUX_HEADERS_DIR)/include\",g' \
		$(UCLIBC_DIR)/.config
	$(SED) 's,^KERNEL_HEADERS=.*,KERNEL_HEADERS=\"$(LINUX_HEADERS_DIR)/include\",g' \
		$(UCLIBC_DIR)/.config
	$(SED) 's,^KERNEL_HEADERS=.*,KERNEL_HEADERS=\"$(LINUX_HEADERS_DIR)/include\",g' \
        -e 's,^.*UCLIBC_HAS_LFS.*,UCLIBC_HAS_LFS=$(if $(BR2_LARGEFILE),y,n),g' \
        -e 's,^.*CONFIG_ARM_EABI.*,CONFIG_ARM_EABI=$(if $(CONFIG_EABI_SUPPORT),y,n),g' \
        -e 's,^.*CONFIG_ARM_OABI.*,CONFIG_ARM_OABI=$(if $(CONFIG_EABI_SUPPORT),n,y),g' \
	    -e 's,.*UCLIBC_HAS_WCHAR.*,UCLIBC_HAS_WCHAR=y,g' \
        $(UCLIBC_DIR)/.config
ifeq ($(BR2_SOFT_FLOAT),y)
	$(SED) 's,^.*UCLIBC_HAS_FPU.*,# UCLIBC_HAS_FPU is not set,g' -e 's,^.*UCLIBC_HAS_FLOATS.*,UCLIBC_HAS_FLOATS=y\nUCLIBC_HAS_SOFT_FLOAT=y,g' $(UCLIBC_DIR)/.config
endif
	mkdir -p $(STAGING_DIR)/include/
	cp -pLR $(TOOL_BUILD_DIR)/linux/include/asm $(STAGING_DIR)/include/ ;
	-cp -pLR $(TOOL_BUILD_DIR)/linux/include/asm-$(UCLIBC_TARGET_ARCH) $(STAGING_DIR)/include/ ;
	cp -pLR $(TOOL_BUILD_DIR)/linux/include/asm-generic $(STAGING_DIR)/include/ ;
	cp -pLR $(TOOL_BUILD_DIR)/linux/include/linux $(STAGING_DIR)/include/ ;
	cp -pLR $(TOOL_BUILD_DIR)/linux/include/asm $(UCLIBC_DIR)/include/ ;
	-cp -pLR $(TOOL_BUILD_DIR)/linux/include/asm-$(UCLIBC_TARGET_ARCH) $(UCLIBC_DIR)/include/ ;
	cp -pLR $(TOOL_BUILD_DIR)/linux/include/asm-generic $(UCLIBC_DIR)/include/ ;
	cp -pLR $(TOOL_BUILD_DIR)/linux/include/linux $(UCLIBC_DIR)/include/ ;
ifeq ($(BR2_LINUX_VERSION),"2.6.32")
	cp -pLR $(TOOL_BUILD_DIR)/linux/include/trace $(UCLIBC_DIR)/include/ ;
endif
	touch $(UCLIBC_DIR)/.configured

$(UCLIBC_DIR)/lib/libc.a: $(UCLIBC_DIR)/.configured $(LIBFLOAT_TARGET)
	$(MAKE1) -C $(UCLIBC_DIR) \
		PREFIX= \
		DEVEL_PREFIX=/ \
		RUNTIME_PREFIX=/ \
		HOSTCC="$(HOSTCC)" \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		CPU_CFLAGS="$(TARGET_CFLAGS)" \
		all
	touch -c $(UCLIBC_DIR)/lib/libc.a

$(STAGING_DIR)/lib/libc.a: $(UCLIBC_DIR)/lib/libc.a
	$(MAKE1) -C $(UCLIBC_DIR) \
		PREFIX=$(STAGING_DIR)/ \
		DEVEL_PREFIX=/ \
		RUNTIME_PREFIX=/ \
		CPU_CFLAGS="$(TARGET_CFLAGS)" \
		CC="$(TARGET_CC)" \
		install_runtime install_dev
	$(CP) -a $(LINUX_HEADERS_DIR)/include/mtd $(STAGING_DIR)/include/mtd
	rm -rf $(STAGING_DIR)/lib/libc.so
	ln -s $(STAGING_DIR)/lib/libuClibc-$(UCLIBC_VER).so $(STAGING_DIR)/lib/libc.so
	echo $(UCLIBC_VER) > $(STAGING_DIR)/uclibc_version
	touch -c $(STAGING_DIR)/lib/libc.a

source: $(DL_DIR)/$(UCLIBC_SOURCE)
prepare: $(UCLIBC_DIR)/.configured
compile: $(UCLIBC_DIR)/lib/libc.a
install: $(STAGING_DIR)/lib/libc.a $(UCLIBC_TARGETS)
clean:
	rm -rf $(UCLIBC_DIR)

endif

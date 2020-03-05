include $(TOPDIR)/rules.mk

#############################################################
#
# build binutils for use on the host system
#
#############################################################
BINUTILS_VERSION:=$(strip $(subst ",, $(BR2_BINUTILS_VERSION)))
#"

BINUTILS_SITE:=https://dl.meraki.net/

BINUTILS_STABLE_SITE:=https://dl.meraki.net/

ifeq ($(BINUTILS_VERSION),2.16.1)
	PKG_MD5:=6a9d529efb285071dad10e1f3d2b2967
else ifeq ($(BINUTILS_VERSION),2.19.1)
	PKG_MD5:=09a8c5821a2dfdbb20665bc0bd680791
else ifeq ($(BINUTILS_VERSION),2.21)
	PKG_MD5=c84c5acc9d266f1a7044b51c85a823f5
else ifeq ($(BINUTILS_VERSION),2.24)
	PKG_MD5:=e0f71a7b2ddab0f8612336ac81d9636b
else ifeq ($(BINUTILS_VERSION),2.25)
	PKG_MD5:=d9f3303f802a5b6b0bb73a335ab89d66
else ifeq ($(BINUTILS_VERSION),2.27)
	PKG_MD5:=2869c9bf3e60ee97c74ac2a6bf4e9d68
else ifeq ($(BINUTILS_VERSION),2.29.1)
	PKG_MD5:=9af59a2ca3488823e453bb356fe0f113
endif

ifeq ($(BINUTILS_VERSION),2.16.1)
BINUTILS_SITE:=$(BINUTILS_STABLE_SITE)
endif

BINUTILS_SOURCE:=binutils-$(BINUTILS_VERSION).tar.bz2
BINUTILS_DIR:=$(TOOL_BUILD_DIR)/binutils-$(BINUTILS_VERSION)
BINUTILS_CAT:=bzcat

BINUTILS_DIR1:=$(TOOL_BUILD_DIR)/binutils-$(BINUTILS_VERSION)-build

ifeq ($(BINUTILS_VERSION),2.20.1)
    EXTRA_BINUTILS_OPTIONS:=--with-sysroot
endif

ifeq ($(BINUTILS_VERSION),2.21.1)
    EXTRA_BINUTILS_OPTIONS:=--with-sysroot
endif

ifeq ($(BINUTILS_VERSION),2.24)
    EXTRA_BINUTILS_OPTIONS:=--with-sysroot
endif

ifeq ($(BINUTILS_VERSION),2.25)
    EXTRA_BINUTILS_OPTIONS:=--with-sysroot
endif

ifeq ($(BINUTILS_VERSION),2.27)
    EXTRA_BINUTILS_OPTIONS:=--with-sysroot
endif

ifeq ($(BINUTILS_VERSION),2.27)
    EXTRA_BINUTILS_OPTIONS:=--with-sysroot
endif

ifeq ($(BINUTILS_VERSION),2.29.1)
    EXTRA_BINUTILS_OPTIONS:=--with-sysroot
endif

$(DL_DIR)/$(BINUTILS_SOURCE):
	mkdir -p $(DL_DIR)
	$(SCRIPT_DIR)/download.pl $(DL_DIR) $(BINUTILS_SOURCE) $(PKG_MD5) $(BINUTILS_SITE)

$(BINUTILS_DIR)/.unpacked: $(DL_DIR)/$(BINUTILS_SOURCE)
	mkdir -p $(TOOL_BUILD_DIR)
	$(BINUTILS_CAT) $(DL_DIR)/$(BINUTILS_SOURCE) | tar -C $(TOOL_BUILD_DIR) $(TAR_OPTIONS) -
	touch $(BINUTILS_DIR)/.unpacked

$(BINUTILS_DIR)/.patched: $(BINUTILS_DIR)/.unpacked
	# Apply appropriate binutils patches.
	$(SCRIPT_DIR)/patch-kernel.sh $(BINUTILS_DIR) ./all \*.patch
	$(SCRIPT_DIR)/patch-kernel.sh $(BINUTILS_DIR) ./$(BINUTILS_VERSION) \*.patch
	touch $(BINUTILS_DIR)/.patched

$(BINUTILS_DIR1)/.configured: $(BINUTILS_DIR)/.patched
	mkdir -p $(BINUTILS_DIR1)
	(cd $(BINUTILS_DIR1); \
		CC="$(HOSTCC)" \
		CXX="$(HOSTCXX)" \
		$(BINUTILS_DIR)/configure \
		--prefix=$(HOST_STAGING_DIR) \
		--build=$(GNU_HOST_NAME) \
		--host=$(GNU_HOST_NAME) \
		--target=$(REAL_GNU_TARGET_NAME) \
		--disable-werror \
		$(EXTRA_BINUTILS_OPTIONS) \
		$(DISABLE_NLS) \
		$(MULTILIB) \
		$(SOFT_FLOAT_CONFIG_OPTION) );
	touch $(BINUTILS_DIR1)/.configured

$(BINUTILS_DIR1)/binutils/objdump: $(BINUTILS_DIR1)/.configured
	$(MAKE) -j4 -C $(BINUTILS_DIR1) all

# Make install will put gettext data in staging_dir/share/locale.
# Unfortunatey, it isn't configureable.
$(HOST_STAGING_DIR)/bin/$(REAL_GNU_TARGET_NAME)-ld: $(BINUTILS_DIR1)/binutils/objdump
	$(MAKE) -C $(BINUTILS_DIR1) install


#############################################################
#
# build binutils for use on the target system
#
#############################################################
BINUTILS_DIR2:=$(BUILD_DIR)/binutils-$(BINUTILS_VERSION)-target
$(BINUTILS_DIR2)/.configured: $(BINUTILS_DIR)/.patched
	mkdir -p $(BINUTILS_DIR2)
	(cd $(BINUTILS_DIR2); \
		PATH=$(TARGET_PATH) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CFLAGS_FOR_BUILD="-O2 -g" \
		$(BINUTILS_DIR)/configure \
		--prefix=/usr \
		--exec-prefix=/usr \
		--build=$(GNU_HOST_NAME) \
		--host=$(REAL_GNU_TARGET_NAME) \
		--target=$(REAL_GNU_TARGET_NAME) \
		$(EXTRA_BINUTILS_OPTIONS) \
		$(DISABLE_NLS) \
		$(MULTILIB) \
		$(SOFT_FLOAT_CONFIG_OPTION) );
	touch $(BINUTILS_DIR2)/.configured

$(BINUTILS_DIR2)/binutils/objdump: $(BINUTILS_DIR2)/.configured
	PATH=$(TARGET_PATH) \
	$(MAKE) -j4 -C $(BINUTILS_DIR2) all

source: $(DL_DIR)/$(BINUTILS_SOURCE)
prepare: $(BINUTILS_DIR)/.patched
compile: $(BINUTILS_DIR1)/binutils/objdump
compile-target: $(BINUTILS_DIR2)/binutils/objdump
install: $(HOST_STAGING_DIR)/bin/$(REAL_GNU_TARGET_NAME)-ld
clean:
	rm -f $(HOST_STAGING_DIR)/bin/$(REAL_GNU_TARGET_NAME)*
	rm -rf $(BINUTILS_DIR) $(BINUTILS_DIR1)



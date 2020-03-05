# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=uClibc++
PKG_RELEASE:=1
ifeq ($(BR2_PACKAGE_UCLIBCXX_VERSION_0_1_11),y)
PKG_VERSION:=0.1.11
PKG_MD5SUM:=8a8e0ee8fefef150c08a649fd7da04aa
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tbz2
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
else ifeq ($(BR2_PACKAGE_UCLIBCXX_VERSION_0_2_2),y)
PKG_VERSION:=0.2.2
PKG_MD5SUM:=1ceef3209cca88be8f1bd9de99735954
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
endif

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_CAT:=bzcat


include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,UCLIBCXX,uclibc++,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

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
)

$(PKG_BUILD_DIR)/.configured:
	$(CP) ./files/config.$(UCLIBC_TARGET_ARCH) $(PKG_BUILD_DIR)/.config
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		TOPDIR="$(PKG_BUILD_DIR)/" \
		$(TARGET_CONFIGURE_OPTS) \
		ARCH_CFLAGS="$(TARGET_CFLAGS)" \
		CROSS="$(TARGET_CROSS)" \
		all
	touch $@

$(IPKG_UCLIBCXX):
	install -d -m0755 $(IDIR_UCLIBCXX)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/libuClibc++*.so* $(IDIR_UCLIBCXX)/usr/lib/
	$(STRIP) $(IDIR_UCLIBCXX)/usr/lib/*.so*
	mkdir -p $(PACKAGE_DIR)
	$(IPKG_BUILD) $(IDIR_UCLIBCXX) $(PACKAGE_DIR)

compile-targets: install-dev
install-dev: $(PKG_BUILD_DIR)/.built
	$(MAKE) -C $(PKG_BUILD_DIR) \
		TOPDIR="$(PKG_BUILD_DIR)/" \
		$(TARGET_CONFIGURE_OPTS) \
		ARCH_CFLAGS="$(TARGET_CFLAGS)" \
		CROSS="$(TARGET_CROSS)" \
		DESTDIR="$(STAGING_DIR)" \
		install

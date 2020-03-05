# $Id: Makefile 3112 2010-09-16 23:53:19Z rts $

include $(TOPDIR)/rules.mk

PKG_NAME:=grub
PKG_VERSION:=0.97
PKG_RELEASE:=3
PKG_MD5SUM:=cd3f3eb54446be6003156158d51f4884

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:= zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk


$(eval $(call PKG_template,GRUB,grub,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
	./configure CFLAGS="-O2 -fno-stack-protector -U_FORTIFY_SOURCE -Wl,--build-id=none" \
	CPPFLAGS="-O2 -fno-stack-protector -U_FORTIFY_SOURCE" SHELL=/bin/bash \
	grub_cv_prog_objcopy_absolute=yes \
	--target=$(GNU_HOST_NAME) \
	--host=$(GNU_HOST_NAME) \
	--build=$(GNU_HOST_NAME) \
	--program-prefix= \
	--program-suffix= \
	--disable-auto-linux-mem-opt \
	--disable-hercules \
	--without-curses \
	--disable-graphics \
	--disable-grub-mkfont \
	);
	touch $@



$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
	DESTDIR="$(PKG_INSTALL_DIR)" \
	all
	touch $@

$(IPKG_GRUB):
	install -m0755 -d $(IDIR_GRUB)/usr/bin
	$(IPKG_BUILD) $(IDIR_GRUB) $(PACKAGE_DIR)

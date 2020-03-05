# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=speexdsp
PKG_VERSION:=1.2rc3
PKG_RELEASE:=1
PKG_MD5SUM:=70d9d31184f7eb761192fd1ef0b73333
PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://us.speexdsp.org/download
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBSPEEXDSP,libspeexdsp,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(strip $(TARGET_CFLAGS))" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		./configure \
		--target=$(GNU_TARGET_NAME) \
		--host=$(GNU_TARGET_NAME) \
		--build=$(GNU_HOST_NAME) \
		  --program-prefix="" \
		  --program-suffix="" \
		  --prefix=/usr \
		  --exec-prefix=/usr \
		  --bindir=/usr/bin \
		  --datadir=/usr/share \
		  --includedir=/usr/include \
		  --infodir=/usr/share/info \
		  --libdir=/usr/lib \
		  --libexecdir=/usr/lib \
		  --localstatedir=/var \
		  --mandir=/usr/share/man \
		  --sbindir=/usr/sbin \
		  --sysconfdir=/etc \
		  $(DISABLE_LARGEFILE) \
		  $(DISABLE_NLS) \
		  --enable-shared \
		  --enable-static \
		  --disable-oggtest \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
	  	bin_PROGRAMS="" \
		all install
	touch $@

$(IPKG_LIBSPEEXDSP):
	install -d -m0755 $(IDIR_LIBSPEEXDSP)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libspeexdsp.so.* $(IDIR_LIBSPEEXDSP)/usr/lib/
	$(RSTRIP) $(IDIR_LIBSPEEXDSP)
	$(IPKG_BUILD) $(IDIR_LIBSPEEXDSP) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libspeexdsp.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/speex $(STAGING_DIR)/usr/include/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libspeexdsp.{a,so*} $(STAGING_DIR)/usr/lib/
	mkdir -p $(STAGING_DIR)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/speexdsp.pc $(STAGING_DIR)/usr/lib/pkgconfig/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libspeexdsp.so

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/include/speex \
		$(STAGING_DIR)/usr/lib/libspeexdsp.{a,so*} \
		$(STAGING_DIR)/usr/lib/pkgconfig/speexdsp.pc \

compile-targets: install-dev
clean-targets: uninstall-dev

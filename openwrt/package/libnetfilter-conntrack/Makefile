# $Id: Makefile 3586 2006-04-02 21:59:18Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=libnetfilter_conntrack
PKG_VERSION:=20070729
PKG_RELEASE:=1
PKG_MD5SUM:=2d2fefa94f8565530b3be86f95c7a299

PKG_SOURCE_URL:=https://dl.meraki.net/

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk
include $(TOPDIR)/target/linux/$(BOARD)-2.6/config

$(eval $(call PKG_template,LIBNETFILTER_CONNTRACK,libnetfilter-conntrack,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib -lnfnetlink" \
		LIBNFNETLINK_CFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		LIBNFNETLINK_LIBS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		LIBNETFILTER_CONNTRACK_CFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		LIBNETFILTER_CONNTRACK_LIBS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
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
			--disable-tcl \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) CC="$(TARGET_CC)" \
		LIBNFNETLINK_LIBS="-lnfnetlink" DESTDIR=$(PKG_INSTALL_DIR) \
		all install
	touch $@

$(STAGING_DIR)/usr/lib/libnetfilter_conntrack.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include $(STAGING_DIR)/usr/lib
	rsync -a $(PKG_INSTALL_DIR)/usr/include/ $(STAGING_DIR)/usr/include/
	rsync -a $(PKG_INSTALL_DIR)/usr/lib/ $(STAGING_DIR)/usr/lib/
	touch $@

$(IPKG_LIBNETFILTER_CONNTRACK):
	install -d -m0755 $(IDIR_LIBNETFILTER_CONNTRACK)/usr/lib
	$(CP) -a $(PKG_INSTALL_DIR)/usr/lib/* $(IDIR_LIBNETFILTER_CONNTRACK)/usr/lib/
	$(RSTRIP) $(IDIR_LIBNETFILTER_CONNTRACK)
	$(IPKG_BUILD) $(IDIR_LIBNETFILTER_CONNTRACK) $(PACKAGE_DIR)

install-dev: $(STAGING_DIR)/usr/lib/libnetfilter_conntrack.so

compile-targets: install-dev

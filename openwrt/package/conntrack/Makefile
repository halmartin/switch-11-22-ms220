# $Id: Makefile 3586 2006-04-02 21:59:18Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=conntrack-tools
PKG_VERSION:=0.9.5
PKG_RELEASE:=1
PKG_MD5SUM:=c639e17ba6cbfce52b288a5105724f2d

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk
include $(TOPDIR)/target/linux/$(BOARD)-2.6/config

$(eval $(call PKG_template,CONNTRACK,conntrack,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib -lnfnetlink" \
		LIBNETFILTER_CONNTRACK_CFLAGS="-I$(STAGING_DIR)/usr/include -L$(STAGING_DIR)/usr/lib" \
		LIBNETFILTER_CONNTRACK_LIBS="-lnetfilter_conntrack" \
		LIBNFNETLINK_CFLAGS="-I$(STAGING_DIR)/usr/include -L$(STAGING_DIR)/usr/lib" \
		LIBNFNETLINK_LIBS="-lnfnetlink" \
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
	$(MAKE) -C $(PKG_BUILD_DIR) CC="$(TARGET_CC)" DESTDIR=$(PKG_INSTALL_DIR) \
		all install
	touch $@

$(IPKG_CONNTRACK):
	install -d -m0755 $(IDIR_CONNTRACK)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/conntrack $(IDIR_CONNTRACK)/usr/sbin/
	$(RSTRIP) $(IDIR_CONNTRACK)
	$(IPKG_BUILD) $(IDIR_CONNTRACK) $(PACKAGE_DIR)

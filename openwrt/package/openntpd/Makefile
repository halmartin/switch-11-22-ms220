# $Id: Makefile 3274 2006-02-25 23:32:40Z florian $

include $(TOPDIR)/rules.mk

PKG_NAME:=openntpd
PKG_VERSION:=3.9p1
PKG_RELEASE:=1
PKG_MD5SUM:=afc34175f38d08867c1403d9008600b3

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,OPENNTPD,openntpd,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
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
		  --with-builtin-arc4random \
		  --with-privsep-user=nobody \
		  --with-adjtimex \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR)
	touch $@

$(IPKG_OPENNTPD):
	install -d -m0755 $(IDIR_OPENNTPD)/usr/sbin/
	install -m0755 $(PKG_BUILD_DIR)/ntpd $(IDIR_OPENNTPD)/usr/sbin/
	$(RSTRIP) $(IDIR_OPENNTPD)
	$(IPKG_BUILD) $(IDIR_OPENNTPD) $(PACKAGE_DIR)


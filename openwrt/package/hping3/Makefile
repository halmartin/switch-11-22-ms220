# $Id: Makefile 3566 2006-04-01 15:21:14Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=hping3
PKG_VERSION:=20051105
PKG_RELEASE:=1
PKG_MD5SUM:=ca4ea4e34bcc2162aedf25df8b2d1747


PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,HPING3,hping3,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	exit
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CXXFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include  -I$(STAGING_DIR)/pcap" \
		LDFLAGS="-nodefaultlibs -L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		ac_cv_prog_CXX="$(TARGET_CXX)" \
		./configure \
		  --target=$(GNU_TARGET_NAME) \
		  --host=$(GNU_TARGET_NAME) \
		  --build=$(GNU_HOST_NAME) \
		  --program-prefix="" \
		  --program-suffix="" \
		  --prefix=/usr \
		  --no-tcl \
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
		  --with-libpcap="$(STAGING_DIR)/usr" \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CCOPT="$(TARGET_CFLAGS) -I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include -L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib" \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all
	mkdir -p $(PKG_INSTALL_DIR)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/hping3 $(PKG_INSTALL_DIR)/usr/bin/hping3
	chmod 755 $(PKG_INSTALL_DIR)/usr/bin/hping3
	touch $@

$(IPKG_HPING3):
	install -d -m0755 $(IDIR_HPING3)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/hping3 $(IDIR_HPING3)/usr/bin/
	$(RSTRIP) $(IDIR_HPING3)
	$(IPKG_BUILD) $(IDIR_HPING3) $(PACKAGE_DIR)

mostlyclean:
	$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm $(PKG_BUILD_DIR)/.built

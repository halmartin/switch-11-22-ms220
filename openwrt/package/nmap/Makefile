# $Id: Makefile 3566 2006-04-01 15:21:14Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=nmap
PKG_VERSION:=6.47
PKG_RELEASE:=1
PKG_MD5SUM:=edfe81f6763223c0a29bfa15a8526e2a

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://download.insecure.org/nmap/dist
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,NMAP,nmap,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CXXFLAGS="$(TARGET_CFLAGS) -fno-builtin" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include  -I$(STAGING_DIR)/pcap" \
		LDFLAGS="-nodefaultlibs -L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		LIBS="-lstdc++ -lc -lm -lgcc -lgcc_eh" \
		ac_cv_prog_CXX="$(TARGET_CXX)" \
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
		  --without-openssl \
		  --without-nmapfe \
		  --without-liblua \
		  --without-zenmap \
		  --without-ncat \
		  --with-libpcap="$(STAGING_DIR)/usr" \
		  --with-libpcre="$(STAGING_DIR)/usr" \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CCOPT="$(TARGET_CFLAGS) -fno-builtin" \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)"
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CCOPT="$(TARGET_CFLAGS) -fno-builtin" \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		STRIP="$(TARGET_CROSS)strip" \
		install
	touch $@

$(IPKG_NMAP):
	install -d -m0755 $(IDIR_NMAP)/usr/share/nmap
	for file in mac-prefixes os-fingerprints protocols rpc service-probes services; do \
		$(CP) $(PKG_INSTALL_DIR)/usr/share/nmap/nmap-$$file $(IDIR_NMAP)/usr/share/nmap; \
	done
	install -d -m0755 $(IDIR_NMAP)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/nmap $(IDIR_NMAP)/usr/bin/
	$(RSTRIP) $(IDIR_NMAP)
	$(IPKG_BUILD) $(IDIR_NMAP) $(PACKAGE_DIR)

mostlyclean:
	$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm $(PKG_BUILD_DIR)/.built

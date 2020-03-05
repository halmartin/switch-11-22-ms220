# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=libevent
PKG_VERSION:=2.1.8-stable
PKG_RELEASE:=1
PKG_MD5SUM:=f3eeaed018542963b7d2416ef1135ecc

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBEVENT,libevent,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
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
		  --disable-thread-support \
		  --disable-openssl \
		  $(DISABLE_LARGEFILE) \
		  $(DISABLE_NLS) \
		  --enable-shared \
		  --enable-static \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_LIBEVENT):
	install -d -m0755 $(IDIR_LIBEVENT)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libevent-*.so.* $(IDIR_LIBEVENT)/usr/lib/
	$(RSTRIP) $(IDIR_LIBEVENT)
	$(IPKG_BUILD) $(IDIR_LIBEVENT) $(PACKAGE_DIR)

$(STAGING_DIR)/usr/lib/libevent.so: $(PKG_BUILD_DIR)/.built
	mkdir -p $(STAGING_DIR)/usr/include/event2
	$(CP) $(PKG_INSTALL_DIR)/usr/include/{evhttp,event,evdns,evrpc,evutil}.h $(STAGING_DIR)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/event2/*.h $(STAGING_DIR)/usr/include/event2/
	mkdir -p $(STAGING_DIR)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libevent.{a,so} $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libevent*.so* $(STAGING_DIR)/usr/lib/
	touch $@

install-dev: $(STAGING_DIR)/usr/lib/libevent.so

uninstall-dev:
	rm -rf \
	  $(STAGING_DIR)/usr/include/{evhttp,event,evdns,evrpc,evutil}.h \
	  $(STAGING_DIR)/usr/include/event2 \
	  $(STAGING_DIR)/usr/lib/libevent.{a,so} \
	  $(STAGING_DIR)/usr/lib/libevent*.so* \

compile-targets: install-dev
clean-targets: uninstall-dev

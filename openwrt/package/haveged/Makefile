include $(TOPDIR)/rules.mk

PKG_NAME:=haveged
PKG_VERSION:=1.9.1
PKG_RELEASE:=0
PKG_MD5SUM:=015ff58cd10607db0e0de60aeca2f5f8

ORIGINAL_UNUSED_SOURCE_URL:=http://www.issihosts.com/haveged/
PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,HAVEGED,haveged,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.source: $(DL_DIR)/$(PKG_SOURCE)
	zcat $(DL_DIR)/$(PKG_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	touch $(HAVEGED_DIR)/.source

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
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
			--disable-shared \
			--disable-olt \
			--enable-tune=cpuid \
			$(DISABLE_NLS) \
			$(DISABLE_LARGEFILE) \
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
	touch $@

$(IPKG_HAVEGED):
	install -d -m0755 $(IDIR_HAVEGED)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/$(PKG_NAME) $(IDIR_HAVEGED)/usr/bin/
	$(RSTRIP) $(IDIR_HAVEGED)/usr/bin/*
	$(IPKG_BUILD) $(IDIR_HAVEGED) $(PACKAGE_DIR)

mostlyclean:
	$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built

include $(TOPDIR)/rules.mk

PKG_NAME:=pam-script
PKG_VERSION:=1.1.6
PKG_RELEASE:=1
PKG_MD5SUM:=99a1f03078926096cddc73bd17462eb0

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,PAM_SCRIPT,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include" \
		CXXFLAGS="$(TARGET_CFLAGS)" \
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
		  --enable-shared \
		  $(DISABLE_LARGEFILE) \
		  $(DISABLE_NLS) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) all
	touch $@

$(IPKG_PAM_SCRIPT):
	install -m0755 -d $(IDIR_PAM_SCRIPT)/usr/lib/security
	$(CP) $(PKG_BUILD_DIR)/.libs/pam_script.so $(IDIR_PAM_SCRIPT)/usr/lib/security
	$(RSTRIP) $(IDIR_PAM_SCRIPT)
	$(IPKG_BUILD) $(IDIR_PAM_SCRIPT) $(PACKAGE_DIR)

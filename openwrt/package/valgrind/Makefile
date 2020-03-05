
include $(TOPDIR)/rules.mk

PKG_NAME:=valgrind
PKG_VERSION:=3.13.0
PKG_RELEASE:=1
PKG_MD5SUM:=817dd08f1e8a66336b9ff206400a5369

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,VALGRIND,valgrind,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; autoreconf -i; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include" \
		LDFLAGS="-L $(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib" \
		./configure \
                        --target=$(GNU_TARGET_NAME) \
                        --host=$(GNU_TARGET_NAME) \
                        --build=$(GNU_HOST_NAME) \
                        --program-prefix="" \
                        --prefix=/usr \
                        --exec-prefix=/usr \
                        --bindir=/usr/bin \
                        --sbindir=/usr/sbin \
                        --libexecdir=/usr/lib \
                        --sysconfdir=/etc \
                        --datadir=/usr/share \
                        --localstatedir=/var \
                        --mandir=/usr/man \
                        --infodir=/usr/info \
	);
	touch $@

$(PKG_BUILD_DIR)/.built: $(PKG_BUILD_DIR)/.configured
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -j4 -C $(PKG_BUILD_DIR) \
		CCOPT="$(TARGET_CFLAGS)" INCLS="-I. -I$(STAGING_DIR)/usr/include" \
		DESTDIR=$(PKG_INSTALL_DIR) \
		install
	touch $@

$(IPKG_VALGRIND):
	install -d -m0755 $(IDIR_VALGRIND)/usr/bin
	install -m0755 $(PKG_INSTALL_DIR)/usr/bin/valgrind $(IDIR_VALGRIND)/usr/bin/
	install -d -m0755 $(IDIR_VALGRIND)/usr/lib/valgrind
	install -D -m0755 $(PKG_INSTALL_DIR)/usr/lib/valgrind/memcheck-*-linux $(IDIR_VALGRIND)/usr/lib/valgrind/
	install -D -m0755 $(PKG_INSTALL_DIR)/usr/lib/valgrind/default.supp $(IDIR_VALGRIND)/usr/lib/valgrind/
	$(IPKG_BUILD) $(IDIR_VALGRIND) $(PACKAGE_DIR)


# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=tinyproxy
PKG_VERSION:=1.8.4
PKG_RELEASE:=1
PKG_MD5SUM:=1c65daa8ca3394999f218a832112f35f

PKG_SOURCE_URL:=https://dl.meraki.net
UNUSED_ORIGINAL_PKG_SOURCE_URL:=@SF/tinyproxy
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,TINYPROXY,tinyproxy,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

ifeq ($(BR2_COMPILE_TINYPROXY_WITH_TRANSPARENT_PROXY),y)
ENABLE_TRANSPARENT:=--enable-transparent-proxy
endif
ifneq ($(BR2_COMPILE_TINYPROXY_WITH_UPSTREAM),y)
DISABLE_UPSTREAM:=--disable-upstream
endif
ifneq ($(BR2_COMPILE_TINYPROXY_WITH_FILTER),y)
DISABLE_FILTER:=--disable-filter
endif

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(strip $(TARGET_CFLAGS))" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		ac_cv_func_malloc_0_nonnull=yes \
		ac_cv_func_realloc_0_nonnull=yes \
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
		  --disable-regexcheck \
		  --sysconfdir=/etc \
		  $(ENABLE_TRANSPARENT) \
		  $(DISABLE_UPSTREAM) \
		  $(DISABLE_FILTER) \
	);
	touch $(PKG_BUILD_DIR)/.configured

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		install
	find $(PKG_INSTALL_DIR) -name '*dist' | xargs rm -f
	touch $(PKG_BUILD_DIR)/.built

$(IPKG_TINYPROXY):
	install -d -m0755 $(IDIR_TINYPROXY)/usr/sbin \
				$(IDIR_TINYPROXY)/etc/init.d \
				$(IDIR_TINYPROXY)/usr/share \
				$(IDIR_TINYPROXY)/var/log/tinyproxy \
				$(IDIR_TINYPROXY)/var/run/tinyproxy
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/tinyproxy $(IDIR_TINYPROXY)/usr/sbin/
	$(CP) $(PKG_INSTALL_DIR)/usr/share/tinyproxy $(IDIR_TINYPROXY)/usr/share/
	$(CP) files/$(PKG_NAME).init $(IDIR_TINYPROXY)/etc/init.d/$(PKG_NAME)
	$(RSTRIP) $(IDIR_TINYPROXY)
	$(IPKG_BUILD) $(IDIR_TINYPROXY) $(PACKAGE_DIR)

install-dev:
	$(MAKE) -C $(PKG_BUILD_DIR) install DESTDIR=$(STAGING_DIR)

compile-targets: install-dev

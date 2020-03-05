# $Id: Makefile 973 2005-05-19 21:22:09Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=liblogging
PKG_VERSION:=1.0.5
PKG_RELEASE:=1
PKG_MD5SUM:=44b8ce2daa1bfb84c9feaf42f9925fd7

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,LIBLOGGING,liblogging,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
                ac_cv_func_malloc_0_nonnull="yes" \
                ac_cv_func_realloc_0_nonnull="yes" \
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
		  --enable-wide-getaddrinfo \
		  --enable-journal=no \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR)
	touch $@

$(IPKG_LIBLOGGING):
	#install -d -m0755 $(IDIR_LIBLOGGING)/usr/bin
	#install -m0755 $(PKG_BUILD_DIR)/liblogging $(IDIR_LIBLOGGING)/usr/bin/liblogging

	$(RSTRIP) $(IDIR_LIBLOGGING)
	$(IPKG_BUILD) $(IDIR_LIBLOGGING) $(PACKAGE_DIR)

include $(TOPDIR)/rules.mk

PKG_NAME:=openl2tp
PKG_VERSION:=1.8
PKG_RELEASE:=1
PKG_MD5SUM:=e3d08dedfb9e6a9a1e24f6766f6dadd0

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,OPENL2TP,openl2tp,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

ifeq ($(BR2_LIBC_MUSL),y)
OPENL2TP_CPPFLAGS=-I$(STAGING_DIR)/include/tirpc
endif

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		READLINE_DIR="$(STAGING_DIR)/usr" \
		DESTDIR="$(IDIR_OPENL2TP)" \
		CPPFLAGS="$(OPENL2TP_CPPFLAGS)" \
		all install
	touch $@

$(IPKG_OPENL2TP):
	rm -rf $(IDIR_OPENL2TP)/usr/lib/openl2tp/event_sock.*
	rm -rf $(IDIR_OPENL2TP)/usr/lib/openl2tp/l2tp_*
	rm -rf $(IDIR_OPENL2TP)/usr/lib/openl2tp/ppp_null.so
	rm -rf $(IDIR_OPENL2TP)/usr/lib/openl2tp/ipsec.so
	rm -rf $(IDIR_OPENL2TP)/usr/share
	$(RSTRIP) $(IDIR_OPENL2TP)
	$(IPKG_BUILD) $(IDIR_OPENL2TP) $(PACKAGE_DIR)

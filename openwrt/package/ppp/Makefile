# $Id: Makefile 3401 2006-03-18 17:27:20Z nbd $

include $(TOPDIR)/rules.mk

PKG_NAME:=ppp
PKG_VERSION:=2.4.7
PKG_RELEASE:=16
PKG_MD5SUM:=78818f40e6d33a1d1de68a1551f6595a

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

define PKG_mod_template

$$(IPKG_$(1)):
	install -d -m0755 $$(IDIR_$(1))/usr/lib/pppd/$(PKG_VERSION)
	install -m0755 $(PKG_INSTALL_DIR)/usr/lib/pppd/$(PKG_VERSION)/$(2).so \
		$$(IDIR_$(1))/usr/lib/pppd/$(PKG_VERSION)/
	$(RSTRIP) $$(IDIR_$(1))
	$(IPKG_BUILD) $$(IDIR_$(1)) $(PACKAGE_DIR)

endef

$(eval $(call PKG_template,PPP,ppp,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,PPP_MOD_PPPOA,ppp-mod-pppoa,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,PPP_MOD_PPPOE,ppp-mod-pppoe,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,PPP_MOD_RADIUS,ppp-mod-radius,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,PPP_MOD_L2TP,ppp-mod-l2tp,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,CHAT,chat,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,PPPDUMP,pppdump,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,PPPSTATS,pppstats,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(eval $(call PKG_mod_template,PPP_MOD_PPPOA,pppoatm))
$(eval $(call PKG_mod_template,PPP_MOD_PPPOE,rp-pppoe))
$(eval $(call PKG_mod_template,PPP_MOD_RADIUS,radius))

PKG_DEPEND:="kmod-ppp"
ifeq ($(BR2_PACKAGE_PPP_WITH_FILTER),y)
ENABLE_FILTER:="PRECOMPILED_FILTER=1"
endif

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
	)
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)/usr
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		COPTS="$(TARGET_CFLAGS) -L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib" \
		USE_PAM="y" \
		$(ENABLE_FILTER) \
		STAGING_DIR=$(STAGING_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)/usr" \
		all install
	touch $@

ifeq ($(BR2_PACKAGE_PPP_WITH_FILTER),y)
INSTALL_FILTER=install -m0644 ./files/etc/ppp/filter $(IDIR_PPP)/etc/ppp/
endif

$(IPKG_PPP):
	install -d -m0755 $(IDIR_PPP)/etc/ppp
	install -d -m0755 $(IDIR_PPP)/etc/ppp/peers
	$(INSTALL_FILTER)
	install -d -m0755 $(IDIR_PPP)/usr/sbin
	install -m0755 $(PKG_INSTALL_DIR)/usr/sbin/pppd $(IDIR_PPP)/usr/sbin/
	install -d -m0755 $(IDIR_PPP)/usr/lib/pppd
	install -d -m0755 $(IDIR_PPP)/usr/lib/pppd/$(PKG_VERSION)
	install -m0755 $(PKG_INSTALL_DIR)/usr/lib/pppd/$(PKG_VERSION)/ipfromclick.so \
		$(IDIR_PPP)/usr/lib/pppd/$(PKG_VERSION)/
	echo "Depends: $(PKG_DEPEND)" >> $(IDIR_PPP)/CONTROL/control
	$(RSTRIP) $(IDIR_PPP)
	$(IPKG_BUILD) $(IDIR_PPP) $(PACKAGE_DIR)

$(IDIR_PPP_MOD_PPPOA)/sbin/ifup.pppoa:
	install -d -m0755 $(IDIR_PPP_MOD_PPPOA)/sbin
	install -m0755 ./files/ifup.pppoa $(IDIR_PPP_MOD_PPPOA)/sbin/

$(IPKG_PPP_MOD_PPPOA): $(IDIR_PPP_MOD_PPPOA)/sbin/ifup.pppoa

$(IDIR_PPP_MOD_RADIUS)/etc/ppp/radius/dictionary:
	install -d -m0755 $(IDIR_PPP_MOD_RADIUS)/etc/ppp
	install -d -m0755 $(IDIR_PPP_MOD_RADIUS)/etc/ppp/radius
	install -m644 ./files/etc/ppp/radius/dictionary* \
		$(IDIR_PPP_MOD_RADIUS)/etc/ppp/radius/

$(IPKG_PPP_MOD_RADIUS): $(IDIR_PPP_MOD_RADIUS)/etc/ppp/radius/dictionary

$(IPKG_CHAT):
	install -d -m0755 $(IDIR_CHAT)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/chat $(IDIR_CHAT)/usr/sbin/
	$(RSTRIP) $(IDIR_CHAT)
	$(IPKG_BUILD) $(IDIR_CHAT) $(PACKAGE_DIR)

$(IPKG_PPPDUMP):
	install -d -m0755 $(IDIR_PPPDUMP)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/pppdump $(IDIR_PPPDUMP)/usr/sbin/
	$(RSTRIP) $(IDIR_PPPDUMP)
	$(IPKG_BUILD) $(IDIR_PPPDUMP) $(PACKAGE_DIR)

$(IPKG_PPPSTATS): $(IPKG_PPP)
	install -d -m0755 $(IDIR_PPPSTATS)/usr/sbin
	$(CP) $(PKG_INSTALL_DIR)/usr/sbin/pppstats $(IDIR_PPPSTATS)/usr/sbin/
	$(RSTRIP) $(IDIR_PPPSTATS)
	$(IPKG_BUILD) $(IDIR_PPPSTATS) $(PACKAGE_DIR)

$(IPKG_PPP_MOD_L2TP):
	install -d -m0755 $(IDIR_PPP_MOD_L2TP)/usr/lib/pppd/$(PKG_VERSION)
	install -m0755 $(PKG_INSTALL_DIR)/usr/lib/pppd/$(PKG_VERSION)/openl2tp.so \
		$(IDIR_PPP_MOD_L2TP)/usr/lib/pppd/$(PKG_VERSION)/
	install -m0755 $(PKG_INSTALL_DIR)/usr/lib/pppd/$(PKG_VERSION)/pppol2tp.so \
		$(IDIR_PPP_MOD_L2TP)/usr/lib/pppd/$(PKG_VERSION)/
	$(RSTRIP) $(IDIR_PPP_MOD_L2TP)
	$(IPKG_BUILD) $(IDIR_PPP_MOD_L2TP) $(PACKAGE_DIR)

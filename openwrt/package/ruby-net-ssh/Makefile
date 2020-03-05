# $Id: Makefile 973 2005-05-19 21:22:09Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=ruby-net-ssh
PKG_VERSION:=2.0.15
PKG_RELEASE:=1
PKG_MD5SUM:=bef3bc238f0ba1988c9ca12698cc4e35

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=net-ssh-$(PKG_VERSION).tgz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/net-ssh-$(PKG_VERSION)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,RUBY_NET_SSH,ruby-net-ssh,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	touch $@

$(IPKG_RUBY_NET_SSH):
	for file in ssh \
		ssh/authentication \
		ssh/proxy \
		ssh/test \
		ssh/service \
		ssh/transport \
		ssh/verifiers ; do \
	  install -d -m0755 $(IDIR_RUBY_NET_SSH)/usr/lib/ruby/1.8/net/$$file; \
	  install -m0755 $(PKG_BUILD_DIR)/lib/net/$$file/*.rb $(IDIR_RUBY_NET_SSH)/usr/lib/ruby/1.8/net/$$file; \
	done
	$(RSTRIP) $(IDIR_RUBY_NET_SSH)
	$(IPKG_BUILD) $(IDIR_RUBY_NET_SSH) $(PACKAGE_DIR)

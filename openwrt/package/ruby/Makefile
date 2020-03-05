# $Id: Makefile 973 2005-05-19 21:22:09Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=ruby
PKG_VERSION:=1.8.4
PKG_RELEASE:=1
PKG_MD5SUM:=bd8c2e593e1fa4b01fd98eaf016329bb

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=ruby-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/ruby-$(PKG_VERSION)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,RUBY,ruby,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="-I$(STAGING_DIR)/usr/include $(TARGET_CFLAGS)" \
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
		  --enable-wide-getaddrinfo \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR)
	touch $@

$(IPKG_RUBY):
	install -d -m0755 $(IDIR_RUBY)/usr/bin
	install -d -m0755 $(IDIR_RUBY)/usr/lib/ruby/1.8
	install -d -m0755 $(IDIR_RUBY)/usr/lib/ruby/1.8/net
	install -d -m0755 $(IDIR_RUBY)/usr/lib/ruby/1.8/uri
	install -d -m0755 $(IDIR_RUBY)/usr/lib/ruby/1.8/openssl
	install -m0755 $(PKG_BUILD_DIR)/ruby $(IDIR_RUBY)/usr/bin/ruby
	install -m0755 $(PKG_BUILD_DIR)/.ext/*-linux/socket.so $(IDIR_RUBY)/usr/lib/ruby/1.8/socket.so
	install -m0755 $(PKG_BUILD_DIR)/.ext/*-linux/syslog.so $(IDIR_RUBY)/usr/lib/ruby/1.8/syslog.so
	install -m0755 $(PKG_BUILD_DIR)/.ext/*-linux/stringio.so $(IDIR_RUBY)/usr/lib/ruby/1.8/stringio.so
	install -m0755 $(PKG_BUILD_DIR)/.ext/*-linux/openssl.so $(IDIR_RUBY)/usr/lib/ruby/1.8/openssl.so
	install -m0755 $(PKG_BUILD_DIR)/.ext/*-linux/fcntl.so $(IDIR_RUBY)/usr/lib/ruby/1.8
	install -m0755 $(PKG_BUILD_DIR)/.ext/*-linux/pty.so $(IDIR_RUBY)/usr/lib/ruby/1.8

	install -m0755 $(PKG_BUILD_DIR)/.ext/openssl.rb $(IDIR_RUBY)/usr/lib/ruby/1.8/
	install -m0755 $(PKG_BUILD_DIR)/.ext/expect.rb $(IDIR_RUBY)/usr/lib/ruby/1.8/
	install -m0755 $(PKG_BUILD_DIR)/.ext/openssl/*.rb $(IDIR_RUBY)/usr/lib/ruby/1.8/openssl
	for file in getoptlong.rb \
			getopts.rb \
			English.rb \
			cgi.rb \
			delegate.rb \
			timeout.rb \
			thread.rb \
			net/http.rb \
			net/https.rb \
			net/protocol.rb \
			net/telnet.rb \
			uri.rb \
			uri/common.rb \
			uri/generic.rb \
			uri/ftp.rb \
			uri/http.rb \
			uri/https.rb \
			uri/ldap.rb \
			uri/mailto.rb \
			; do \
		install -m0755 $(PKG_BUILD_DIR)/lib/$$file $(IDIR_RUBY)/usr/lib/ruby/1.8/$$file; \
	done
	$(RSTRIP) $(IDIR_RUBY)
	$(IPKG_BUILD) $(IDIR_RUBY) $(PACKAGE_DIR)

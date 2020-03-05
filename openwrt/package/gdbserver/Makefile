# $Id: Makefile 3112 2006-02-01 23:53:19Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=gdbserver
PKG_RELEASE:=1.1
PKG_VERSION:=7.11
PKG_MD5SUM:=b5c784685e1cde65ba135feea86b6d75
PKG_BUILD_DIR:=$(BUILD_DIR)/gdb-$(PKG_VERSION)
PKG_SOURCE:=gdb-$(PKG_VERSION).tar.xz
UNUSED_ORIGINAL_PKG_SOURCE_URL:=http://ftp.gnu.org/gnu/gdb/
PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install
PKG_CAT:=xzcat

GDB_DIR:=$(BUILD_DIR)/gdb-$(PKG_VERSION)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,GDBSERVER,gdbserver,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR)/gdb/gdbserver; rm -rf config.{cache,status}; \
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
		  --sbindir=/usr/sbin \
		  --libexecdir=/usr/lib \
		  --sysconfdir=/etc \
		  --datadir=/usr/share \
		  --localstatedir=/var \
		  --mandir=/usr/man \
		  --infodir=/usr/info \
		  $(DISABLE_LARGEFILE) \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR)/gdb/gdbserver \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		install
	touch $@

$(IPKG_GDBSERVER):
	install -m0755 -d $(IDIR_GDBSERVER)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/gdbserver $(IDIR_GDBSERVER)/usr/bin/
	$(RSTRIP) $(IDIR_GDBSERVER)
	$(IPKG_BUILD) $(IDIR_GDBSERVER) $(PACKAGE_DIR)


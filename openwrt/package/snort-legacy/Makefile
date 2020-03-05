# $Id: Makefile 3567 2006-04-01 15:23:25Z nico $

include $(TOPDIR)/rules.mk

PKG_NAME:=snort
PKG_VERSION:=2.9.7.6
PKG_RELEASE:=1
PKG_MD5SUM:=65349f3272c4de5b3210f77f1f7ab0e6

#PKG_SOURCE_URL:= https://www.snort.org/downloads/snort/
#PKG_SOURCE_URL:= https://snort.org/downloads/archive/snort/
PKG_SOURCE_URL:= https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

PKG_CONFIGURE_OPTS := \
	--target=$(GNU_TARGET_NAME) \
	--host=$(GNU_TARGET_NAME) \
	--build=$(GNU_HOST_NAME) \
	--program-prefix="" \
	--program-suffix="" \
	--prefix=/usr \
	--exec-prefix=/usr \
	--bindir=/usr/sbin \
	--datadir=/usr/share \
	--includedir=/usr/include \
	--infodir=/usr/share/info \
	--libdir=/usr/lib \
	--libexecdir=/usr/lib/locate \
	--localstatedir=/var/lib \
	--mandir=/usr/share/man \
	--sbindir=/usr/sbin \
	--sysconfdir=/etc \
	$(DISABLE_LARGEFILE) \
	$(DISABLE_NLS) \
	--enable-shared \
	--disable-static \
	--enable-flexresp \
	--with-dnet-includes="$(STAGING_DIR)/usr/include" \
	--with-dnet-libraries="$(STAGING_DIR)/usr/lib" \
	--with-libpcap-includes="$(STAGING_DIR)/usr/include" \
	--with-libpcap-libraries="$(STAGING_DIR)/usr/lib" \
	--with-libpcre-includes="$(STAGING_DIR)/usr/include" \
	--with-libpcre-libraries="$(STAGING_DIR)/usr/lib" \
	--disable-static-daq \
	--enable-sourcefire \

SNORT_BASIC_CONFIGURE_OPTS := \
	--without-mysql \
	--without-postgresql \

SNORT_MYSQL_CONFIGURE_OPTS := \
	--with-mysql=$(STAGING_DIR)/usr \
	--without-postgresql \

SNORT_PGSQL_CONFIGURE_OPTS := \
	--without-mysql \
	--with-postgresql=$(STAGING_DIR)/usr \

SNORT_CUSTOM_CONFIGURE_OPTS := \

ifeq ($(BR2_PACKAGE_SNORT_ENABLE_DEBUG),y)
SNORT_CUSTOM_CONFIGURE_OPTS += --enable-debug
else
SNORT_CUSTOM_CONFIGURE_OPTS += --disable-debug
endif

ifeq ($(BR2_PACKAGE_SNORT_ENABLE_INLINE),y)
SNORT_CUSTOM_CONFIGURE_OPTS += --enable-inline
SNORT_CUSTOM_CONFIGURE_OPTS += --with-libipq-includes="$(STAGING_DIR)/include/libipq"
SNORT_CUSTOM_CONFIGURE_OPTS += --with-libipq-libraries="$(STAGING_DIR)/lib"
else
SNORT_CUSTOM_CONFIGURE_OPTS += --disable-inline
endif

ifeq ($(BR2_PACKAGE_SNORT_WITH_MYSQL),y)
SNORT_CUSTOM_CONFIGURE_OPTS += --with-mysql="$(STAGING_DIR)/usr"
else
SNORT_CUSTOM_CONFIGURE_OPTS += --without-mysql
endif

ifeq ($(BR2_PACKAGE_SNORT_WITH_PGSQL),y)
SNORT_CUSTOM_CONFIGURE_OPTS += --with-postgresql="$(STAGING_DIR)/usr"
else
SNORT_CUSTOM_CONFIGURE_OPTS += --without-postgresql
endif

define PKG_build

ifneq ($(BR2_PACKAGE_$(1)),)
BUILD_TARGETS += $(PKG_BUILD_DIR)/$(2)
endif

$(PKG_BUILD_DIR)/$(2): $(PKG_BUILD_DIR)/.prepared
	touch -r $(PKG_BUILD_DIR)/Makefile.am $(PKG_BUILD_DIR)/configure.in 
	touch -r $(PKG_BUILD_DIR)/Makefile.in $(PKG_BUILD_DIR)/configure
	-$(MAKE) -C $(PKG_BUILD_DIR) distclean
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status} ; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include/mysql" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib/mysql" \
		have_pcap_lex_destroy="yes" \
		have_inaddr_none="yes" \
		./configure \
		  $(PKG_CONFIGURE_OPTS) \
		  $$($(1)_CONFIGURE_OPTS) \
	);
	$(MAKE) -C $(PKG_BUILD_DIR)
	mv $(PKG_BUILD_DIR)/src/snort $(PKG_BUILD_DIR)/$(2)

$$(IPKG_$(1)): $(PKG_BUILD_DIR)/.installed $(PKG_BUILD_DIR)/$(2)
	install -m0755 -d $$(IDIR_$(1))/usr/lib/snort_dynamicpreprocessor
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/snort_dynamicpreprocessor/lib*.so* $$(IDIR_$(1))/usr/lib/snort_dynamicpreprocessor
	install -m0755 -d $$(IDIR_$(1))/usr/lib/snort_dynamicengine
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/snort_dynamicengine/lib*.so* $$(IDIR_$(1))/usr/lib/snort_dynamicengine
	install -d -m0755 $$(IDIR_$(1))/etc/snort
	install -d -m0755 $$(IDIR_$(1))/usr/sbin
	install -m0755 $(PKG_BUILD_DIR)/$(2) $$(IDIR_$(1))/usr/sbin/snort
	install -d -m0755 $$(IDIR_$(1))/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/snort-version $$(IDIR_$(1))/usr/bin/snort-version
	$(RSTRIP) $$(IDIR_$(1))
	mkdir -p $(PACKAGE_DIR)
	$(IPKG_BUILD) $$(IDIR_$(1)) $(PACKAGE_DIR)

endef

$(eval $(call PKG_template,SNORT_BASIC_LEGACY,snort,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SNORT_MYSQL,snort-mysql,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SNORT_PGSQL,snort-pgsql,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_template,SNORT_CUSTOM,snort-custom,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(eval $(call PKG_build,SNORT_BASIC_LEGACY,snort,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_build,SNORT_MYSQL,snort-mysql,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_build,SNORT_PGSQL,snort-pgsql,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))
$(eval $(call PKG_build,SNORT_CUSTOM,snort-custom,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built: $(BUILD_TARGETS)
	touch $@

$(PKG_BUILD_DIR)/.installed: $(PKG_BUILD_DIR)/.built
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" DESTDIR="$(PKG_INSTALL_DIR)" \
		install
	echo -e '#!/bin/sh\necho -n $(PKG_VERSION)' > $(PKG_BUILD_DIR)/snort-version
	chmod +x $(PKG_BUILD_DIR)/snort-version
	mkdir -p $(PKG_INSTALL_DIR)/usr/bin/
	$(CP) $(PKG_BUILD_DIR)/snort-version $(PKG_INSTALL_DIR)/usr/bin/
	touch $(PKG_BUILD_DIR)/.installed

$(STAGING_DIR)/usr/include/snort: $(PKG_BUILD_DIR)/.built
	mkdir -p $@
	cp -a --target-directory=$(STAGING_DIR)/usr/include $(PKG_INSTALL_DIR)/usr/include/snort

$(STAGING_DIR)/usr/lib/snort_dynamicpreprocessor: $(PKG_BUILD_DIR)/.built
	mkdir -p $@
	cp -a --target-directory=$(STAGING_DIR)/usr/lib $(PKG_INSTALL_DIR)/usr/lib/snort_dynamicpreprocessor

$(STAGING_DIR)/usr/lib/snort_dynamicengine: $(PKG_BUILD_DIR)/.built
	mkdir -p $@
	cp -a --target-directory=$(STAGING_DIR)/usr/lib $(PKG_INSTALL_DIR)/usr/lib/snort_dynamicengine

$(STAGING_DIR)/usr/bin/snort-version: $(PKG_BUILD_DIR)/.built
	mkdir -p $(dir $@)
	cp -a --target-directory=$(dir $@) $(PKG_INSTALL_DIR)/usr/bin/snort-version
	chmod +x $(PKG_BUILD_DIR)/snort-version

install-dev: $(STAGING_DIR)/usr/include/snort
install-dev: $(STAGING_DIR)/usr/lib/snort_dynamicpreprocessor
install-dev: $(STAGING_DIR)/usr/lib/snort_dynamicengine
install-dev: $(STAGING_DIR)/usr/bin/snort-version

uninstall-dev:
	rm -rf \
		$(STAGING_DIR)/usr/include/snort/ \
		$(STAGING_DIR)/usr/lib/snort_dynamicpreprocessor/ \
		$(STAGING_DIR)/usr/lib/snort_dynamicengine/ \
		$(STAGING_DIR)/usr/bin/snort-version \

compile-targets: install-dev
clean-targets: uninstall-dev

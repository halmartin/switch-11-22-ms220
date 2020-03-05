include $(TOPDIR)/rules.mk

PKG_NAME:=wmi
PKG_VERSION:=1.3.16
PKG_RELEASE:=0
PKG_MD5SUM:=ba0ebcc3d5b25cb3690672f845ce3003

PKG_SOURCE_URL:=https://dl.meraki.net
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bzcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,WMI_CLIENT,wmi-client,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

ifeq ($(BR2_64BIT_ARCH),y)
WMI_CLIENT_SIZEOF_LONG=8
else
WMI_CLIENT_SIZEOF_LONG=4
endif

$(PKG_BUILD_DIR)/.configured:
	[ -e $(PKG_BUILD_DIR)/Samba/source/librpc/config.mk ] || ln -sf config.mk.nobreakpad $(PKG_BUILD_DIR)/Samba/source/librpc/config.mk || true
	touch $@

$(PKG_BUILD_DIR)/.tools:
	#generate autoconf
	(cd $(PKG_BUILD_DIR)/Samba/source ; ./autogen.sh );

	#build asn1_compile for host
	(cd $(PKG_BUILD_DIR)/Samba/source; rm -rf config.{cache,status}; \
		./configure \
			--without-readline \
			--with-included-popt \
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
			--localstatedir=/var/log/samba \
			--mandir=/usr/share/man \
			--sbindir=/usr/sbin \
			--sysconfdir=/etc/samba \
			$(DISABLE_LARGEFILE) \
			$(DISABLE_NLS) \
			--with-lockdir=/var/run/samba \
	#		--with-privatedir=/etc/samba \
	);

	# create host-based tools
	$(MAKE) -C $(PKG_BUILD_DIR)/Samba/source \
		clean bin/asn1_compile bin/compile_et

	# stash
	(cd $(PKG_BUILD_DIR)/Samba/source; \
		cp ./bin/asn1_compile ./bin/compile_et . \
	);

	$(MAKE) -C $(PKG_BUILD_DIR)/Samba/source clean

	touch $@

$(PKG_BUILD_DIR)/.built: $(PKG_BUILD_DIR)/.tools
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)

	#generate autoconf
	(cd $(PKG_BUILD_DIR)/Samba/source ; ./autogen.sh );

	(cd $(PKG_BUILD_DIR)/Samba/source; rm -rf config.{cache,status}; \
		$(TARGET_CONFIGURE_OPTS) \
		CPP="$(TARGET_CROSS)gcc -E -ffreestanding" \
		CFLAGS="$(TARGET_CFLAGS) -D_GNU_SOURCE -DNDEBUG -DSHMEM_SIZE=524288" \
		CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-lgcc_s -L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib" \
		SMB_BUILD_CC_NEGATIVE_ENUM_VALUES=yes \
		PKG_CONFIG_PATH="$(STAGING_DIR)/usr/lib/pkgconfig" \
		ac_cv_path_PKG_CONFIG=no \
		ac_cv_sizeof_int=4 \
		ac_cv_sizeof_long=$(WMI_CLIENT_SIZEOF_LONG) \
		ac_cv_sizeof_short=2 \
		libreplace_cv_READDIR_NEEDED=no \
		libreplace_cv_USABLE_NET_IF_H=yes \
		libreplace_cv_dlfcn=no \
		libreplace_cv_immediate_structures=yes \
		samba_cv_HAVE_C99_VSNPRINTF=yes \
		XXsamba_cv_HAVE_FUNCTION_MACRO=yes \
		samba_cv_HAVE_GETTIMEOFDAY_TZ=yes \
		XXsamba_cv_HAVE_IFACE_AIX=no \
		XXsamba_cv_HAVE_IFACE_IFCONF=yes \
		XXsamba_cv_HAVE_IRIX_SPECIFIC_CAPABILITIES=no \
		samba_cv_HAVE_MMAP=yes \
		samba_cv_HAVE_OPEN_O_DIRECT=no \
		samba_cv_HAVE_SECURE_MKSTEMP=yes \
		samba_cv_HAVE_SOCK_SIN_LEN=no \
		samba_cv_HAVE_VA_COPY=yes \
		XXsamba_cv_HAVE_WORKING_AF_LOCAL=yes \
		samba_cv_HAVE_WRFILE_KEYTAB=no \
		samba_cv_REPLACE_GETPASS=no \
		XXsamba_cv_REPLACE_INET_NTOA=no \
		XXsamba_cv_c99_struct_initialization=yes \
		XXsamba_cv_sig_atomic_t=yes \
		XXsamba_cv_unixsocket=yes \
		XXsamba_cv_volatile=yes \
		XXsmb_attr_cv_xattr_add_opt=no \
		SMB_BUILD_CC_NEGATIVE_ENUM_VALUES=yes \
		./configure \
			--without-readline \
			--with-included-popt \
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
			--localstatedir=/var/log/samba \
			--mandir=/usr/share/man \
			--sbindir=/usr/sbin \
			--sysconfdir=/etc/samba \
			$(DISABLE_LARGEFILE) \
			$(DISABLE_NLS) \
			--with-lockdir=/var/run/samba \
			--with-privatedir=/etc/samba \
	);

	# build objects to prevent rebuild
	$(MAKE) -C $(PKG_BUILD_DIR)/Samba/source \
		bin/asn1_compile bin/compile_et

	# restore host-based tools
	(cd $(PKG_BUILD_DIR)/Samba/source; \
		cp ./asn1_compile ./compile_et ./bin \
	);

	$(MAKE) -C $(PKG_BUILD_DIR)/Samba/source \
		$(TARGET_CONFIGURE_OPTS) CPP="$(TARGET_CROSS)gcc -E -ffreestanding" \
		proto bin/wmic bin/wmilogons

	touch $@

$(IPKG_WMI_CLIENT):
	install -d -m0755 $(IDIR_WMI_CLIENT)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/Samba/source/bin/wmic $(IDIR_WMI_CLIENT)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/Samba/source/bin/wmilogons $(IDIR_WMI_CLIENT)/usr/bin
	$(RSTRIP) $(IDIR_WMI_CLIENT)
	$(IPKG_BUILD) $(IDIR_WMI_CLIENT) $(PACKAGE_DIR)

mostlyclean:
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	rm -f $(PKG_BUILD_DIR)/.built


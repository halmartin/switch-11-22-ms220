# $Id: Makefile 3561 2006-03-31 18:25:00Z mbm $

include $(TOPDIR)/rules.mk

PKG_NAME:=base-files
PKG_RELEASE:=6
PKG_BUILD_DIR:=$(BUILD_DIR)/base-files


include $(TOPDIR)/package/rules.mk

IDIR_BASE:=$(PKG_BUILD_DIR)/base-files
IPKG_BASE:=$(PACKAGE_DIR)/$(PKG_NAME)_$(PKG_RELEASE)_$(ARCH).ipk
PACKAGES:=$(IPKG_BASE)
PACKAGES_INSTALL:=$(IPKG_BASE)

ifeq ($(BR2_LIBC_UCLIBC),y)
UCLIBC_VERSION:=${shell cat $(STAGING_DIR)/uclibc_version}
IDIR_UCLIBC:=$(PKG_BUILD_DIR)/uclibc
IPKG_UCLIBC:=$(PACKAGE_DIR)/uclibc_$(UCLIBC_VERSION)-$(PKG_RELEASE)_$(ARCH).ipk
PACKAGES += $(IPKG_UCLIBC)
PACKAGES_INSTALL += $(IPKG_UCLIBC)
endif

ifeq ($(BR2_LIBC_MUSL),y)
MUSL_VERSION:=${shell cat $(STAGING_DIR)/musl_version}
IDIR_MUSL:=$(PKG_BUILD_DIR)/musl
IPKG_MUSL:=$(PACKAGE_DIR)/musl_$(MUSL_VERSION)-$(PKG_RELEASE)_$(ARCH).ipk
PACKAGES += $(IPKG_MUSL)
PACKAGES_INSTALL += $(IPKG_MUSL)
endif

LIBGCC_VERSION:=${shell cat $(STAGING_DIR)/gcc_version}
IDIR_LIBGCC:=$(PKG_BUILD_DIR)/libgcc
IPKG_LIBGCC:=$(PACKAGE_DIR)/libgcc_$(LIBGCC_VERSION)-$(PKG_RELEASE)_$(ARCH).ipk

ifeq ($(BR2_PACKAGE_LIBGCC),y)
PACKAGES+=$(IPKG_LIBGCC)
PACKAGES_INSTALL+=$(IPKG_LIBGCC)
endif
ifeq ($(BR2_PACKAGE_LIBGCC),m)
PACKAGES+=$(IPKG_LIBGCC)
endif

$(PKG_BUILD_DIR)/.prepared:
	mkdir -p $(PKG_BUILD_DIR) $(PACKAGE_DIR)
	touch $@

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	touch $@

$(IPKG_BASE):

ifeq ($(BR2_LIBC_UCLIBC),y)
$(IPKG_UCLIBC):
	$(SCRIPT_DIR)/make-ipkg-dir.sh $(IDIR_UCLIBC) ipkg/uclibc.control $(UCLIBC_VERSION)-$(PKG_RELEASE) $(ARCH)
	mkdir -p $(IDIR_UCLIBC)/lib
	for file in ld*-uClibc libc libcrypt libdl libm libnsl libresolv librt libuClibc libutil; do \
		$(CP) $(STAGING_DIR)/lib/$$file.so.* $(IDIR_UCLIBC)/lib/; \
		$(CP) $(STAGING_DIR)/lib/$$file-$(UCLIBC_VERSION).so $(IDIR_UCLIBC)/lib/; \
	done
	-$(STRIP) $(IDIR_UCLIBC)/lib/*
	$(IPKG_BUILD) $(IDIR_UCLIBC) $(PACKAGE_DIR)
endif

ifeq ($(BR2_LIBC_MUSL),y)
$(IPKG_MUSL):
	$(SCRIPT_DIR)/make-ipkg-dir.sh $(IDIR_MUSL) ipkg/musl.control $(MUSL_VERSION)-$(PKG_RELEASE) $(ARCH)
	mkdir -p $(IDIR_MUSL)/lib
	$(CP) $(STAGING_DIR)/lib/libc.so $(IDIR_MUSL)/lib/
	$(CP) -a $(STAGING_DIR)/lib/ld-musl-* $(IDIR_MUSL)/lib/
	-$(STRIP) $(IDIR_MUSL)/lib/libc.so
	$(IPKG_BUILD) $(IDIR_MUSL) $(PACKAGE_DIR)
endif

$(IPKG_LIBGCC):
	$(SCRIPT_DIR)/make-ipkg-dir.sh $(IDIR_LIBGCC) ipkg/libgcc.control $(LIBGCC_VERSION)-$(PKG_RELEASE) $(ARCH)
	mkdir -p $(IDIR_LIBGCC)/lib
	if [ -e $(STAGING_DIR)/lib64/libgcc_s.so ]; then \
		$(CP) -d $(STAGING_DIR)/lib64/libgcc_s.so* $(IDIR_LIBGCC)/lib/; \
	else \
		$(CP) -d $(STAGING_DIR)/lib/libgcc_s.so* $(IDIR_LIBGCC)/lib/; \
	fi
	-$(STRIP) $(IDIR_LIBGCC)/lib/*
	$(IPKG_BUILD) $(IDIR_LIBGCC) $(PACKAGE_DIR)

package-clean:
	rm -f $(PACKAGES)

clean-targets: package-clean
prepare:
compile-targets: $(PACKAGES)
install-targets: compile
	mkdir -p $(TARGET_DIR)
	$(IPKG) install $(PACKAGES_INSTALL)

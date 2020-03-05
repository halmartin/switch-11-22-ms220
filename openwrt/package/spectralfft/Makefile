# $Id: Makefile for spectralfft.c $

include $(TOPDIR)/rules.mk

PKG_NAME:=spectralfft
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/spectralfft

include $(TOPDIR)/package/rules.mk

COPTS+= -I$(STAGING_DIR)/include -I$(STAGING_DIR)/usr/include
LIBS+= -L$(STAGING_DIR)/lib -L$(STAGING_DIR)/usr/lib
ifeq ($(BR2_PACKAGE_SPECTRALFFT_WITH_FFTW),y)
COPTS+= -DINCLUDE_FFTW=1
LIBS+= -lfftw3
endif
LIBS+= -lm

$(eval $(call PKG_template,SPECTRALFFT,spectralfft,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.prepared:
	mkdir -p $(PKG_BUILD_DIR)
	cp LICENSE-meraki $(PKG_BUILD_DIR)/LICENSE-meraki
	touch $@

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(TARGET_CC) $(TARGET_CFLAGS) $(COPTS) -o $(PKG_BUILD_DIR)/spectralfft spectralfft.c $(LIBS)
	touch $@

$(IPKG_SPECTRALFFT):
	install -d -m0755 $(IDIR_SPECTRALFFT)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/spectralfft $(IDIR_SPECTRALFFT)/usr/bin/
	$(RSTRIP) $(IDIR_SPECTRALFFT)
	$(IPKG_BUILD) $(IDIR_SPECTRALFFT) $(PACKAGE_DIR)

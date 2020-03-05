# $Id: Makefile for motiondetector.c $

include $(TOPDIR)/rules.mk

PKG_NAME:=motiondetector
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/motiondetector

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,MOTIONDETECTOR,motiondetector,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.prepared:
	mkdir -p $(PKG_BUILD_DIR)
	touch $@

$(PKG_BUILD_DIR)/.configured:
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(TARGET_CC) $(TARGET_CFLAGS) -D CROSS_COMPILE -o $(PKG_BUILD_DIR)/motiondetector motiondetector.cc -I$(STAGING_DIR)/usr/include -L$(STAGING_DIR)/usr/lib -lm -lz -lpthread -lavformat -lavcodec -lavutil -lavfilter
	touch $@

$(IPKG_MOTIONDETECTOR):
	install -d -m0755 $(IDIR_MOTIONDETECTOR)/usr/bin
	install -m0755 $(PKG_BUILD_DIR)/motiondetector $(IDIR_MOTIONDETECTOR)/usr/bin/
	$(RSTRIP) $(IDIR_MOTIONDETECTOR)
	$(IPKG_BUILD) $(IDIR_MOTIONDETECTOR) $(PACKAGE_DIR)

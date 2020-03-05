include $(TOPDIR)/rules.mk

PKG_NAME:=ffmpeg
PKG_VERSION:=3.3.2
PKG_RELEASE:=1
PKG_MD5SUM:=e6e3b5f85eb5cb5448501fe4d8ca5bd0

PKG_SOURCE_URL:=https://dl.meraki.net/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_CAT:=bunzip2 -c

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,FFMPEG,$(PKG_NAME),$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

$(PKG_BUILD_DIR)/.configured:
	(cd $(PKG_BUILD_DIR); \
		./configure \
		--enable-cross-compile \
		--cross-prefix=$(TARGET_CROSS) \
		--arch=arm \
		--sysroot=$(STAGING_DIR) \
		--sysinclude=$(STAGING_DIR)/usr/include \
		--target-os=linux \
		--enable-shared \
		--disable-everything \
		--disable-doc \
		--disable-ffprobe \
		--disable-ffplay \
		--enable-demuxer=rtsp,hls,concat \
		--enable-protocol=concat,file \
		--enable-muxer=rtsp,mp4,hls,segment,image2 \
		--enable-parser=aac,h264 \
		--enable-filter=scale \
		--enable-decoder=h264 \
		--enable-encoder=mjpeg \
		--enable-bsf=h264_mp4toannexb \
		--enable-pixelutils \
	);
	touch $@

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR)
	mkdir -p $(STAGING_DIR)/usr/include/libavcodec/
	mkdir -p $(STAGING_DIR)/usr/include/libavdevice/
	mkdir -p $(STAGING_DIR)/usr/include/libavfilter/
	mkdir -p $(STAGING_DIR)/usr/include/libavformat/
	mkdir -p $(STAGING_DIR)/usr/include/libavutil/
	mkdir -p $(STAGING_DIR)/usr/include/libswresample/
	mkdir -p $(STAGING_DIR)/usr/include/libswscale/
	$(CP) $(PKG_BUILD_DIR)/libavcodec/*.h $(STAGING_DIR)/usr/include/libavcodec/
	$(CP) $(PKG_BUILD_DIR)/libavdevice/*.h $(STAGING_DIR)/usr/include/libavdevice/
	$(CP) $(PKG_BUILD_DIR)/libavfilter/*.h $(STAGING_DIR)/usr/include/libavfilter/
	$(CP) $(PKG_BUILD_DIR)/libavformat/*.h $(STAGING_DIR)/usr/include/libavformat/
	$(CP) $(PKG_BUILD_DIR)/libavutil/*.h $(STAGING_DIR)/usr/include/libavutil/
	$(CP) $(PKG_BUILD_DIR)/libswresample/*.h $(STAGING_DIR)/usr/include/libswresample/
	$(CP) $(PKG_BUILD_DIR)/libswscale/*.h $(STAGING_DIR)/usr/include/libswscale/
	mkdir -p $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libavcodec/libavcodec.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libavdevice/libavdevice.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libavfilter/libavfilter.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libavformat/libavformat.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libavutil/libavutil.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libswresample/libswresample.so* $(STAGING_DIR)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/libswscale/libswscale.so* $(STAGING_DIR)/usr/lib/
	touch $@

$(IPKG_FFMPEG):
	install -d -m0755 $(IDIR_FFMPEG)/usr/lib/
	install $(STAGING_DIR)/usr/lib/libavcodec.so* $(IDIR_FFMPEG)/usr/lib/
	install $(STAGING_DIR)/usr/lib/libavdevice.so* $(IDIR_FFMPEG)/usr/lib/
	install $(STAGING_DIR)/usr/lib/libavfilter.so* $(IDIR_FFMPEG)/usr/lib/
	install $(STAGING_DIR)/usr/lib/libavformat.so* $(IDIR_FFMPEG)/usr/lib/
	install $(STAGING_DIR)/usr/lib/libavutil.so* $(IDIR_FFMPEG)/usr/lib/
	install $(STAGING_DIR)/usr/lib/libswresample.so* $(IDIR_FFMPEG)/usr/lib/
	install $(STAGING_DIR)/usr/lib/libswscale.so* $(IDIR_FFMPEG)/usr/lib/
	install -d -m0755 $(IDIR_FFMPEG)/usr/bin/
	$(CP) $(PKG_BUILD_DIR)/ffmpeg $(IDIR_FFMPEG)/usr/bin/ffmpeg
	$(RSTRIP) $(IDIR_FFMPEG)
	$(IPKG_BUILD) $(IDIR_FFMPEG) $(PACKAGE_DIR)

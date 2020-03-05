include $(TOPDIR)/rules.mk

ifeq ($(BR2_LIBC_MUSL),y)

MUSL_VER:=$(subst ",,$(BR2_MUSL_VERSION))
# "
ifeq ($(MUSL_VER),1.1.19)
MUSL_MD5:=399784355ef84d800623ef5e3f51e8b8
else ifeq ($(MUSL_VER),1.1.18)
MUSL_MD5:=5ff5f669dd248f00df77c19f575d2039
else
$(error "No MD5 hash available for this musl version!")
endif

MUSL_DIR:=$(TOOL_BUILD_DIR)/musl-$(MUSL_VER)
MUSL_SOURCE:=musl-$(MUSL_VER).tar.gz
MUSL_CAT:=zcat
MUSL_SITE:=http://dl.meraki.net

MUSL_CFLAGS=$(TARGET_CFLAGS)

$(DL_DIR)/$(MUSL_SOURCE):
	mkdir -p $(DL_DIR)
	$(SCRIPT_DIR)/download.pl $(DL_DIR) $(MUSL_SOURCE) $(MUSL_MD5) $(MUSL_SITE)

$(MUSL_DIR)/.unpacked: $(DL_DIR)/$(MUSL_SOURCE)
	mkdir -p $(TOOL_BUILD_DIR)
	$(MUSL_CAT) $< | tar -C $(TOOL_BUILD_DIR) $(TAR_OPTIONS) -
	if [ -d ./patches/$(MUSL_VER) ]; then \
		$(PATCH) $(MUSL_DIR) ./patches/$(MUSL_VER); \
	fi
	touch $@

$(MUSL_DIR)/.configured: $(MUSL_DIR)/.unpacked
	(cd $(MUSL_DIR); \
		PATH=$(TARGET_PATH) \
		CFLAGS="$(MUSL_CFLAGS)" \
		CROSS_COMPILE=$(TARGET_CROSS) \
		./configure \
		--prefix=/ \
		--enable-debug \
		--disable-wrapper );
	touch $@

$(MUSL_DIR)/lib/libc.a: $(MUSL_DIR)/.configured
	$(MAKE) -C $(MUSL_DIR)

$(STAGING_DIR)/lib/libc.a: $(MUSL_DIR)/lib/libc.a
	$(MAKE) -C $(MUSL_DIR) \
		DESTDIR=$(STAGING_DIR) \
		install
	cp -pLR $(TOOL_BUILD_DIR)/linux/include/* $(STAGING_DIR)/include/ ;
	cp -pLR ./include/* $(STAGING_DIR)/include/
	echo $(MUSL_VER) > $(STAGING_DIR)/musl_version

source: $(DL_DIR)/$(MUSL_SOURCE)
prepare:
compile: $(MUSL_DIR)/lib/libc.a
install: $(STAGING_DIR)/lib/libc.a
clean:
	rm -rf $(MUSL_DIR)


endif

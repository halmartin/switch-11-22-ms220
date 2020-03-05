include $(TOPDIR)/rules.mk

ASN1C_NAME:=asn1c
ASN1C_SITE:=https://dl.meraki.net
ASN1C_VERSION=0.9.27
ASN1C_MD5SUM=e59fb7c79ed69a3a04e02e26b4006355
ASN1C_SOURCE:=$(ASN1C_NAME)-$(ASN1C_VERSION).tar.gz
ASN1C_CAT:=zcat

ASN1C_DIR:=$(TOOL_BUILD_DIR)/$(ASN1C_NAME)-$(ASN1C_VERSION)

$(DL_DIR)/$(ASN1C_SOURCE):
	$(WGET) -P $(DL_DIR) $(ASN1C_SITE)/$(ASN1C_SOURCE)

$(ASN1C_DIR)/.patched: $(DL_DIR)/$(ASN1C_SOURCE)
	$(ASN1C_CAT) $(DL_DIR)/$(ASN1C_SOURCE) | tar -C $(TOOL_BUILD_DIR) $(TAR_OPTIONS) -
	if [ -d ./patches/$(ASN1C_VERSION) ]; then \
		$(PATCH) $(ASN1C_DIR) ./patches/$(ASN1C_VERSION);  \
	fi
	touch $(ASN1C_DIR)/.patched

$(ASN1C_DIR)/.configured: $(ASN1C_DIR)/.patched
	mkdir -p $(ASN1C_DIR)
	(cd $(ASN1C_DIR); \
		CC="$(HOSTCC)" \
		CXX="$(HOSTCXX)" \
		$(ASN1C_DIR)/configure \
		--prefix=$(STAGING_DIR) \
		--build=$(GNU_HOST_NAME) \
		--host=$(GNU_HOST_NAME) \
		--target=$(REAL_GNU_TARGET_NAME) \
		$(DISABLE_NLS) \
	);
	touch  $(ASN1C_DIR)/.configured

$(ASN1C_DIR)/.compiled: $(ASN1C_DIR)/.configured
	$(MAKE) -j4 CC="$(HOSTCC)" CXX="$(HOSTCXX)" -C $(ASN1C_DIR)
	touch $(ASN1C_DIR)/.compiled

$(ASN1C_DIR)/.installed: $(ASN1C_DIR)/.compiled
	$(MAKE) -C $(ASN1C_DIR) install
	touch $@

source: $(DL_DIR)/$(ASN1C_SOURCE)
prepare: $(ASN1C_DIR)/.patched
compile: $(ASN1C_DIR)/.compiled
install: $(ASN1C_DIR)/.installed
clean:
	rm -rf $(ASN1C_DIR)

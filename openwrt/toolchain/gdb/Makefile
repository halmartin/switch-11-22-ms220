# $Id: Makefile 1287 2005-06-26 17:31:18Z nbd $

include $(TOPDIR)/rules.mk

GDB_NAME:=gdb
#GDB_SITE:=http://ftp.gnu.org/gnu/gdb
GDB_SITE:=https://dl.meraki.net
GDB_VERSION=7.11
GDB_MD5SUM=b5c784685e1cde65ba135feea86b6d75
GDB_SOURCE:=$(GDB_NAME)-$(GDB_VERSION).tar.xz
GDB_CAT:=xzcat

GDB_DIR:=$(TOOL_BUILD_DIR)/$(GDB_NAME)-$(GDB_VERSION)

$(DL_DIR)/$(GDB_SOURCE):
	$(WGET) -P $(DL_DIR) $(GDB_SITE)/$(GDB_SOURCE)

$(GDB_DIR)/.patched: $(DL_DIR)/$(GDB_SOURCE)
	$(GDB_CAT) $(DL_DIR)/$(GDB_SOURCE) | tar -C $(TOOL_BUILD_DIR) $(TAR_OPTIONS) -
	if [ -d ./patches/$(GDB_VERSION) ]; then \
		$(PATCH) $(GDB_DIR) ./patches/$(GDB_VERSION);  \
	fi
	touch $(GDB_DIR)/.patched

# gdb client

GDB_CLIENT_DIR:=$(TOOL_BUILD_DIR)/gdbclient-$(GDB_VERSION)

$(GDB_CLIENT_DIR)/.configured: $(GDB_DIR)/.patched
	mkdir -p $(GDB_CLIENT_DIR)
	(cd $(GDB_CLIENT_DIR); \
		gdb_cv_func_sigsetjmp=yes \
		CC="$(HOSTCC)" \
		CXX="$(HOSTCXX)" \
		$(GDB_DIR)/configure \
		--prefix=$(HOST_STAGING_DIR) \
		--build=$(GNU_HOST_NAME) \
		--host=$(GNU_HOST_NAME) \
		--target=$(REAL_GNU_TARGET_NAME) \
		$(DISABLE_NLS) \
		--without-included-gettext \
		--without-python \
		--enable-threads \
		--with-expat \
	);
	touch  $(GDB_CLIENT_DIR)/.configured

$(GDB_CLIENT_DIR)/gdb/gdb: $(GDB_CLIENT_DIR)/.configured
	$(MAKE) -j4 CC="$(HOSTCC)" CXX="$(HOSTCXX)" -C $(GDB_CLIENT_DIR)
	strip $(GDB_CLIENT_DIR)/gdb/gdb

$(TARGET_CROSS)gdb: $(GDB_CLIENT_DIR)/gdb/gdb
	install -c $(GDB_CLIENT_DIR)/gdb/gdb $(TARGET_CROSS)gdb
	cd $(HOST_STAGING_DIR)/bin && \
	ln -fs $(TARGET_CROSS)gdb $(GNU_TARGET_NAME)-gdb

source: $(DL_DIR)/$(GDB_SOURCE)
prepare: $(GDB_DIR)/.patched
compile: 
install: $(TARGET_CROSS)gdb
clean:
	rm -rf $(GDB_CLIENT_DIR) $(GDB_DIR)

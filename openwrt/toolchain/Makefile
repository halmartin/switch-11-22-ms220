# Main makefile for the toolchain
include $(TOPDIR)/rules.mk

ifeq ($(BR2_LIBC_UCLIBC),y)
TARGET_LIBC:=uClibc
else
TARGET_LIBC:=musl
endif

ifeq ($(BR2_PACKAGE_GDB_CLIENT),y)
TARGETS:=sed utils binutils gcc $(TARGET_LIBC) ipkg-utils gdb libnotimpl asn1c
else
TARGETS:=sed utils binutils gcc $(TARGET_LIBC) ipkg-utils libnotimpl asn1c
endif

TARGETS_INSTALL:=$(patsubst %,%-install,$(TARGETS))
TARGETS_CLEAN:=$(patsubst %,%-clean,$(TARGETS))

all: install
install: $(TARGETS_INSTALL)
clean: $(TARGETS_CLEAN)

$(TARGET_LIBC)-prepare: kernel-headers-prepare sed-install utils-install
binutils-prepare: $(TARGET_LIBC)-prepare
gcc-prepare: binutils-install
$(TARGET_LIBC)-compile: gcc-prepare
gcc-compile: $(TARGET_LIBC)-install

TOOLCHAIN_STAMP_DIR:=$(HOST_STAGING_DIR)/stampfiles

$(TOOLCHAIN_STAMP_DIR):
	mkdir -p $(TOOLCHAIN_STAMP_DIR)

$(HOST_STAGING_DIR):
	@mkdir -p $(HOST_STAGING_DIR)
	ln -fs . $(HOST_STAGING_DIR)/usr

$(STAGING_DIR):
	@mkdir -p $(STAGING_DIR)/lib
	@mkdir -p $(STAGING_DIR)/include

$(TOOL_BUILD_DIR):
	@mkdir -p $(TOOL_BUILD_DIR)

%-prepare: $(TOOLCHAIN_STAMP_DIR) $(HOST_STAGING_DIR) $(STAGING_DIR) $(TOOL_BUILD_DIR)
	@[ -f $(TOOLCHAIN_STAMP_DIR)/.toolchain_$@ ] || { \
		$(TRACE) toolchain/$(patsubst %-prepare,%,$@)/prepare; \
		$(MAKE) -C $(patsubst %-prepare,%,$@) prepare $(MAKE_TRACE); \
	}
	@touch $(TOOLCHAIN_STAMP_DIR)/.toolchain_$@

%-compile: %-prepare 
	@[ -f $(TOOLCHAIN_STAMP_DIR)/.toolchain_$@ ] || { \
		$(TRACE) toolchain/$(patsubst %-compile,%,$@)/compile; \
		$(MAKE) -C $(patsubst %-compile,%,$@) compile $(MAKE_TRACE); \
	}
	@touch $(TOOLCHAIN_STAMP_DIR)/.toolchain_$@

%-compile-target: %-prepare
	@[ -f $(TOOLCHAIN_STAMP_DIR)/.toolchain_$@ ] || { \
		$(TRACE) toolchain/$(patsubst %-compile,%,$@)/compile-target; \
		$(MAKE) -C $(patsubst %-compile-target,%,$@) compile-target $(MAKE_TRACE); \
	}
	@touch $(TOOLCHAIN_STAMP_DIR)/.toolchain_$@

%-install: %-compile
	@[ -f $(TOOLCHAIN_STAMP_DIR)/.toolchain_$@ ] || { \
		$(TRACE) toolchain/$(patsubst %-install,%,$@)/install; \
		$(MAKE) -C $(patsubst %-install,%,$@) install $(MAKE_TRACE); \
	}
	@touch $(TOOLCHAIN_STAMP_DIR)/.toolchain_$@

%-clean:
	$(TRACE) toolchain/$(patsubst %-clean,%,$@)/clean
	@$(MAKE) -C $(patsubst %-clean,%,$@) clean $(MAKE_TRACE)
	@rm -f $(TOOLCHAIN_STAMP_DIR)/.toolchain_$(patsubst %-clean,%,$@)-*


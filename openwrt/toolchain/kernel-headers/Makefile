include $(TOPDIR)/rules.mk

# linux kernel headers for toolchain

ifeq ($(BR2_LINUX_VERSION_MAINLINE),)
LINUX_HEADERS_VERSION=-$(BR2_LINUX_VERSION)
endif

LINUX_HEADERS_SOURCE=linux$(LINUX_HEADERS_VERSION).tar.bz2

ifeq ($(KERNEL_VERSION),"2.6.16")
LINUX_HEADERS_ARCH:=$(shell echo $(ARCH) | sed -e 's/i[3-9]86/i386/' \
	-e 's/mipseb/mips/' \
	-e 's/mipsel/mips/' \
	-e 's/sh[234]/sh/' \
	-e 's/armeb/arm/' \
	-e 's/x86_64/x86/' \
	)
else
LINUX_HEADERS_ARCH:=$(shell echo $(ARCH) | sed -e 's/i[3-9]86/x86/' \
	-e 's/mipseb/mips/' \
	-e 's/mipsel/mips/' \
	-e 's/sh[234]/sh/' \
	-e 's/armeb/arm/' \
	-e 's/x86_64/x86/' \
	)
endif

$(DL_DIR)/$(LINUX_HEADERS_SOURCE):
	touch $@ 

$(LINUX_HEADERS_DIR)/.unpacked:
	mkdir -p $(TOOL_BUILD_DIR)
	rm -rf $(TOOL_BUILD_DIR)/linux$(LINUX_HEADERS_VERSION)
ifneq ($(LINUX_HEADERS_VERSION),)
	$(CP) -av $(TOPDIR)/../linux$(LINUX_HEADERS_VERSION) $(TOOL_BUILD_DIR)/linux$(LINUX_HEADERS_VERSION) \
	  | ruby -e 'i=0; while STDIN.gets; i+=1; (STDOUT.write("."); STDOUT.flush) if i % 500 == 0; end; puts'
	mkdir -p $(LINUX_HEADERS_DIR)
ifneq ($(BR2_LINUX_VERSION_2_6_16),y)
	[ ! -d $(TOOL_BUILD_DIR)/linux$(LINUX_HEADERS_VERSION)/include/asm-$(LINUX_HEADERS_ARCH) ] || ( echo include/asm-$(LINUX_HEADERS_ARCH) should not be present in linux source tree ; false )
	$(CP) -r $(TOOL_BUILD_DIR)/linux$(LINUX_HEADERS_VERSION)/arch/$(LINUX_HEADERS_ARCH)/include/asm $(TOOL_BUILD_DIR)/linux$(LINUX_HEADERS_VERSION)/include/asm-$(LINUX_HEADERS_ARCH)
	true #$(SED) 's/@expr length/@-expr length/' $(LINUX_HEADERS_DIR)/Makefile
endif
else
	mkdir -p $(TOOL_BUILD_DIR)/linux
endif
	touch $(LINUX_HEADERS_DIR)/.unpacked

$(LINUX_HEADERS_DIR)/.configured: $(LINUX_HEADERS_DIR)/.unpacked
ifeq ($(BR2_LINUX_VERSION_2_6_16),y)
	-$(CP) ../../target/linux/$(BOARD)$(LINUX_HEADERS_VERSION)/config $(LINUX_HEADERS_DIR)/.config
	$(MAKE) -C $(LINUX_HEADERS_DIR) ARCH=$(LINUX_HEADERS_ARCH) oldconfig include/linux/version.h include/asm 
else
	$(MAKE) -C $(TOPDIR)/../linux$(LINUX_HEADERS_VERSION) ARCH=$(LINUX_HEADERS_ARCH) INSTALL_HDR_PATH=$(LINUX_HEADERS_DIR) headers_install
endif
	touch $(LINUX_HEADERS_DIR)/.configured

source: $(DL_DIR)/$(LINUX_HEADERS_SOURCE)
prepare: $(LINUX_HEADERS_DIR)/.configured
compile:
install:
clean:
	rm -rf $(LINUX_HEADERS_DIR)


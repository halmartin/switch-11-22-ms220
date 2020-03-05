include $(TOPDIR)/rules.mk

TARGETS:=sstrip
UTILS_BUILD_DIR:=$(TOOL_BUILD_DIR)/utils

OS:=$(shell uname)
ifeq ($(OS),Darwin)
CFLAGS += -I./include
endif

define PKG_CONFIG_WRAPPER
#!/bin/bash

export SYSROOT="$(STAGING_DIR)"

export PKG_CONFIG_DIR=
export PKG_CONFIG_LIBDIR=$${SYSROOT}/usr/lib/pkgconfig:$${SYSROOT}/usr/share/pkgconfig
export PKG_CONFIG_SYSROOT_DIR=$${SYSROOT}

exec pkg-config "$$@"
endef

export PKG_CONFIG_WRAPPER

prepare: $(UTILS_BUILD_DIR)
compile: prepare $(patsubst %,$(UTILS_BUILD_DIR)/%,$(TARGETS))
install: compile
	mkdir -p $(HOST_STAGING_DIR)/bin
	echo "$$PKG_CONFIG_WRAPPER" > $(HOST_STAGING_DIR)/bin/$(REAL_GNU_TARGET_NAME)-pkg-config
	chmod 755 $(HOST_STAGING_DIR)/bin/$(REAL_GNU_TARGET_NAME)-pkg-config
	ln -s $(REAL_GNU_TARGET_NAME)-pkg-config $(HOST_STAGING_DIR)/bin/$(GNU_TARGET_NAME)-pkg-config
	$(CP) $(UTILS_BUILD_DIR)/* $(HOST_STAGING_DIR)/bin/
package:
clean:
	rm -rf $(UTILS_BUILD_DIR)

$(UTILS_BUILD_DIR):
	mkdir -p $(UTILS_BUILD_DIR)

$(UTILS_BUILD_DIR)/%: src/%.c
	$(HOSTCC) $(CFLAGS) -o $@ $(patsubst $(UTILS_BUILD_DIR)/%,src/%.c,$@)
	chmod 755 $@


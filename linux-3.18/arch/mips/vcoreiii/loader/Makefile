#
# Makefile for VCore-III boot images
#
# Copyright (c) 2011 Meraki, Inc.
#
# Author: Kevin Paul Herbert <kph@meraki.net>

extra-y := head.o init_luton26.o init_jaguar.o

GCC_MAJOR_GTE5:=$(shell expr `$(CC) -dumpversion | cut -d'.' -f1` \>= 5)

CFLAGS_init_luton26.o += -fPIC -G 65535
CFLAGS_init_jaguar.o += -fPIC -G 65535

ifeq ($(GCC_MAJOR_GTE5),1)
CFLAGS_init_luton26.o += -Wno-error=date-time
CFLAGS_init_jaguar.o += -Wno-error=date-time
endif

LDFLAGS-LOADER = -Ttext=0x0 -T $(srctree)/$(src)/loader.lds

$(obj)/loader.elf: $(obj)/head.o $(obj)/init_luton26.o $(obj)/init_jaguar.o
	$(LD) $(LDFLAGS-LOADER) -o $@ $^

$(obj)/%.bin: $(obj)/%.elf
	$(OBJCOPY) -O binary $< $@

loader.bin: $(obj)/loader.bin

clean:
	rm -f loader.elf loader.bin $(extra-y)

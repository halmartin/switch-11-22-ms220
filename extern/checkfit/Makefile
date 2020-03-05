CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
STRIP=$(CROSS_COMPILE)strip

OBJS = crypto.o image-fit.o image-sig.o main.o fdt_region.o \
	asn1.o bignum.o ecdsa.o ecp.o ecp-curves.o
LIBS = -lcrypto -lz -lfdt
OBJDIR ?= .
TARGET_NAME = checkfit
TARGET = $(OBJDIR)/$(TARGET_NAME)

REAL_OBJS = $(addprefix $(OBJDIR)/,$(OBJS))
REAL_DEPS = $(REAL_OBJS:.o=.d)

DESTDIR=/usr

CFLAGS = -g -std=gnu99

all: $(TARGET)

ifneq ($(MAKECMDGOALS),clean)
-include $(REAL_DEPS)
endif

$(TARGET): $(REAL_OBJS) $(OBJDIR)
	$(CC) $(REAL_OBJS) $(LIBS) -o $@

clean:
	rm -rf $(REAL_OBJS) $(REAL_DEPS) $(TARGET)

depend: $(REAL_DEPS)

install: $(TARGET)
	mkdir -p $(DESTDIR)/bin
	cp $< $(DESTDIR)/bin/$(TARGET_NAME)
	$(STRIP) $(DESTDIR)/bin/$(TARGET_NAME)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c $(OBJDIR)
	$(CC) -c $(CFLAGS) -o $@ $<

$(OBJDIR)/%.d: %.c $(OBJDIR)
	$(CC) -MM -MF $@ $(CFLAGS) $<

.PHONY: all clean


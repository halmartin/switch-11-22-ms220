EXTRA_CFLAGS := -c -I. -I../include  -fexceptions -rdynamic -fPIC -DWITH_SSL -I$(STAGING_DIR)/include
LIBRADIUSBSD_OBJS := radlib.o md5c.o


all: libradiusbsd.so

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

libradiusbsd.so: $(LIBRADIUSBSD_OBJS)
	$(CC) -shared -L$(STAGING_DIR)/usr/lib -lssl -o $@ $^

clean:
	rm -f *.o *.so

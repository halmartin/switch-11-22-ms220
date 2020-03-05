EXTRA_CFLAGS := -c -I. -I../include  -fexceptions -rdynamic -fPIC
LIBUBACKTRACE_OBJS := backtrace.o backtracesyms.o backtracesymsfd.o


all: libubacktrace.so

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^

libubacktrace.so: $(LIBUBACKTRACE_OBJS)
	$(CC) -shared -o $@ $^

clean:
	rm -f *.o *.so

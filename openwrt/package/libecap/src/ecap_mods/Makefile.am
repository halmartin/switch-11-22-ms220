EXTRA_DIST = \
	squid_ssl_sniffer.cc

lib_LTLIBRARIES = \
	squid_ssl_sniffer.la

noinst_HEADERS = \
	sample.h \
	autoconf.h

squid_ssl_sniffer_la_SOURCES = squid_ssl_sniffer.cc
squid_ssl_sniffer_la_LDFLAGS = -module -avoid-version $(libecap_LIBS)

DISTCLEANFILES = \
        autoconf.h

AM_CPPFLAGS = -I$(top_srcdir)/ecap_mods/ $(libecap_CFLAGS)

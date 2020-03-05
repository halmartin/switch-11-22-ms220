amwall-compile: libamsel-compile
arpd-compile: libpcap-compile libdnet-compile libevent-compile
arpwatch-compile: libpcap-compile
atftp-compile: readline-compile ncurses-compile
avahi-compile: libdaemon-compile expat-compile libgdbm-compile
bitchx-compile: ncurses-compile
bitlbee-compile: libiconv-compile openssl-compile glib-compile
blescan-compile: mbluez-compile
busybox-compile: util-linux-compile
cbtt-compile: mysql-compile zlib-compile
clinkc-compile: expat-compile
conntrack-compile: libnetfilter-conntrack-compile
curl-compile: openssl-compile zlib-compile
cyrus-sasl-compile: openssl-compile
deco-compile: ncurses-compile
dhcp6-compile: ncurses-compile
dsniff-compile: libnids-compile openssl-compile libgdbm-compile
e2fsprogs-compile: util-linux-compile
spectralfft-compile: fftw3-compile
flashrom-compile: pciutils-compile
fontconfig-compile: freetype-compile
freetype-compile: zlib-compile
fprobe-compile: libpcap-compile
gdbserver-compile: ncurses-compile
gettext-compile: libiconv-compile
glib2-compile: gettext-compile libffi-compile libpthread-compile
ifeq ($(BR2_PACKAGE_LIBPCRE),y)
glib2-compile: pcre-compile
endif
ifeq ($(BR2_LIBC_MUSL),y)
glib2-compile: libiconv-compile
endif
glib-networking-compile: glib2-compile gnutls-compile intltool-compile
gmediaserver-compile: id3lib-compile libupnp-compile
gnutls-compile: nettle-compile libgcrypt-compile
gpsd-compile: uclibc++-compile
icecast-compile: curl-compile libvorbisidec-compile libxml2-compile libxslt-compile
id3lib-compile: uclibc++-compile zlib-compile
iftop-compile: libpcap-compile libpthread-compile ncurses-compile
ipcad-compile: libpcap-compile
irssi-compile: glib-compile ncurses-compile
iperf-compile: uclibc++-compile
iptables-snmp-compile: net-snmp-compile
iptraf-compile: ncurses-compile
ipsec-tools-compile: openssl-compile libradiusbsd-compile openldap-compile libpam-compile
strongswan-compile: openssl-compile
jamvm-compile: libffi-compile zlib-compile sablevm-classpath-compile
json-glib-compile: glib2-compile
httping-compile: openssl-compile
kismet-compile: uclibc++-compile libpcap-compile ncurses-compile
l2tpns-compile: libcli-compile
less-compile: ncurses-compile
lcd4linux-compile: ncurses-compile
daq-compile: libdnet-compile pcre-compile libpcap-compile
libdirectfb-compile: freetype-compile zlib-compile jpeg-compile libpng-compile
libgcrypt-compile: libgpg-error-compile
libgd-compile: libpng-compile jpeg-compile
libid3tag-compile: zlib-compile
libnet-compile: libpcap-compile
libnetfilter-conntrack-compile: libnfnetlink-compile
libnids-compile: libnet-compile
libsoup-compile: glib2-compile intltool-compile libxml2-compile sqlite-compile
libvorbis-compile: libogg-compile
libxml2-compile: zlib-compile
xmlsec1-compile: libxml2-compile openssl-compile
libxslt-compile: libxml2-compile
lighttpd-compile: openssl-compile pcre-compile
logrotate-compile: popt-compile
madplay-compile: libid3tag-compile libmad-compile
miax-compile: bluez-libs-compile
miredo-compile: uclibc++-compile
monit-compile: openssl-compile
motiondetector-compile: ffmpeg-compile
mt-daapd-compile: howl-compile libgdbm-compile libid3tag-compile
mtr-compile: ncurses-compile
mutt-compile: ncurses-compile openssl-compile
mysql-compile: ncurses-compile zlib-compile readline-compile
nano-compile: ncurses-compile
net-snmp-compile: libelf-compile
nettle-compile: gmp-compile
nfs-server-compile: portmap-compile
nmap-compile: libstdcxx-compile pcre-compile libpcap-compile
cryptsetup-compile: e2fsprogs-compile lvm2-compile popt-compile
hping3-compile: libpcap-compile libpthread-compile
nocatsplash-compile: glib-compile
opencdk-compile: libgcrypt-compile
openh323-compile: pwlib-compile
openl2tp-compile: readline-compile
openldap-compile: cyrus-sasl-compile openssl-compile
openssh-compile: zlib-compile openssl-compile
openssl-compile: zlib-compile
openswan-compile: gmp-compile
osiris-compile: openssl-compile
palantir-compile: jpeg-compile
pciutils-compile: zlib-compile
pcm-compile: libpthread-compile libstdcxx-compile
peercast-compile: uclibc++-compile
peerguardian-compile: libpthread-compile
popt-compile: libgcrypt-compile
portmap-compile: tcp_wrappers-compile
postgresql-compile: zlib-compile
ppp-compile: libpcap-compile
privoxy-compile: pcre-compile
ptunnel-compile: libpcap-compile
pwlib-compile: libpthread-compile
quagga-compile: readline-compile ncurses-compile
raddump-compile: openssl-compile libpcap-compile
radiusclient-ng-compile: openssl-compile
rarpd-compile: libnet-compile
ifneq ($(BR2_PACKAGE_LIBRRD),)
rrdcollect-compile: rrdtool-compile
endif
ifneq ($(BR2_PACKAGE_LIBRRD1),)
rrdcollect-compile: rrdtool1-compile
endif
rrdtool-compile: cgilib-compile freetype-compile libart-compile libpng-compile
rrdtool1-compile: zlib-compile
rsync-compile: popt-compile
rsyslog-compile: liblogging-compile libestr-compile libfastjson-compile gnutls-compile
scanlogd-compile: libpcap-compile libnids-compile libnet-compile
scdp-compile: libnet-compile
screen-compile: ncurses-compile
sipp-compile: ncurses-compile uclibc++-compile libpthread-compile
siproxd-compile: libosip2-compile
sipsak-compile: openssl-compile
socat-compile: openssl-compile
sqlite-compile: ncurses-compile readline-compile
sqlite2-compile: ncurses-compile readline-compile
squid-compile: openssl-compile libstdcxx-compile libecap-compile
sscep-compile: openssl-compile
ssltunnel-compile: openssl-compile ppp-compile
syslog-ng-compile: libol-compile
tcpdump-compile: libpcap-compile
tinc-compile: zlib-compile openssl-compile liblzo-compile
tor-compile: libevent-compile openssl-compile zlib-compile
usbutils-compile: libusb-compile
vim-compile: ncurses-compile
vnc-reflector-compile: jpeg-compile zlib-compile
vpnc-compile: libgcrypt-compile libgpg-error-compile
vtun-compile: zlib-compile openssl-compile liblzo-compile
wificonf-compile: wireless-tools-compile nvram-compile
wiviz-compile: libpcap-compile
wknock-compile: libpcap-compile
wpa_supplicant-compile: openssl-compile
wx200d-compile: postgresql-compile
xsupplicant-compile: openssl-compile
ruby-compile: openssl-compile
ruby-net-ssh-compile: ruby-compile
asterisk-compile: bluez-libs-compile ncurses-compile openssl-compile openh323-compile
ifneq ($(BR2_PACKAGE_ASTERISK_CODEC_SPEEX),)
asterisk-compile: speex-compile
endif
ifneq ($(BR2_PACKAGE_ASTERISK_PGSQL),)
asterisk-compile: postgresql-compile
endif
ifneq ($(BR2_PACKAGE_ASTERISK_MYSQL),)
asterisk-compile: mysql-compile
endif
ifneq ($(BR2_PACKAGE_ASTERISK_SQLITE),)
asterisk-compile: sqlite2-compile
endif

freeradius-compile: libtool-compile openssl-compile
ifneq ($(BR2_PACKAGE_FREERADIUS_MOD_LDAP),)
freeradius-compile: openldap-compile
endif
ifneq ($(BR2_PACKAGE_FREERADIUS_MOD_SQL_MYSQL),)
freeradius-compile: mysql-compile
endif
ifneq ($(BR2_PACKAGE_FREERADIUS_MOD_SQL_PGSQL),)
freeradius-compile: postgresql-compile
endif

freeswitch-compile: ncurses-compile curl-compile readline-compile libpthread-compile pcre-compile gnutls-compile jpeg-compile speex-compile speexdsp-compile sqlite3-compile

hostapd-compile: wireless-tools-compile
ifneq ($(BR2_PACKAGE_HOSTAPD),)
hostapd-compile: openssl-compile
endif

ifneq ($(BR2_PACKAGE_MINI_HTTPD_MATRIXSSL),)
mini_httpd-compile: matrixssl-compile
endif
ifneq ($(BR2_PACKAGE_MINI_HTTPD_OPENSSL),)
mini_httpd-compile: openssl-compile
endif

ifneq ($(BR2_PACKAGE_MOTION),)
motion-compile: jpeg-compile
endif

ifneq ($(BR2_PACKAGE_MPD_MP3),)
mpd-compile: libid3tag-compile libmad-compile
endif
ifneq ($(BR2_PACKAGE_MPD_OGG),)
mpd-compile: libvorbisidec-compile
endif
ifneq ($(BR2_PACKAGE_MPD_FLAC),)
mpd-compile: flac-compile
endif

ifeq ($(BR2_PACKAGE_LIBOPENSSL),y)
openvpn-compile: openssl-compile
endif
ifeq ($(BR2_PACKAGE_OPENVPN_LZO),y)
openvpn-compile: liblzo-compile
endif

php4-compile: openssl-compile zlib-compile
ifneq ($(BR2_PACKAGE_PHP4_MOD_CURL),)
php4-compile: curl-compile
endif
ifneq ($(BR2_PACKAGE_PHP4_MOD_GD),)
php4-compile: libgd-compile libpng-compile
endif
ifneq ($(BR2_PACKAGE_PHP4_MOD_GMP),)
php4-compile: gmp-compile
endif
ifneq ($(BR2_PACKAGE_PHP4_MOD_LDAP),)
php4-compile: openldap-compile
endif
ifneq ($(BR2_PACKAGE_PHP4_MOD_MYSQL),)
php4-compile: mysql-compile
endif
ifneq ($(BR2_PACKAGE_PHP4_MOD_PCRE),)
php4-compile: pcre-compile
endif
ifneq ($(BR2_PACKAGE_PHP4_MOD_PGSQL),)
php4-compile: postgresql-compile
endif
ifneq ($(BR2_PACKAGE_PHP4_MOD_SQLITE),)
php4-compile: sqlite2-compile
endif
ifneq ($(BR2_PACKAGE_PHP4_MOD_XML),)
php4-compile: expat-compile
endif

php5-compile: openssl-compile zlib-compile
ifneq ($(BR2_PACKAGE_PHP5_MOD_CURL),)
php5-compile: curl-compile
endif
ifneq ($(BR2_PACKAGE_PHP5_MOD_GD),)
php5-compile: libgd-compile libpng-compile
endif
ifneq ($(BR2_PACKAGE_PHP5_MOD_GMP),)
php5-compile: gmp-compile
endif
ifneq ($(BR2_PACKAGE_PHP5_MOD_LDAP),)
php5-compile: openldap-compile
endif
ifneq ($(BR2_PACKAGE_PHP5_MOD_MYSQL),)
php5-compile: mysql-compile
endif
ifneq ($(BR2_PACKAGE_PHP5_MOD_PCRE),)
php5-compile: pcre-compile
endif
ifneq ($(BR2_PACKAGE_PHP5_MOD_PGSQL),)
php5-compile: postgresql-compile
endif
ifneq ($(BR2_PACKAGE_PHP5_MOD_SQLITE),)
php5-compile: sqlite2-compile
endif
ifneq ($(BR2_PACKAGE_PHP5_MOD_XML),)
php5-compile: expat-compile
endif

pmacct-compile: libpcap-compile
ifneq ($(BR2_COMPILE_PMACCT_MYSQL),)
pmacct-compile: mysql-compile
endif
ifneq ($(BR2_COMPILE_PMACCT_PGSQL),)
pmacct-compile: postgresql-compile
endif
ifneq ($(BR2_COMPILE_PMACCT_SQLITE),)
pmacct-compile: sqlite-compile
endif

rrs-compile: uclibc++-compile
ifneq ($(BR2_PACKAGE_RRS),)
rrs-compile: openssl-compile
endif

snort-compile: libdnet-compile libpcap-compile pcre-compile
ifeq ($(BR2_PACKAGE_SNORT_WITH_MYSQL),y)
snort-compile: mysql-compile
endif
ifeq ($(BR2_PACKAGE_SNORT_WITH_PGSQL),y)
snort-compile: postgresql-compile
endif
ifeq ($(BR2_PACKAGE_SNORT_ENABLE_INLINE),y)
snort-compile: iptables-compile
endif
ifeq ($(BR2_LIBC_MUSL),y)
snort-compile: libtirpc-compile
endif

snort-compile: daq-compile

snort-wireless-compile: libnet-compile libpcap-compile pcre-compile
ifeq ($(BR2_PACKAGE_SNORT_WIRELESS_WITH_MYSQL),y)
snort-wireless-compile: mysql-compile
endif
ifeq ($(BR2_PACKAGE_SNORT_WIRELESS_WITH_PGSQL),y)
snort-wireless-compile: postgresql-compile
endif
ifeq ($(BR2_PACKAGE_SNORT_WIRELESS_ENABLE_INLINE),y)
snort-wireless-compile: iptables-compile
endif

ulogd-compile: iptables-compile
ifneq ($(BR2_PACKAGE_ULOGD_MOD_MYSQL),)
ulogd-compile: mysql-compile
endif
ifneq ($(BR2_PACKAGE_ULOGD_MOD_PGSQL),)
ulogd-compile: postgresql-compile
endif

wpa_supplicant-compile: base-files-compile

xfont-compile: libfontenc-compile xproto-compile xtrans-compile

libxau-compile: xproto-compile

libxcb-compile: libxau-compile

xlib-compile: kbproto-compile inputproto-compile libxcb-compile xtrans-compile

libxkbfile-compile: xlib-compile

libext-compile: xextproto-compile

pixman-compile: xlib-compile libxcb-compile

xf86-input-keyboard-compile: xorg-server-compile

xf86-input-mouse-compile: xorg-server-compile

xf86-video-fbdev-compile: xorg-server-compile

xorg-server-compile: fontconfig-compile xcmiscproto-compile bigreqsproto-compile fontsproto-compile videoproto-compile xfont-compile libxkbfile-compile libpciaccess-compile libxext-compile renderproto-compile randrproto-compile fixesproto-compile pixman-compile

ifeq ($(BR2_PACKAGE_DMALLOC),y)
busybox-compile: dmalloc-compile
endif

ifneq ($(BR2_PACKAGE_LIBLZMA),)
kexec-tools-compile: liblzma-compile
endif

ifeq ($(BR2_LIBC_MUSL),y)
openl2tp-compile: libtirpc-compile
endif

ifeq ($(BR2_PACKAGE_DNSCRYPT_PROXY),y)
dnscrypt-proxy-compile: libsodium-compile
endif

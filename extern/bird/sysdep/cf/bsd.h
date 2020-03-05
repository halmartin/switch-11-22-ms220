/*
 *	Configuration for *BSD based systems (tested on FreeBSD and NetBSD)
 *
 *	(c) 2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#define CONFIG_AUTO_ROUTES
#define CONFIG_SELF_CONSCIOUS
#define CONFIG_MULTIPLE_TABLES
#define CONFIG_SINGLE_ROUTE

#define CONFIG_SKIP_MC_BIND
#define CONFIG_NO_IFACE_BIND
#define CONFIG_USE_HDRINCL

/*
Link: sysdep/unix
Link: sysdep/bsd
 */

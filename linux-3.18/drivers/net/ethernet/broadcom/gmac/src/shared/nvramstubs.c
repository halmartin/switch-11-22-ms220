/*
 * $Copyright Open Broadcom Corporation$
 *
 * Stubs for NVRAM functions for platforms without flash
 *
 * $Id: nvramstubs.c 325991 2012-04-05 10:16:42Z kenlo $
 */

#include <bcm_cfg.h>
#include <typedefs.h>
#include <bcmutils.h>
#undef strcmp
#define strcmp(s1,s2)	0	/* always match */
#include <bcmnvram.h>

#define FAKE_NVRAM

int
nvram_init(void *sih)
{
	return 0;
}

int
nvram_append(void *sb, char *vars, uint varsz)
{
	return 0;
}

void
nvram_exit(void *sih)
{
}

/* fake nvram tuples */
typedef struct {
	char *name;
	char *value;
} nvram_t;

static nvram_t fake_nvram[] = {
	{"boardtype",		"0x058d"},
	{"boardnum",		"0x010"},
	{"boardrev",		"0x1100"},
	{"boardflags",		"0x710"},
	{"boardflags2",		"0"},
	{"sromrev",		"8"},
	{"clkfreq",		"133,133,133"},
	{"xtalfreq",		"125000"},
	{"et_txq_thresh",	"1024"},
	{"et_rx_rate_limit","1"},
	{"sdram_config",	"0x103"},
	{"swgmacet",		"et2"},
	{"brcmtag",			"1"},
	{"ethaddr",			"00:90:4c:06:a5:72"},
	{"phyaddr",		"1"},
	{"et0phyaddr",		"1"},
#ifdef FOUR_PORT_CONFIG
	{"vlan1hwname",		"et2"},
	{"vlan1ports",		"0 1 2 8*"},
	{"vlan2hwname",		"et2"},
	{"vlan2ports",		"3 8*"},
	{"wanport",			"3"},
#else
	{"vlan1hwname",		"et2"},
	{"vlan1ports",		"0 1 2 3 8*"},
	{"vlan2hwname",		"et2"},
	{"vlan2ports",		"4 8*"},
	{"wanport",			"4"},
#endif
	{"landevs",			"vlan1"},
	{"wandevs",			"et0"},
	{"lan_ipaddr",		"192.168.1.1"},
	{"lan_netmask",		"255.255.255.0"},
	{"boot_wait",		"on"},
	{"wait_time",		"3"},
	{"watchdog",		"0"},
	{"et_msglevel",		"0xFFFFFFFF"}
};
#define fake_nvram_size sizeof(fake_nvram)/sizeof(fake_nvram[0])

#ifndef FAKE_NVRAM

#if defined(CONFIG_MACH_IPROC_P7)
#define CONFIG_SPI_BASE			0xf0000000
#else
#define CONFIG_SPI_BASE			0x1e000000
#endif /* CONFIG_MACH_IPROC_P7 */
#define CONFIG_ENV_OFFSET		0xc0000		/* 30000-b0000 - use last 10000 for env */
#define CONFIG_ENV_SIZE			0x10000 /* 64K */
#define CONFIG_ENV_MAX_ENTRIES	512

#define UBOOT_ENV_ADDR			CONFIG_SPI_BASE+CONFIG_ENV_OFFSET
#define UBOOT_ENV_SIZE			CONFIG_ENV_SIZE
#define UBOOT_ENV_MAX_NUM		CONFIG_ENV_MAX_ENTRIES

static uint8 u_boot_env[UBOOT_ENV_SIZE];
static bool u_boot_env_loaded=false;
static nvram_t env_list[UBOOT_ENV_MAX_NUM];
static int uboot_vars_start = UBOOT_ENV_ADDR;
static int uboot_nvram_max = UBOOT_ENV_SIZE;

/* pass envaddr=<hexvalue eg: 0x1e0a0000> in bootargs */
static int __init envaddr_setup(char *str)
{
	int ret =0;
	unsigned long ul=0;

	ret = kstrtoul(str, 16, &ul);

	if (!ret) {
		uboot_vars_start = ul;
		printk("NVRAM: assign 0x%08x\n", uboot_vars_start);
	}

	return !ret;
}
__setup("envaddr=", envaddr_setup);

/*
APIs for access into uboot env vars
*/

int
nvram_env_init(void)
{
	volatile void *envbuf;
	char *dp, *sp, *name, *value, *dp_end;
	char sep = '\0';
	int idx=0;


	printk("NVRAM: map 0x%08x\n", uboot_vars_start);

	/* map uboot env */
	if ((envbuf = (uint8*)ioremap(uboot_vars_start, UBOOT_ENV_SIZE)) == NULL) {
		printk("%s: ioremap() failed\n", __FUNCTION__);
		return -ENOMEM;
	}

	/* copy memory into buffer */
	memcpy((void*)u_boot_env, (void *) envbuf, uboot_nvram_max);

	/* clear fake entry set */
	memset(env_list, 0, sizeof(env_list));

	/* load uboot fake nvram buffer */
	/* point to first data */
	dp = (char*)u_boot_env;	
	/* point to data buffer */
	dp += 4;
	dp_end = (char*)((uint32)u_boot_env+UBOOT_ENV_SIZE);

	/* point to first data */
	do {
		/* skip leading white space */
		while ((*dp == ' ') || (*dp == '\t')) {
			++dp;
		}

		/* skip comment lines */
		if (*dp == '#') {
			while (*dp && (*dp != sep)) {
				++dp;
			}
			++dp;
			continue;
		}

		/* parse name */
		for (name = dp; *dp != '=' && *dp && *dp != sep; ++dp) {
			;
		}

		*dp++ = '\0';	/* terminate name */

		/* parse value; deal with escapes */
		for (value = sp = dp; *dp && (*dp != sep); ++dp) {
			if ((*dp == '\\') && *(dp + 1)) {
				++dp;
			}
			*sp++ = *dp;
		}
		*sp++ = '\0';	/* terminate value */
		++dp;

		/* enter into hash table */
		env_list[idx].name = name;
		env_list[idx].value = value;
		//printk("entry%d %s=%s\n", idx, name, value);
		idx++;

		/* check if table is full */
		if (idx >= UBOOT_ENV_MAX_NUM ) {
			printk("%s: WARNING - UBoot environment table is full\n", __FUNCTION__);
			break;
		}
		/* check if end of table */
	} while ((dp < dp_end) && *dp);	/* size check needed for text */

	u_boot_env_loaded = true;

	/* unmap uboot env */
	iounmap(envbuf);

	return 0;
}
#endif

int
nvram_env_gmac_name(int gmac, char *name)
{
	int ret=0;
	switch (gmac)
	{
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_SB2) || defined(CONFIG_MACH_GH2))
	case 0:
		strcpy(name, "ethaddr"); 
		break;
	case 1:
		sprintf(name, "eth1addr"); 
		break;
#elif (defined(CONFIG_MACH_HR2) || defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3))
	case 0:
		strcpy(name, "ethaddr"); 
		break;
#endif
	default:
		strcpy(name, "unknown"); 
		ret = -1;
		break;
	}
	return ret;

}

char *
nvram_get(const char *name)
{
	int i, len;
	nvram_t *tuple;
	int num_entries;

	if (!name) {
		return (char *) 0;
	}

	len = strlen(name);
	if (len == 0) {
		return (char *) 0;
	}

#if defined(CONFIG_MACH_SB2) && defined(CONFIG_MACH_IPROC_EMULATION)
  static char macAddr[17];  /* = "d4:ae:52:bc:a5:09" */
  
  if (name[0] == 'e' && name[1] == 't' && name[2] == 'h' && name[3] == 'a' &&
  	  name[4] == 'd' && name[5] == 'd' && name[6] == 'r')
  {
       macAddr[0] = 'd';       macAddr[1] = '4';       macAddr[2] = ':';
       macAddr[3] = 'a';       macAddr[4] = 'e';       macAddr[5] = ':';
       macAddr[6] = '5';       macAddr[7] = '2';       macAddr[8] = ':';
       macAddr[9] = 'b';       macAddr[10] = 'c';      macAddr[11] = ':';
       macAddr[12] = 'a';      macAddr[13] = '5';      macAddr[14] = ':';
       macAddr[15] = '0';      macAddr[16] = '9';
       return((char *)macAddr);
  } /* else if (name[0] == 'e' && name[1] == 't' && name[2] == 'h' && name[3] == '1' &&
  	  name[4] == 'a' && name[5] == 'd' && name[6] == 'd' && name[7] == 'r')
  {
       macAddr[0] = 'd';       macAddr[1] = '5';       macAddr[2] = ':';
       macAddr[3] = 'a';       macAddr[4] = 'e';       macAddr[5] = ':';
       macAddr[6] = '5';       macAddr[7] = '3';       macAddr[8] = ':';
       macAddr[9] = 'b';       macAddr[10] = 'c';      macAddr[11] = ':';
       macAddr[12] = 'a';      macAddr[13] = '6';      macAddr[14] = ':';
       macAddr[15] = '0';      macAddr[16] = 'a';
       return((char *)macAddr);
  } */
#endif

#ifndef FAKE_NVRAM
	tuple = &env_list[0];
	num_entries = sizeof(env_list)/sizeof(nvram_t);

	if (!u_boot_env_loaded) {
		nvram_env_init();
	}

	/* first check the uboot NVRAM variables */
	for (i = 0; i < num_entries; i++) {
		if (tuple->name && (bcmp(tuple->name, name, len) == 0) && (strlen(tuple->name)==len)) {
			/*printf("%s (NVRAM) %s: %s\n", __FUNCTION__, name, tuple->value);*/
			return tuple->value;
		}
		tuple++;
	}
#endif

	/* if cant find then check fake table above */
	tuple = &fake_nvram[0];
	num_entries = fake_nvram_size;
	for (i = 0; i < num_entries; i++) {
		if (tuple->name && (bcmp(tuple->name, name, len) == 0) && (strlen(tuple->name)==len)) {
			/*printf("%s (STUBS) %s: %s\n", __FUNCTION__, name, tuple->value);*/
			return tuple->value;
		}
		tuple++;
	}

	return (char *) 0;
}

int
nvram_set(const char *name, const char *value)
{
	return 0;
}

int
nvram_unset(const char *name)
{
	return 0;
}

int
nvram_commit(void)
{
	return 0;
}

int
nvram_getall(char *buf, int count)
{
	/* add null string as terminator */
	if (count < 1) {
		return BCME_BUFTOOSHORT;
	}
	*buf = '\0';
	return 0;
}

static int __init iproc_nvram_init(void)
{
#ifndef FAKE_NVRAM
	nvram_env_init();
#endif
	return 0;
}

#include <asm/mach-vcoreiii/hardware.h>

/*
 * read_mii - Low level MII read access
 *
 * Low level read routine. Helper only. Do not use directly, does
 * not lock access to chip nor deal with paging registers.
 */

static int32_t
read_mii(uint16_t controller, uint16_t phy_addr, uint16_t reg_addr)
{
	uint32_t val;

	/*
	 * Issue the read operation to the controller
	 */

	slv_writel(VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_OPR_FIELD(3) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_VLD |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_REGAD(reg_addr) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_PHYAD(phy_addr),
	       VTSS_DEVCPU_GCB_MIIM_MII_CMD(controller));

	/*
	 * Wait for the busy flag to be cleared
	 */

	do {
		val = slv_readl(VTSS_DEVCPU_GCB_MIIM_MII_STATUS(controller));
	} while (val & VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_BUSY);

	/*
	 * Read the result register.
	 */
	val = slv_readl(VTSS_DEVCPU_GCB_MIIM_MII_DATA(controller));

	/*
	 * Return an error or the value
	 */

	if (val & VTSS_F_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_SUCCESS(3))
		return -1;

	/*
	 * Success, return the value
	 */

	return val & 0xffff;
}

/*
 * write_mii - Low level MII write access
 *
 * Low level write routine. Helper only. Do not use directly, does
 * not lock access to chip nor deal with paging register.
 */

static void
write_mii(uint16_t controller, uint16_t phy_addr, uint16_t reg_addr,
	  uint16_t data)
{
	uint32_t val;

	/*
	 * Issue the write operation to the controller
	 */

	slv_writel(VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_OPR_FIELD(1) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_WRDATA(data) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_VLD |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_REGAD(reg_addr) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_PHYAD(phy_addr),
	       VTSS_DEVCPU_GCB_MIIM_MII_CMD(controller));

	/*
	 * Wait for the busy flag to be cleared
	 */

	do {
		val = slv_readl(VTSS_DEVCPU_GCB_MIIM_MII_STATUS(controller));
	} while (val & VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_BUSY);
}

/*
 * address_mii - Low level MII address set (Clause 45 operation)
 *
 * Low level address routine. Helper only. Do not use directly,
 * does not lock access to chip.
 */

static void address_mii(uint16_t controller, uint16_t phy_addr,
			uint16_t reg_addr, uint16_t data)
{
	uint32_t val;

	/*
	 * Issue the write operation to the controller
	 */

	slv_writel(VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_OPR_FIELD(0) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_WRDATA(data) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_VLD |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_REGAD(reg_addr) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_PHYAD(phy_addr),
	       VTSS_DEVCPU_GCB_MIIM_MII_CMD(controller));

	/*
	 * Wait for the busy flag to be cleared
	 */

	do {
		val = slv_readl(VTSS_DEVCPU_GCB_MIIM_MII_STATUS(controller));
	} while (val & VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_BUSY);
}

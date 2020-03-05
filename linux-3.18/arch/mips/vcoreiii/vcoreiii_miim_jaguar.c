#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include "vcoreiii_miim_phy8488.h"

static int32_t
read_phy(uint16_t controller, uint16_t phy_addr, uint16_t page,
	 uint16_t reg_addr)
{
	int32_t val;

	vcoreiii_api_lock(__func__);	/* Lock the controller */

	address_mii(controller, phy_addr, page, reg_addr);

	val = read_mii(controller, phy_addr, page); /* Read register */

	vcoreiii_api_unlock(__func__);	/* Unlock controller */

	return val;
}

static void
write_phy_masked(uint16_t controller, uint16_t phy_addr, uint16_t page,
		 uint16_t reg_addr, uint16_t data, uint16_t mask)
{
	int32_t old_val = 0;

	vcoreiii_api_lock(__func__);	/* Lock the controller */

	address_mii(controller, phy_addr, page, reg_addr);

	if (mask != 0xffff)
		old_val = read_mii(controller, phy_addr, page) &
			~mask;	/* Get the old value, masked */

	if (old_val >= 0)
		write_mii(controller, phy_addr, page, (data & mask) | old_val);

	vcoreiii_api_unlock(__func__);	/* Unlock controller */
}

int jaguar_phy8488_read(uint16_t controller, uint16_t phy_addr,
			uint16_t reg_addr, uint16_t address)
{
	return read_phy(controller, phy_addr, reg_addr, address);
}

void jaguar_phy8488_write_masked(uint16_t controller, uint16_t phy_addr,
				 uint16_t reg_addr, uint16_t address,
				 uint16_t data, uint16_t mask)
{
	write_phy_masked(controller, phy_addr, reg_addr, address, data, mask);
}

extern int jaguar_phy8488_read(uint16_t controller, uint16_t phy_addr,
			       uint16_t reg_addr, uint16_t address);
extern void jaguar_phy8488_write_masked(uint16_t controller, uint16_t phy_addr,
					uint16_t reg_addr, uint16_t address,
					uint16_t data, uint16_t mask);

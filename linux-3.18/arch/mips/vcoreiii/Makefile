#
# Makefile for the VCore-III reference boards
#

obj-y := vcoreiii_setup.o vcoreiii_irq.o vcoreiii_platform.o \
	vcoreiii_prom.o vcoreiii_mtd.o vcoreiii_gpio.o

obj-$(CONFIG_VTSS_VCOREIII_SGPIO) += vcoreiii_sgpio.o

obj-$(CONFIG_VTSS_VCOREIII_JAGUAR) += vcoreiii_irq_jaguar.o
obj-$(CONFIG_VTSS_VCOREIII_JAGUAR) += vcoreiii_mtd_jaguar.o
obj-$(CONFIG_VTSS_VCOREIII_JAGUAR) += vcoreiii_setup_jaguar.o
obj-$(CONFIG_VTSS_VCOREIII_JAGUAR) += vcoreiii_wdt_jaguar.o
obj-$(CONFIG_VTSS_VCOREIII_JAGUAR) += vcoreiii_miim_jaguar.o

ifeq ($(CONFIG_VTSS_VCOREIII_JAGUAR),y)
obj-$(CONFIG_VTSS_VCOREIII_PHY8488_GPIO) += vcoreiii_gpio_phy8488_jaguar.o
obj-$(CONFIG_VTSS_VCOREIII_PHY8512_GPIO) += vcoreiii_gpio_phy8512_jaguar.o
obj-$(CONFIG_THERMAL) += vcoreiii_thermal_jaguar.o
endif

obj-$(CONFIG_VTSS_VCOREIII_JAGUAR_DUAL) += vcoreiii_setup_jaguar_slv.o
obj-$(CONFIG_VTSS_VCOREIII_JAGUAR_DUAL) += vcoreiii_irq_jaguar_slv.o
obj-$(CONFIG_VTSS_VCOREIII_JAGUAR_DUAL) += vcoreiii_gpio_jaguar_slv.o

ifeq ($(CONFIG_VTSS_VCOREIII_JAGUAR_DUAL),y)
obj-$(CONFIG_VTSS_VCOREIII_PHY8488_GPIO) += vcoreiii_gpio_phy8488_jaguar_slv.o
obj-$(CONFIG_VTSS_VCOREIII_PHY8512_GPIO) += vcoreiii_gpio_phy8512_jaguar_slv.o
endif

obj-$(CONFIG_VTSS_VCOREIII_LUTON26) += vcoreiii_irq_luton26.o
obj-$(CONFIG_VTSS_VCOREIII_LUTON26) += vcoreiii_mtd_luton26.o
obj-$(CONFIG_VTSS_VCOREIII_LUTON26) += vcoreiii_setup_luton26.o
obj-$(CONFIG_VTSS_VCOREIII_LUTON26) += vcoreiii_wdt_luton26.o

ifeq ($(CONFIG_VTSS_VCOREIII_LUTON26),y)
obj-$(CONFIG_VTSS_VCOREIII_PHY8512_GPIO) += vcoreiii_gpio_phy8512_luton26.o
endif

EXTRA_CFLAGS += -Werror

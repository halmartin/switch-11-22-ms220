/*
 *
 * VCore-III ROM Loader
 *
 * Copyright (C) 2011 Meraki, Inc.
 * Author: Kevin Paul Herbert <kph@meraki.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <asm/asm.h>
#include <asm/regdef.h>
#include <asm/mipsregs.h>
#include <asm/addrspace.h>

#define STACK_BASE ((KSEG0 + 0x4000) - 32) /* Stack 16KiB in memory */
#define INITIAL_SR 0x0000ff00		   /* Enable but mask all interrupts */
#define INITIAL_CONFIG 0x3		/* KSEG0 cached */

#define LOADER_MAGIC 0x4d495053
#define LOADER_SIZE  0x00040000		/* Size of memory allocated to loader */
#define LOADER_MASK ~(LOADER_SIZE-1)
#define PAYLOAD_SIZE 0x003c0000		/* Size of memory allocated to payload */
#define REGION_SIZE (LOADER_SIZE + PAYLOAD_SIZE)
#define REGION_MASK ~(REGION_SIZE-1)

#define REASON_STARTUP 		0		/* Power up */
#define REASON_TLB		1		/* TLB exception */
#define REASON_CACHE		2		/* Cache error */
#define REASON_EXCEPTION 	3		/* Assorted exception */
#define REASON_INTERRUPT	4		/* Unexpected interrupt */
#define REASON_INITFAILED	5		/* Initialization failed */
#define REASON_PAYLOAD		6		/* Payload is bad */
#define REASON_PAYLOAD_ERROR	7		/* Payload declared error */

	.set	noreorder

__start:bal	10f		/* Figure out where we are */
	 nop			/* Keep branch delay slot empty */

	/* Raw startup - no stack, no RAM, running uncached in KSEG1,
	 * with the machine in boot mode. */

10:	sub	gp, ra, 8	      /* Set GP to our execution address */
	mtc0	zero, CP0_WATCHLO, 0 /* Clear watchpoint low 0 */
	mtc0	zero, CP0_WATCHHI, 0 /*  and watchpoint high 0 */
	mtc0	zero, CP0_WATCHLO, 1 /* Clear watchpoint low 1 */
	mtc0	zero, CP0_WATCHHI, 1 /*  and watchpoint high 1 */
	mtc0	zero, CP0_WATCHLO, 2 /* Clear watchpoint low 2 */
	mtc0	zero, CP0_WATCHHI, 2 /*  and watchpoint high 2 */
	mtc0	zero, CP0_WATCHLO, 3  /* Clear watchpoint low 3 */
	mtc0	zero, CP0_WATCHHI, 3 /*  and watchpoint high 3 */
	mtc0	zero, CP0_CAUSE	/* Clear any pending cause */
	li	t0, INITIAL_CONFIG /* Get initial config */
	mtc0	t0, CP0_CONFIG	/* and set it */
	li	t0, INITIAL_SR	/* Get the initial status */
	mtc0	t0, CP0_STATUS	/*  and set it */
	ehb			/* Avoid any hazards */
	bal	init_system_jaguar1 /* Attempt to initialize system */
	 move	a0, k0		/* Pass the reason */
	bnez	v0, 20f		/* It is a jaguar1, machine initialized */
	 move	a0, k0		/* Get reason code back */

	bal	init_system_luton26 /* Try luton 26 */
	 nop
	bnez	v0, 20f		/* Worked, great */
	 li	k0, REASON_INITFAILED /* Set up error code */
	b	loader_fail	/* Unable to initialize */
	 nop			/* Just loop */

20:
	/* Cache is working, RAM is working, SPI Flash is mapped at
	 * 0x40000000, DRAM is mapped cached at 0x20000000. Still in
	 * boot mode. Set up stack, continue executing from mapped SPI.
	 *
	 * v0 = Address to get us out of boot mode
	 */

	PTR_LI	sp, STACK_BASE  /* Set up a stack in DRAM */
	move	fp, sp		/* Set up initial frame pointer */
	lw	t0, 0(v0)	/* Are we in boot mode? */
	beqz	t0, 30f		/* No, so continue as we are */
	 nop
	bal	boot_mode_trampoline /* Come back at 4xxxxxxx */
	 nop

	/*
	 * When boot_mode_trampoline returns, we will be executing
	 * at our 4xxxxxxx address.
	 */

	sw	zero, 0(v0)	/* Get ready to take us out of boot mode */
	lw	zero, 0(v0)	/* Now take us out of boot mode */

/*
 * crc32 calculator macro. Input is in any register.
 *   a2 -> crc table
 *   s0 =  crc accumulator
 *
 * Uses: t6, t7, t8
 */

	.macro crc32 reg
	ext	t6, \reg, 0, 8	/* t6 = first 8 bits */
	xor	t6, t6, s0	/* incorporate crc so far */
	andi	t6, t6, 0xff	/* Save only low 8 bits */
	sll	t6, t6, 2	/* turn into an index in the table */
	add	t8, a2, t6	/* t8 -> crc table entry */
	lw	t7, 0(t8)	/* t7 = crc for first byte */
	srl	s0, s0, 8	/* Update accumulator while load runs */

	ext	t6, \reg, 8, 8	/* t6 = next 8 bits */
	xor	s0, s0, t7	/* s0 = crc including bits [0-7] */
	xor	t6, t6, s0	/* incorporate crc so far */
	andi	t6, t6, 0xff	/* Save only low 8 bits */
	sll	t6, t6, 2	/* turn into an index in the table */
	add	t8, a2, t6	/* t8 -> crc table entry */
	lw	t7, 0(t8)	/* t7 = crc for second byte */
	srl	s0, s0, 8	/* Update accumulator while load runs */

	ext	t6, \reg, 16, 8	/* t6 = next 8 bits */
	xor	s0, s0, t7	/* s0 = crc including bits [8-15] */
	xor	t6, t6, s0	/* incorporate crc so far */
	andi	t6, t6, 0xff	/* Save only low 8 bits */
	sll	t6, t6, 2	/* turn into an index in the table */
	add	t8, a2, t6	/* t8 -> crc table entry */
	lw	t7, 0(t8)	/* t7 = crc for second byte */
	srl	s0, s0, 8	/* Update accumulator while load runs */

	ext	t6, \reg, 24, 8	/* t6 = next 8 bits */
	xor	s0, s0, t7	/* s0 = crc including bits [16-23] */
	xor	t6, t6, s0	/* incorporate crc so far */
	andi	t6, t6, 0xff	/* Save only low 8 bits */
	sll	t6, t6, 2	/* turn into an index in the table */
	add	t8, a2, t6	/* t8 -> crc table entry */
	lw	t7, 0(t8)	/* t7 = crc for second byte */
	srl	s0, s0, 8	/* Update accumulator while load runs */
	xor	s0, s0, t7	/* Now we have the CRC for 32 bits */
.endm

30:	li	a1, LOADER_SIZE	/* Get loader size */
	add	a0, a1, gp	/* Round up to payload area */
	li	a1, LOADER_MASK /* Get loader mask */
	and	a0, a0, a1	/* a0 -> start of payload */

	lw	t0, 0(a0)	/* Load the magic number */
	li	t1, LOADER_MAGIC /* And what we expect */
	bne	t0, t1, 50f	/* If not the right magic, get out */
	 lw	a1, 4(a0)	/* Get address to move kernel to */
	lw	v0, 8(a0)	/* Get length of data to move */
	lw	a3, 12(a0)	/* Get entry point */
	lw	s1, 16(a0)	/* Get expected CRC */

	li	t0, PAYLOAD_SIZE /* Get the maximum payload size */
	subu	t0, t0, v0	/* Is the payload too big? */
	bltz	t0, 50f		/* Yes, don't try to load it */
	 move	t0, a1		/* No, copy load address */
	srl	t0, t0, 28	/* Isolate only top 4 bits */
	li	t2, 8		/* Code must begin at 8xxxxxxx */
	bne	t0, t2, 50f	/* Don't try to load this */

	lui	a2, %hi(crctab) /* Get CRC table msb */
	ori	a2, %lo(crctab) /* Get CRC table lsb */
	add	a2, a2, gp	/* a2 = crc table (PIC) */
	lui	s0, 0xffff	/* initialize crc accumulator */
	ori	s0, 0xffff	/* s0 = crc accumulator */

/*
 * The CRC is calculated over the header fields, with the initial CRC
 * field set to zero.
 */

	crc32	t1		/* magic */
	crc32	a1		/* load_addr */
	crc32	v0		/* size */
	crc32	a3		/* entry point */
	crc32	zero		/* CRC, initially zero */
	lw	t0, 20(a0)	/* Fetch reserved words */
	lw	t1, 24(a0)
	lw	t2, 28(a0)
	addi	a0, 32		/* Point past the header */
	crc32	t0		/* Include reserved words in CRC */
	crc32	t1
	crc32	t2

/*
 * CRC calculator
 *   a0 -> input data to move (from ROM)
 *   a1 -> output data (in RAM)
 *   a2 -> crc table
 *   a3 -> entry point of final image
 *   v0 =  byte count to move
 *   s0 =  CRC accumulator
 *   s1 =  CRC from header
 */

40:	lw	t0, 0(a0)	/* Get four reads in flight */
	lw	t1, 4(a0)
	lw	t2, 8(a0)
	lw	t3, 12(a0)
	crc32	t0		/* Calculate CRC32 hopefully from cache */
	crc32	t1		/* ... */
	sub	v0, v0, 32	/* Update length */
	lw	t4, 16(a0)	/* Get two more reads in flight */
	lw	t5, 20(a0)
	crc32	t2
	crc32	t3
	sw	t0, 0(a1)	/* Store two words */
	sw	t1, 4(a1)
	lw	t0, 24(a0)	/* Get two more reads in flight */
	lw	t1, 28(a0)
	crc32	t4
	crc32	t5
	add	a0, a0, 32	/* Update source pointer */
	add	a1, a1, 32	/* Update destination pointer */
	sw	t2, -24(a1)	/* Get six stores in flight */
	sw	t3, -20(a1)
	sw	t4, -16(a1)
	sw	t5, -12(a1)
	crc32	t0
	crc32	t1
	sw	t0,  -8(a1)
	sw	t1,  -4(a1)
	pref	0, 8*32(a0)	/* Hint about our read prefetch */
	pref	1, 8*32(a1)	/* Hint about our write prefetch */
	bgtz	v0, 40b		/* Now loop until we are done */
	 nop

	xor	s0, s0, s1	/* xor the result with the expected */
	addi	s0, 1		/*  ..add one, should be zero */
	bnez	s0, 50f		/* It is not, error */
	 move	t0, a3		/* Save kernel entry point */
	lui	a0, 0		/* Clear a0 */
	lui	a1, 0		/*  ...  a1 */
	lui	a2, 0
	jalr	t0		/* Go run the kernel */
	 lui	a3, 0

	li	k0, REASON_PAYLOAD_ERROR
	b	loader_fail	/* We failed */
	 nop

50:	li	k0, REASON_PAYLOAD /* Set up the error code */

loader_fail:
	li	t0, REGION_SIZE /* Get our region size */
	add	t1, t0, gp	/* Point into next region */
	li	t0, REGION_MASK /* Get the payload mask */
	and	t1, t1, t0	/* Now get the start of next region */
	jalr	t1		/* Now go there */

	/*
	 * We are built PIC, so that the loader updater can put us
	 * anywhere. When we are started in boot mode, we are running
	 * from Axxxxxxx addresses (KSEG0, uncached). We do a relative
	 * branch here which gives us a return address in ra. We
	 * modify the return address by masking the top 4 bits and
	 * adding 0x4000000. Note that we could just bias the return
	 * address by the proper amount, but masking works whether
	 * we are run at 8xxxxxxx or Axxxxxxx.
	 */

boot_mode_trampoline:
	lui	t1, 0x0fff	/* Get ready to mask top 4 bits */
	ori	t1, t1, 0xffff	/* Get 0x0fffffff as a mask */
	and	ra, ra, t1	/* Get our flash load offset */
	and	gp, gp, t1	/* Turn our GP to an offset as well */
	lui	t1, 0x4000	/* Get ready to execute code at 4xxxxxxx */
	add	ra, ra, t1	/* Now we have 4xxxxxxx based start */
	add	gp, gp, t1	/* and a 4xxxxxxx based gp */
	jr	ra		/* Continue at 4xxxxxxx */
	 nop

crctab:
	.word 0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419
	.word 0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4
	.word 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07
	.word 0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de
	.word 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856
	.word 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9
	.word 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4
	.word 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b
	.word 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3
	.word 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a
	.word 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599
	.word 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924
	.word 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190
	.word 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f
	.word 0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e
	.word 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01
	.word 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed
	.word 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950
	.word 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3
	.word 0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2
	.word 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a
	.word 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5
	.word 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010
	.word 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f
	.word 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17
	.word 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6
	.word 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615
	.word 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8
	.word 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344
	.word 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb
	.word 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a
	.word 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5
	.word 0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1
	.word 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c
	.word 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef
	.word 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236
	.word 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe
	.word 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31
	.word 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c
	.word 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713
	.word 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b
	.word 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242
	.word 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1
	.word 0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c
	.word 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278
	.word 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7
	.word 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66
	.word 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9
	.word 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605
	.word 0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8
	.word 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b
	.word 0x2d02ef8d

	.ascii	"LinuxLoader VCoreIII"

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR
	.ascii	" VSC7434"
#endif

#ifdef CONFIG_VTSS_VCOREIII_LUTON26
	.ascii	" VSC7427"
#endif

	.align	4

.global __start

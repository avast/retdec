/**
 * @file include/retdec/capstone2llvmir/mips/mips_defs.h
 * @brief Additional (on top of Capstone) definitions for MIPS translator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_MIPS_MIPS_DEFS_H
#define RETDEC_CAPSTONE2LLVMIR_MIPS_MIPS_DEFS_H

/**
 * 64-bit double precision floating point registers used on 32-bit systems
 * to represent floating point regiters pairs.
 * e.g. MIPS_REG_FD4 = (MIPS_REG_F4, MIPS_REG_F5)
 * In HW, there is only one register array, but it would be very hard and ugly
 * to model 64-bit operations on 2x32-bit pairs.
 */
enum mips_reg_fpu_double
{
	MIPS_REG_FD0 = MIPS_REG_ENDING + 1,
	MIPS_REG_FD2,
	MIPS_REG_FD4,
	MIPS_REG_FD6,
	MIPS_REG_FD8,
	MIPS_REG_FD10,
	MIPS_REG_FD12,
	MIPS_REG_FD14,
	MIPS_REG_FD16,
	MIPS_REG_FD18,
	MIPS_REG_FD20,
	MIPS_REG_FD22,
	MIPS_REG_FD24,
	MIPS_REG_FD26,
	MIPS_REG_FD28,
	MIPS_REG_FD30,
};

#endif

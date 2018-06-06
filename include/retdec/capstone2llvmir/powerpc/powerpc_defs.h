/**
 * @file include/retdec/capstone2llvmir/powerpc/powerpc_defs.h
 * @brief Additional (on top of Capstone) definitions for PowerPC translator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_POWERPC_POWERPC_DEFS_H
#define RETDEC_CAPSTONE2LLVMIR_POWERPC_POWERPC_DEFS_H

enum ppc_reg_cr_flags
{
	/// Negative -- set when result is negative.
	PPC_REG_CR0_LT = PPC_REG_ENDING + 1,
	/// Positive -- set when result is positive and not zero.
	PPC_REG_CR0_GT,
	/// Zero -- set when result is zero
	PPC_REG_CR0_EQ,
	/// Copy of the final state of XER[SO] at the completion of the instruction.
	PPC_REG_CR0_SO,

	PPC_REG_CR1_LT,
	PPC_REG_CR1_GT,
	PPC_REG_CR1_EQ,
	PPC_REG_CR1_SO,

	PPC_REG_CR2_LT,
	PPC_REG_CR2_GT,
	PPC_REG_CR2_EQ,
	PPC_REG_CR2_SO,

	PPC_REG_CR3_LT,
	PPC_REG_CR3_GT,
	PPC_REG_CR3_EQ,
	PPC_REG_CR3_SO,

	PPC_REG_CR4_LT,
	PPC_REG_CR4_GT,
	PPC_REG_CR4_EQ,
	PPC_REG_CR4_SO,

	PPC_REG_CR5_LT,
	PPC_REG_CR5_GT,
	PPC_REG_CR5_EQ,
	PPC_REG_CR5_SO,

	PPC_REG_CR6_LT,
	PPC_REG_CR6_GT,
	PPC_REG_CR6_EQ,
	PPC_REG_CR6_SO,

	PPC_REG_CR7_LT,
	PPC_REG_CR7_GT,
	PPC_REG_CR7_EQ,
	PPC_REG_CR7_SO,
};

enum ppc_cr_types
{
	PPC_CR_LT,
	PPC_CR_GT,
	PPC_CR_EQ,
	PPC_CR_SO,
};

#endif

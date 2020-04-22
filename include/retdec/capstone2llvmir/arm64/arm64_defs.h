/**
 * @file include/retdec/capstone2llvmir/arm64/arm64_defs.h
 * @brief Additional (on top of Capstone) definitions for ARM64 translator.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_ARM64_ARM64_DEFS_H
#define RETDEC_CAPSTONE2LLVMIR_ARM64_ARM64_DEFS_H

#include <capstone/arm64.h>

enum arm64_reg_cpsr_flags
{
	ARM64_REG_CPSR_N = ARM64_REG_ENDING + 1,
	ARM64_REG_CPSR_Z,
	ARM64_REG_CPSR_C,
	ARM64_REG_CPSR_V,
	ARM64_REG_PC,
};

#endif /* RETDEC_CAPSTONE2LLVMIR_ARM64_ARM64_DEFS_H */

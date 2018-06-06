/**
 * @file include/retdec/capstone2llvmir/arm/arm_defs.h
 * @brief Additional (on top of Capstone) definitions for ARM translator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_ARM_ARM_DEFS_H
#define RETDEC_CAPSTONE2LLVMIR_ARM_ARM_DEFS_H

#include <capstone/arm.h>

enum arm_reg_cpsr_flags
{
	ARM_REG_CPSR_N = ARM_REG_ENDING + 1,
	ARM_REG_CPSR_Z,
	ARM_REG_CPSR_C,
	ARM_REG_CPSR_V,
};

#endif

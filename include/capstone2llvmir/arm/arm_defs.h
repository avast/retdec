/**
 * @file include/capstone2llvmir/arm/arm_defs.h
 * @brief Definitions for ARM implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_ARM_ARM_DEFS_H
#define CAPSTONE2LLVMIR_ARM_ARM_DEFS_H

#include <capstone/arm.h>

namespace capstone2llvmir {

enum arm_reg_cpsr_flags
{
	ARM_REG_CPSR_N = ARM_REG_ENDING + 1,
	ARM_REG_CPSR_Z,
	ARM_REG_CPSR_C,
	ARM_REG_CPSR_V,
};

} // namespace capstone2llvmir

#endif

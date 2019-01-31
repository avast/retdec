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

/**
 * The problem: ARM uses two sets of registers (two enums), ordinary registers
 * (enum arm_reg) and system registers (enum arm_sysreg).
 * Most system registers have enum numbers greater than 256 - these numbers do
 * not overlap with ordinary register numbers.
 * But 8 registers from arm_sysreg overlap with ordinary registers.
 * These are SPSR and CPSR related registers.
 * We cannot use these Capstone enums, since they would collide in our maps with
 * ordinary registers.
 * Moreover, these 8 registers denote flag registers and can be OR combined.
 * Therefore, if we wanted to capture their full semantics, we would either have
 * to create registers for all combinations (e.g. C, X, S, F, CX, CS, CF, XS,
 * XF, SF, CXS, ...) and use appropriate variant depending on asm instruction
 * as Capstone/IDA does (e.g. msr cpsr_fc, r6), or simulate this on a single
 * register using bit setting (i.e. and/or operations).
 * Instead, we ignore work with individual flags - we create only two registers
 * and use them every time any flag is modified.
 */
enum arm_sysreg_extension
{
	ARM_SYSREG_SPSR = ARM_REG_CPSR_V + 1,
	ARM_SYSREG_CPSR,
};

#endif

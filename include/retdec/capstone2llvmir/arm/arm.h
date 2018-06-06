/**
 * @file include/retdec/capstone2llvmir/arm/arm.h
 * @brief ARM specialization of translator's abstract public interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_ARM_ARM_H
#define RETDEC_CAPSTONE2LLVMIR_ARM_ARM_H

#include "retdec/capstone2llvmir/arm/arm_defs.h"
#include "retdec/capstone2llvmir/capstone2llvmir.h"

namespace retdec {
namespace capstone2llvmir {

/**
 * ARM specialization of translator's abstract public interface.
 */
class Capstone2LlvmIrTranslatorArm : virtual public Capstone2LlvmIrTranslator
{
	public:
		virtual ~Capstone2LlvmIrTranslatorArm() {};
};

} // namespace capstone2llvmir
} // namespace retdec

#endif

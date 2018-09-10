/**
 * @file include/retdec/capstone2llvmir/arm64/arm64.h
 * @brief ARM64 specialization of translator's abstract public interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_ARM64_ARM64_H
#define RETDEC_CAPSTONE2LLVMIR_ARM64_ARM64_H

#include "retdec/capstone2llvmir/arm64/arm64_defs.h"
#include "retdec/capstone2llvmir/capstone2llvmir.h"

namespace retdec {
namespace capstone2llvmir {

/**
 * ARM64 specialization of translator's abstract public interface.
 */
class Capstone2LlvmIrTranslatorArm64 : virtual public Capstone2LlvmIrTranslator
{
	public:
		virtual ~Capstone2LlvmIrTranslatorArm64() {};
};

} // namespace capstone2llvmir
} // namespace retdec

#endif /* RETDEC_CAPSTONE2LLVMIR_ARM64_ARM64_H */

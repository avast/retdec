/**
 * @file include/retdec/capstone2llvmir/arm64/arm64.h
 * @brief ARM64 specialization of translator's abstract public interface.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
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
		/**
		 * @return Capstone register that is parent to the specified Capstone
		 * register @p r. Register can be its own parent.
		 */
		virtual uint32_t getParentRegister(uint32_t r) const = 0;
};

} // namespace capstone2llvmir
} // namespace retdec

#endif /* RETDEC_CAPSTONE2LLVMIR_ARM64_ARM64_H */

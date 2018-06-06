/**
 * @file include/retdec/capstone2llvmir/powerpc/powerpc.h
 * @brief PowerPC specialization of translator's abstract public interface.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_POWERPC_POWERPC_H
#define RETDEC_CAPSTONE2LLVMIR_POWERPC_POWERPC_H

#include "retdec/capstone2llvmir/capstone2llvmir.h"
#include "retdec/capstone2llvmir/powerpc/powerpc_defs.h"

namespace retdec {
namespace capstone2llvmir {

/**
 * PowerPC specialization of translator's abstract public interface.
 */
class Capstone2LlvmIrTranslatorPowerpc : virtual public Capstone2LlvmIrTranslator
{
	public:
		virtual ~Capstone2LlvmIrTranslatorPowerpc() {};
};

} // namespace capstone2llvmir
} // namespace retdec

#endif

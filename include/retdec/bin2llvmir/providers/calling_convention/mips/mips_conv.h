/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/mips/mips_conv.h
 * @brief Calling convention of MIPS architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_MIPS_CONV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_MIPS_CONV_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class MipsCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		MipsCallingConvention(const Abi* a);

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

}
}

#endif

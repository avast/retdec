/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/mips64/mips64_conv.h
 * @brief Calling convention of Mips64 architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_MIPS64_MIPS64_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_MIPS64_MIPS64_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class Mips64CallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		Mips64CallingConvention(const Abi* a);

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

}
}

#endif

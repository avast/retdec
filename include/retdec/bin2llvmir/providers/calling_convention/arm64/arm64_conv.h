/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/arm64/arm64_conv.h
 * @brief Calling conventions of ARM64 architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_ARM64_CONV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_ARM64_CONV_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class Arm64CallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		Arm64CallingConvention(const Abi* a);

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

}
}

#endif

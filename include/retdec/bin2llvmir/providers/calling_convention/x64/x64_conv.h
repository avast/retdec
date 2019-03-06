/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/x64/x64_conv.h
 * @brief Calling convention of X64 architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X64_X64_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X64_X64_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class X64CallingConvention : public CallingConvention
{
	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);
};

}
}

#endif

/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/x86/x86_conv.h
 * @brief Common calling convention of x86 architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X86_X86_CONV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X86_X86_CONV_H

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class X86CallingConvention: public CallingConvention
{
	// Ctors.
	public:
		X86CallingConvention(const Abi* a);

	// Stacks.
	//
	public:
		virtual std::size_t getMaxBytesPerStackParam() const override;
};

}
}

#endif

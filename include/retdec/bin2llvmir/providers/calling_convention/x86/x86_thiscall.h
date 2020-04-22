/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/x86/x86_thiscall.h
 * @brief Thiscall calling convention of x86 architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X86_X86_THISCALL_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X86_X86_THISCALL_H

#include "retdec/bin2llvmir/providers/calling_convention/x86/x86_conv.h"

namespace retdec {
namespace bin2llvmir {

class ThiscallCallingConvention: public X86CallingConvention
{
	// Ctors, dtors.
	//
	public:
		ThiscallCallingConvention(const Abi* a);

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);
};

}
}

#endif

/**
 * @file src/bin2llvmir/providers/calling_convention/x86/x86_pascal.cpp
 * @brief Pascal calling convention of architecture x86.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/x86/x86_pascal.h"
#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace bin2llvmir {

PascalCallingConvention::PascalCallingConvention(const Abi* a) :
		X86CallingConvention(a)

{
	_returnRegs = {
		X86_REG_EAX,
		X86_REG_EDX
	};

	_returnFPRegs = {
		X86_REG_ST7,
		X86_REG_ST0
	};

	_stackParamOrder = LTR;
}

CallingConvention::Ptr PascalCallingConvention::create(const Abi* a)
{
	if (!a->isX86())
	{
		return nullptr;
	}

	return std::make_unique<PascalCallingConvention>(a);
}

}
}

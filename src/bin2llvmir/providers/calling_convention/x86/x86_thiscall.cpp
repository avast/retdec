/**
 * @file src/bin2llvmir/providers/calling_convention/x86/x86_thiscall.cpp
 * @brief Thiscall calling convention of architecture x86.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/x86/x86_thiscall.h"
#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace bin2llvmir {

ThiscallCallingConvention::ThiscallCallingConvention(const Abi* a) :
		X86CallingConvention(a)

{
	_paramRegs = {
		X86_REG_ECX
	};

	_returnRegs = {
		X86_REG_EAX,
		X86_REG_EDX
	};

	_returnFPRegs = {
		X86_REG_ST7,
		X86_REG_ST0
	};
}

CallingConvention::Ptr ThiscallCallingConvention::create(const Abi* a)
{
	if (!a->isX86())
	{
		return nullptr;
	}

	return std::make_unique<ThiscallCallingConvention>(a);
}

}
}

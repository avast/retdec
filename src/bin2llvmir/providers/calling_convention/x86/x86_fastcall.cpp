/**
 * @file src/bin2llvmir/providers/calling_convention/x86/x86_fastcall.cpp
 * @brief Fastcall calling convention of architecture x86.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/x86/x86_fastcall.h"
#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// PascalFastcallCallingConvention
//==============================================================================
//

PascalFastcallCallingConvention::PascalFastcallCallingConvention(const Abi* a) :
		X86CallingConvention(a)

{
	_paramRegs = {
		X86_REG_EAX,
		X86_REG_EDX,
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

	_stackParamOrder = LTR;
}

//
//==============================================================================
// FastcallCallingConvention
//==============================================================================
//

FastcallCallingConvention::FastcallCallingConvention(const Abi* a) :
		X86CallingConvention(a)

{
	_paramRegs = {
		X86_REG_ECX,
		X86_REG_EDX,
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

CallingConvention::Ptr FastcallCallingConvention::create(const Abi* a)
{
	if (!a->isX86())
	{
		return nullptr;
	}

	if (a->getConfig()->getConfig().tools.isBorland())
	{
		return std::make_unique<PascalFastcallCallingConvention>(a);
	}

	return std::make_unique<FastcallCallingConvention>(a);
}

}
}

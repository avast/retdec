/**
 * @file src/bin2llvmir/providers/calling_convention/x64/x64_microsoft.cpp
 * @brief Microsoft calling convention of X64 architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/calling_convention/x64/x64_microsoft.h"
#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace bin2llvmir {

MicrosoftX64CallingConvention::MicrosoftX64CallingConvention(const Abi* a) :
	CallingConvention(a)
{
	_paramRegs = {
		X86_REG_RCX,
		X86_REG_RDX,
		X86_REG_R8,
		X86_REG_R9
	};
	_paramFPRegs = {
		X86_REG_XMM0,
		X86_REG_XMM1,
		X86_REG_XMM2,
		X86_REG_XMM3
	};

	_returnRegs = {
		X86_REG_RAX
	};
	_returnFPRegs = {
		X86_REG_XMM0
	};

	_largeObjectsPassedByReference = true;
}

}
}

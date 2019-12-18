/**
 * @file src/bin2llvmir/providers/calling_convention/x64/x64_systemv.cpp
 * @brief System V Calling convention of X64 architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/calling_convention/x64/x64_systemv.h"
#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace bin2llvmir {

SystemVX64CallingConvention::SystemVX64CallingConvention(const Abi* a) :
	CallingConvention(a)
{
	_paramRegs = {
		X86_REG_RDI,
		X86_REG_RSI,
		X86_REG_RDX,
		X86_REG_RCX,
		X86_REG_R8,
		X86_REG_R9
	};
	_paramFPRegs = {
		X86_REG_XMM0,
		X86_REG_XMM1,
		X86_REG_XMM2,
		X86_REG_XMM3,
		X86_REG_XMM4,
		X86_REG_XMM5,
		X86_REG_XMM6,
		X86_REG_XMM7
	};
	_paramVectorRegs = {
		X86_REG_XMM0,
		X86_REG_XMM1,
		X86_REG_XMM2,
		X86_REG_XMM3,
		X86_REG_XMM4,
		X86_REG_XMM5,
		X86_REG_XMM6,
		X86_REG_XMM7
	};

	_returnRegs = {
		X86_REG_RAX,
		X86_REG_RDX
	};
	_returnFPRegs = {
		X86_REG_XMM0,
		X86_REG_XMM1
	};
	_returnVectorRegs = {
		X86_REG_XMM0,
		X86_REG_XMM1
	};

	_largeObjectsPassedByReference = true;
	_numOfRegsPerParam = 2;
	_numOfFPRegsPerParam = 2;
	_numOfVectorRegsPerParam = 2;
}

}
}

/**
 * @file src/bin2llvmir/providers/calling_convention/mips/mips_conv.cpp
 * @brief Calling conventions of MIPS architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/mips/mips_conv.h"
#include "retdec/bin2llvmir/providers/calling_convention/mips/mips_psp.h"
#include "retdec/capstone2llvmir/mips/mips.h"

namespace retdec {
namespace bin2llvmir {

MipsCallingConvention::MipsCallingConvention(const Abi* a) :
	CallingConvention(a)
{
	_paramRegs = {
		MIPS_REG_A0,
		MIPS_REG_A1,
		MIPS_REG_A2,
		MIPS_REG_A3
	};
	_paramFPRegs = {
		MIPS_REG_F12,
		MIPS_REG_F14,
		MIPS_REG_F16,
		MIPS_REG_F18
	};
	_paramDoubleRegs = {
		MIPS_REG_FD12,
		MIPS_REG_FD14,
		MIPS_REG_FD16,
	};

	_returnRegs = {
		MIPS_REG_V0
	};
	_returnFPRegs = {
		MIPS_REG_F0
	};

	_numOfRegsPerParam = 2;
	_largeObjectsPassedByReference = true;
	_respectsRegCouples = true;
}

CallingConvention::Ptr MipsCallingConvention::create(const Abi* a)
{
	if (!a->isMips())
	{
		return nullptr;
	}

	if (a->getConfig()->getConfig().tools.isPspGcc())
	{
		return std::make_unique<MipsPSPCallingConvention>(a);
	}

	return std::make_unique<MipsCallingConvention>(a);
}

}
}

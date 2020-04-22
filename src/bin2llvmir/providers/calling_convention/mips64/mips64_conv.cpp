/**
 * @file src/bin2llvmir/providers/calling_convention/mips64/mips64_conv.cpp
 * @brief Calling convention of Mips64 architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/mips64/mips64_conv.h"
#include "retdec/capstone2llvmir/mips/mips.h"

namespace retdec {
namespace bin2llvmir {

Mips64CallingConvention::Mips64CallingConvention(const Abi* a) :
	CallingConvention(a)
{
	_paramRegs = {
		MIPS_REG_A0,
		MIPS_REG_A1,
		MIPS_REG_A2,
		MIPS_REG_A3,
		MIPS_REG_T0,
		MIPS_REG_T1,
		MIPS_REG_T2,
		MIPS_REG_T3
	};
	_paramFPRegs = {
		MIPS_REG_F12,
		MIPS_REG_F13,
		MIPS_REG_F14,
		MIPS_REG_F15,
		MIPS_REG_F16,
		MIPS_REG_F17,
		MIPS_REG_F18
	};

	_returnRegs = {
		MIPS_REG_V0
	};
	_returnFPRegs = {
		MIPS_REG_F1
	};

	_numOfRegsPerParam = 2;
	_largeObjectsPassedByReference = true;
	_respectsRegCouples = true;
}

CallingConvention::Ptr Mips64CallingConvention::create(const Abi* a)
{
	if (!a->isMips64())
	{
		return nullptr;
	}

	return std::make_unique<Mips64CallingConvention>(a);
}

}
}

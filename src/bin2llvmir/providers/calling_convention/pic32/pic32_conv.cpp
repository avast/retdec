/**
 * @file src/bin2llvmir/providers/calling_convention/pic32/pic32_conv.cpp
 * @brief Calling conventions of PIC32 architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/pic32/pic32_conv.h"
#include "retdec/capstone2llvmir/mips/mips.h"

namespace retdec {
namespace bin2llvmir {

Pic32CallingConvention::Pic32CallingConvention(const Abi* a) :
	CallingConvention(a)
{
	_paramRegs = {
		MIPS_REG_A0,
		MIPS_REG_A1,
		MIPS_REG_A2,
		MIPS_REG_A3
	};

	_returnRegs = {
		MIPS_REG_V0
	};

	_numOfRegsPerParam = 1;
	_largeObjectsPassedByReference = true;
	_respectsRegCouples = true;
}

CallingConvention::Ptr Pic32CallingConvention::create(const Abi* a)
{
	if (!a->isPic32())
	{
		return nullptr;
	}

	return std::make_unique<Pic32CallingConvention>(a);
}

}
}

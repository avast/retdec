/**
 * @file src/bin2llvmir/providers/calling_convention/powerpc/powerpc_conv.cpp
 * @brief Calling conventions of PowerPC architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/powerpc/powerpc_conv.h"
#include "retdec/capstone2llvmir/powerpc/powerpc.h"

namespace retdec {
namespace bin2llvmir {

PowerPCCallingConvention::PowerPCCallingConvention(const Abi* a) :
	CallingConvention(a)
{
	_paramRegs = {
		PPC_REG_R3,
		PPC_REG_R4,
		PPC_REG_R5,
		PPC_REG_R6,
		PPC_REG_R7,
		PPC_REG_R8,
		PPC_REG_R9,
		PPC_REG_R10
	};
	_paramFPRegs = {
		PPC_REG_F1,
		PPC_REG_F2,
		PPC_REG_F3,
		PPC_REG_F4,
		PPC_REG_F5,
		PPC_REG_F6,
		PPC_REG_F7,
		PPC_REG_F8
	};

	_returnRegs = {
		PPC_REG_R3,
		PPC_REG_R4
	};
	_returnFPRegs = {
		PPC_REG_F1
	};

	_numOfRegsPerParam = 2;
	_largeObjectsPassedByReference = true;
	_respectsRegCouples = true;
}

CallingConvention::Ptr PowerPCCallingConvention::create(const Abi* a)
{
	if (!a->isPowerPC())
	{
		return nullptr;
	}

	return std::make_unique<PowerPCCallingConvention>(a);
}

}
}

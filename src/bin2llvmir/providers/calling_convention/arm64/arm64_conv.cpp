/**
 * @file src/bin2llvmir/providers/calling_convention/arm64/arm64_conv.cpp
 * @brief Calling conventions of ARM64 architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <capstone/arm64.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/arm64/arm64_conv.h"

namespace retdec {
namespace bin2llvmir {

Arm64CallingConvention::Arm64CallingConvention(const Abi* a) :
	CallingConvention(a)
{
	_paramRegs = {
		ARM64_REG_X0,
		ARM64_REG_X1,
		ARM64_REG_X2,
		ARM64_REG_X3,
		ARM64_REG_X4,
		ARM64_REG_X5,
		ARM64_REG_X6,
		ARM64_REG_X7
	};
	_paramFPRegs = {
		ARM64_REG_V0,
		ARM64_REG_V1,
		ARM64_REG_V2,
		ARM64_REG_V3,
		ARM64_REG_V4,
		ARM64_REG_V5,
		ARM64_REG_V6,
		ARM64_REG_V7
	};

	_paramVectorRegs = {
		ARM64_REG_V0,
		ARM64_REG_V1,
		ARM64_REG_V2,
		ARM64_REG_V3,
		ARM64_REG_V4,
		ARM64_REG_V5,
		ARM64_REG_V6,
		ARM64_REG_V7
	};

	_returnRegs = {
		ARM64_REG_X0
	};

	_returnFPRegs = {
		ARM64_REG_V0
	};

	_largeObjectsPassedByReference = true;
	_respectsRegCouples = true;
	_numOfRegsPerParam = 2;
}

CallingConvention::Ptr Arm64CallingConvention::create(const Abi* a)
{
	if (!a->isArm64())
	{
		return nullptr;
	}

	return std::make_unique<Arm64CallingConvention>(a);
}

}
}

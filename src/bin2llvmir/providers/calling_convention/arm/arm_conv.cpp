/**
 * @file src/bin2llvmir/providers/calling_convention/arm/arm_conv.cpp
 * @brief Calling convention of ARM architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/arm/arm_conv.h"
#include "retdec/capstone2llvmir/arm/arm.h"

namespace retdec {
namespace bin2llvmir {

ArmCallingConvention::ArmCallingConvention(const Abi* a) :
	CallingConvention(a)
{
	_paramRegs = {
		ARM_REG_R0,
		ARM_REG_R1,
		ARM_REG_R2,
		ARM_REG_R3};

	_returnRegs = {
		ARM_REG_R0,
		ARM_REG_R1};

	_largeObjectsPassedByReference = true;
//	_respectsRegCouples = true;
	_numOfRegsPerParam = 2;
	_numOfFPRegsPerParam = 2;
	_numOfVectorRegsPerParam = 4;
}

CallingConvention::Ptr ArmCallingConvention::create(const Abi* a)
{
	if (!a->isArm())
	{
		return nullptr;
	}

	return std::make_unique<ArmCallingConvention>(a);
}

}
}

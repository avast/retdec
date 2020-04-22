/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/arm/arm_conv.h
 * @brief Calling conventions of ARM architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_ARM_CONV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_ARM_CONV_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class ArmCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		ArmCallingConvention(const Abi* a);

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

}
}

#endif

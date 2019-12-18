/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/powerpc/powerpc_conv.h
 * @brief Calling conventions of PowerPC architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_POWERPC_POWERPC_CONV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_POWERPC_POWERPC_CONV_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class PowerPCCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		PowerPCCallingConvention(const Abi* a);

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

}
}

#endif

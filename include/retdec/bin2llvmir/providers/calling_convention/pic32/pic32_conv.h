/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/pic32/pic32_conv.h
 * @brief Calling conventions of PIC32 architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_PIC32_PIC32_CONV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_PIC32_PIC32_CONV_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class Pic32CallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		Pic32CallingConvention(const Abi* a);

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

}
}

#endif

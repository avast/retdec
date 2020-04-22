/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/x64/x64_systemv.h
 * @brief System V calling convention of X64 architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X64_X64_SYSV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X64_X64_SYSV_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class SystemVX64CallingConvention : public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		SystemVX64CallingConvention(const Abi* a);
};

}
}

#endif

/**
 * @file retdec/include/bin2llvmir/providers/calling_convention/x64.h
 * @brief Calling conventions of X64 architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X64_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_X64_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class SystemVX64CallingConvention : public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		SystemVX64CallingConvention(const Abi* a);
		virtual ~SystemVX64CallingConvention();

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

class MicrosoftX64CallingConvention : public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		MicrosoftX64CallingConvention(const Abi* a);
		virtual ~MicrosoftX64CallingConvention();

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

}
}

#endif

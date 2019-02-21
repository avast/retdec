/**
 * @file retdec/include/bin2llvmir/providers/calling_convention/mips.h
 * @brief Calling conventions of MIPS architecture.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_MIPS_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_MIPS_H

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class MipsCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		MipsCallingConvention(const Abi* a);
		virtual ~MipsCallingConvention();

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

class MipsPSPCallingConvention: public CallingConvention
{
	// Ctors, dtors.
	//
	public:
		MipsPSPCallingConvention(const Abi* a);
		virtual ~MipsPSPCallingConvention();

	// Construcor method.
	//
	public:
		static CallingConvention::Ptr create(const Abi* a);

};

}
}

#endif

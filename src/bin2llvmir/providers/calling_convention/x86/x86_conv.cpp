/**
 * @file src/bin2llvmir/providers/calling_convention/x86/x86_conv.cpp
 * @brief Calling convention of architecture x86.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/x86/x86_conv.h"
#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace bin2llvmir {

X86CallingConvention::X86CallingConvention(const Abi* a) :
		CallingConvention(a)

{
}

std::size_t X86CallingConvention::getMaxBytesPerStackParam() const
{
	return _abi->getWordSize()*2;
}

}
}

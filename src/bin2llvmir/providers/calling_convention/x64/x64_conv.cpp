/**
 * @file src/bin2llvmir/providers/calling_convention/x64/x64_conv.cpp
 * @brief Calling conventions of X64 architecture.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/x64/x64_conv.h"
#include "retdec/bin2llvmir/providers/calling_convention/x64/x64_microsoft.h"
#include "retdec/bin2llvmir/providers/calling_convention/x64/x64_systemv.h"
#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace bin2llvmir {

CallingConvention::Ptr X64CallingConvention::create(const Abi* a)
{
	if (!a->isX64())
	{
		return nullptr;
	}

	auto c = a->getConfig();
	bool isPe = c->getConfig().fileFormat.isPe();

	if (isPe || c->getConfig().tools.isMsvc())
	{
		return std::make_unique<MicrosoftX64CallingConvention>(a);
	}

	return std::make_unique<SystemVX64CallingConvention>(a);
}

}
}

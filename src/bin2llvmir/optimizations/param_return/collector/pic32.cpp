/**
* @file src/bin2llvmir/optimizations/param_return/collector/pic32.cpp
* @brief Pic32 specific collection algorithms.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/param_return/collector/pic32.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

void CollectorPic32::collectCallSpecificTypes(CallEntry* ce) const
{
	Collector::collectCallSpecificTypes(ce);

	std::vector<llvm::Type*> argTypes;
	for (auto t : ce->argTypes())
	{
		if (t->isDoubleTy())
		{
			argTypes.push_back(Type::getFloatTy(_module->getContext()));
		}
		else
		{
			argTypes.push_back(t);
		}
	}

	ce->setArgTypes(std::move(argTypes));
}

}
}

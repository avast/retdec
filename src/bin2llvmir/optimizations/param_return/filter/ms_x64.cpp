/**
* @file src/bin2llvmir/optimizations/param_return/filter/ms_x64.cpp
* @brief Microsoft x64 specific filtration of registers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <deque>

#include "retdec/bin2llvmir/optimizations/param_return/filter/ms_x64.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

void MSX64Filter::filterDefinitionArgs(FilterableLayout& args, bool isVoidarg) const
{
	leaveOnlyPositiveStacks(args);

	if (isVoidarg)
	{
		args.gpRegisters.clear();
		args.fpRegisters.clear();
		args.doubleRegisters.clear();
		args.vectorRegisters.clear();
		args.stacks.clear();
	}
	else if (!args.knownTypes.empty())
	{
		filterArgsByKnownTypes(args);
	}
	else
	{
		leaveOnlyAlternatingArgRegisters(args);
	}

	leaveOnlyContinuousStack(args);
}

void MSX64Filter::filterCallArgs(FilterableLayout& args, bool isVoidarg) const
{
	if (isVoidarg)
	{
		args.gpRegisters.clear();
		args.fpRegisters.clear();
		args.doubleRegisters.clear();
		args.vectorRegisters.clear();
		args.stacks.clear();
	}
	else if (!args.knownTypes.empty())
	{
		filterArgsByKnownTypes(args);
	}
	else
	{
		leaveOnlyAlternatingArgRegisters(args);
	}

	leaveOnlyContinuousStack(args);
}

void MSX64Filter::filterArgsByKnownTypes(FilterableLayout& lay) const
{
	FilterableLayout newLayout;
	newLayout.knownTypes = lay.knownTypes;

	auto& gpRegs = _cc->getParamRegisters();

	// Indexes of registers to be used next as particular parameter.
	auto sIt = lay.stacks.begin();

	std::size_t regEnd = gpRegs.size();

	std::vector<uint32_t> registers;

	std::vector<llvm::Type*> types = expandTypes(lay.knownTypes);

	for (auto t: types)
	{
		std::size_t requiredStacks = 0;
		OrderID stackOrd = OrderID::ORD_STACK;

		if (t->isFloatingPointTy() || t->isVectorTy())
		{
			if (registers.size() < regEnd)
			{
				newLayout.fpRegisters = registers;
				requiredStacks = fetchFPRegsForType(t, newLayout);
				registers = newLayout.fpRegisters;
				stackOrd = OrderID::ORD_STACK_GROUP;
			}
		}
		else
		{
			if (registers.size() < regEnd)
			{
				newLayout.gpRegisters = registers;
				requiredStacks = fetchGPRegsForType(t, newLayout);
				registers = newLayout.gpRegisters;
				stackOrd = OrderID::ORD_STACK_GROUP;
			}
		}

		if (!requiredStacks && stackOrd == OrderID::ORD_STACK)
		{
			requiredStacks = getNumberOfStacksForType(t);
		}

		for (std::size_t i = 0; i < requiredStacks; i++)
		{
			if (sIt != lay.stacks.end())
			{
				newLayout.stacks.push_back(*sIt);
				sIt++;
			}
			else
			{
				newLayout.stacks.push_back(nullptr);
			}

			newLayout.knownOrder.push_back(
				i == 0 ? stackOrd :
					OrderID::ORD_STACK_GROUP);
		}
	}

	std::vector<Value*> regVals;
	for (auto r : registers)
	{
		regVals.push_back(_abi->getRegister(r));
	}

	lay = separateArgValues(regVals);
	lay.stacks = newLayout.stacks;
	lay.knownOrder = newLayout.knownOrder;
	lay.knownTypes = newLayout.knownTypes;
}

void MSX64Filter::leaveOnlyAlternatingArgRegisters(FilterableLayout& lay) const
{
	auto& templRegs = _cc->getParamRegisters();
	auto& fpTemplRegs = _cc->getParamFPRegisters();

	auto it = lay.gpRegisters.begin();
	auto fIt = lay.fpRegisters.begin();

	std::size_t idx = 0;
	while (idx < fpTemplRegs.size() && idx < templRegs.size())
	{
		if (it == lay.gpRegisters.end() && fIt == lay.fpRegisters.end())
		{
			lay.stacks.clear();
			return;
		}

		if (it != lay.gpRegisters.end() && *it == templRegs[idx])
		{
			it++;
		}
		else if (fIt != lay.fpRegisters.end() && *fIt == fpTemplRegs[idx])
		{
			fIt++;
		}
		else
		{
			lay.gpRegisters.erase(it, lay.gpRegisters.end());
			lay.fpRegisters.erase(fIt, lay.fpRegisters.end());
			lay.stacks.clear();
			return;
		}

		idx++;
	}
}

}
}

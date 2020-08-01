/**
* @file src/bin2llvmir/optimizations/param_return/filter/filter.cpp
* @brief Filters potential values according to calling convention.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <deque>
#include <optional>

#include "retdec/bin2llvmir/optimizations/param_return/filter/filter.h"
#include "retdec/bin2llvmir/optimizations/param_return/filter/ms_x64.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  Filter
//=============================================================================
//

Filter::Filter(
		const Abi* abi,
		const CallingConvention* cc) :
	_abi(abi),
	_cc(cc)
{
}

void Filter::estimateRetValue(DataFlowEntry* de) const
{
	auto retValue = de->getRetValue();
	auto retType = de->getRetType();

	if (retType == nullptr)
	{
		if (!de->retEntries().empty()
			&& !de->retEntries().front().retValues().empty())
		{
			retType = de->retEntries().front().retValues().front()->getType();
			if (auto* p = dyn_cast<PointerType>(retType))
			{
				retType = p->getElementType();
			}
			retValue = de->retEntries().front().retValues().front();
		}
		else
		{
			// This is hack -> retdec expects generation of
			// implicit return for every funtion definition
			// but not external calls.
			//
			// In fact this should return void type here.
			// This is why retType is not set to any type.
			if (!_cc->getReturnRegisters().empty())
			{
				retValue = _abi->getRegister(_cc->getReturnRegisters().front());
			}
		}
	}
	else
	{
//		TODO: double-read-modf.x86.clang-3.2.O0.g.elf
//		In test above return type is found from configuration to be
//		double but collector finds only stores to EAX which results in failure in
//		decompilation.
//
//		if (!de->retEntries().empty()
//			&& !de->retEntries().front().retValues().empty())
//		{
//			retValue = de->retEntries().front().retValues().front();
//		}
//		else
		{
			if (!_cc->getReturnRegisters().empty())
			{
				retValue = _abi->getRegister(_cc->getReturnRegisters().front());
			}

			if (retType->isFloatingPointTy() && !_cc->getReturnFPRegisters().empty())
			{
				retValue = _abi->getRegister(_cc->getReturnFPRegisters().front());
			}

			if (retType->isDoubleTy() && !_cc->getReturnDoubleRegisters().empty())
			{
				retValue = _abi->getRegister(_cc->getReturnDoubleRegisters().front());
			}
		}
	}

	de->setRetType(retType);
	de->setRetValue(retValue);
}

void Filter::filterDefinition(DataFlowEntry* de) const
{
	if (!de->hasDefinition())
	{
		return;
	}

	FilterableLayout defArgs = createArgsFilterableLayout(de->args(), de->argTypes());
	filterDefinitionArgs(defArgs, de->isVoidarg());

	de->setArgs(createGroupedArgValues(defArgs));

	if (de->retEntries().empty())
	{
		return;
	}

	std::vector<FilterableLayout> defRets;
	for (auto& ret : de->retEntries())
	{
		defRets.push_back(
			createRetsFilterableLayout(ret.retValues(), de->getRetType()));
	}

	leaveCommonRets(defRets);
	filterRets(defRets.front());

	FilterableLayout retTempl = defRets.front();

	for (auto& ret : de->retEntries())
	{
		filterRetsByDefLayout(defRets.front(), retTempl);
		ret.setRetValues(createGroupedValues(defRets.front()));

		defRets.erase(defRets.begin());
	}
}

void Filter::filterCalls(DataFlowEntry* de) const
{
	if (de->callEntries().empty())
	{
		return;
	}

	std::vector<FilterableLayout> callArgs, callArgsCopy;
	std::vector<FilterableLayout> callRets;

	for (auto& call : de->callEntries())
	{
		callArgs.push_back(
			createArgsFilterableLayout(call.args(), de->argTypes()));
		callRets.push_back(
			createRetsFilterableLayout(
				call.retValues(),
				de->getRetType()));
	}

	callArgsCopy = callArgs;

	FilterableLayout retTempl, argTempl;

	if (!callArgs.empty())
	{
		if (!de->isVoidarg() && de->argTypes().empty())
		{
			leaveCommonArgs(callArgs);
		}
		filterCallArgs(callArgs.front(), de->isVoidarg());
		argTempl = callArgs.front();
	}

	if (!callRets.empty())
	{
		leaveCommonRets(callRets);
		filterRets(callRets.front());
		retTempl = callRets.front();
	}

	/* When there is definition available we should
	 * use arguments from there. This is more reliable than
	 * constructing intersations of used arguments in file.
	 */
	if (de->hasDefinition())
	{
		FilterableLayout defArgs;
		defArgs = createArgsFilterableLayout(
				de->args(),
				de->argTypes());
		if (!de->isVoidarg() && !de->argTypes().empty())
		{
			// This function is called because
			// in case when we have info about
			// types and order of the parameters
			// we would loose it by plain creation
			// of template.
			// This order is estimated in function
			// below.
			filterArgsByKnownTypes(defArgs);
		}
		else if (de->args().empty() && (
				// possible wrapper
				(de->numberOfCalls() == 1 && !de->hasBranches())
				// Possible error in stack analysis.
				|| (de->storesOnRawStack(*_abi))
				// Selective decompilation. Definition exists
				// but is empty -> we do not trust it.
				|| (!de->isFullyDecoded())
			))
		{
			// In this case it might be wrapper that
			// takes arguments from call and do not modify them
			// in definition.
			filterCallArgsByDefLayout(defArgs, argTempl);
			de->setArgs(createGroupedArgValues(defArgs));
		}
		else if (argTempl.stacks.size() > defArgs.stacks.size()
				&& de->numberOfCalls() == 1 && !de->hasBranches())
		{
			if (argTempl.gpRegisters.size() == defArgs.gpRegisters.size()
				&& argTempl.fpRegisters.size() == defArgs.fpRegisters.size()
				&& argTempl.doubleRegisters.size() == defArgs.doubleRegisters.size()
				&& argTempl.vectorRegisters.size() == defArgs.vectorRegisters.size())
			{
				leaveSameStacks(defArgs, argTempl);
				de->setArgs(createGroupedArgValues(defArgs));
			}
		}

		if (!de->retEntries().empty())
		{
			retTempl = createRetsFilterableLayout(
					de->retEntries().front().retValues(),
					de->getRetType());
		}

		argTempl = std::move(defArgs);
	}

	for (auto& call : de->callEntries())
	{
		filterCallArgsByDefLayout(callArgsCopy.front(), argTempl);
		filterRetsByDefLayout(callRets.front(), retTempl);

		call.setArgs(createGroupedArgValues(callArgsCopy.front()));
		call.setRetValues(createGroupedRetValues(callRets.front()));

		callArgsCopy.erase(callArgsCopy.begin());
		callRets.erase(callRets.begin());
	}
}

void Filter::filterCallsVariadic(DataFlowEntry* de, const Collector* collector) const
{
	if (de->callEntries().empty())
	{
		return;
	}

	std::vector<FilterableLayout> callArgs;
	std::vector<FilterableLayout> callRets;

	for (auto& call : de->callEntries())
	{
		auto argTypes = de->argTypes();

		FilterableLayout argLayout = createArgsFilterableLayout(call.args(), {});

		// To collect specific types, we need ordered values.
		// Collector will find first occourence of string and parse it.
		call.setArgs(createGroupedArgValues(argLayout));
		collector->collectCallSpecificTypes(&call);

		argTypes.insert(
			argTypes.end(),
			call.argTypes().begin(),
			call.argTypes().end());

		argLayout.knownTypes = std::move(argTypes);

		callArgs.push_back(argLayout);
		callRets.push_back(
			createRetsFilterableLayout(
				call.retValues(),
				call.getBaseFunction()->getRetType()));
	}

	FilterableLayout retTempl;

	if (de->hasDefinition() && !de->retEntries().empty())
	{
		retTempl = createRetsFilterableLayout(
				de->retEntries().front().retValues(),
				de->getRetType());
	}
	else if (!callRets.empty())
	{
		leaveCommonRets(callRets);
		filterRets(callRets.front());
		retTempl = callRets.front();
	}

	for (auto& call : de->callEntries())
	{
		filterCallArgs(callArgs.front(), de->isVoidarg() && !call.argTypes().empty());
		filterRetsByDefLayout(callRets.front(), retTempl);

		call.setArgs(createGroupedArgValues(callArgs.front()));
		call.setRetValues(createGroupedRetValues(callRets.front()));

		callArgs.erase(callArgs.begin());
		callRets.erase(callRets.begin());
	}
}

void Filter::filterDefinitionArgs(FilterableLayout& args, bool isVoidarg) const
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
		createContinuousArgRegisters(args);
	}

	leaveOnlyContinuousStack(args);
}

void Filter::filterCallArgs(FilterableLayout& args, bool isVoidarg) const
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
		leaveOnlyContinuousArgRegisters(args);
	}

	leaveOnlyContinuousStack(args);
}

void Filter::filterCallArgsByDefLayout(
			FilterableLayout& args,
			const FilterableLayout& defArgs) const
{
	args.gpRegisters = std::vector<uint32_t>(defArgs.gpRegisters);
	args.fpRegisters = std::vector<uint32_t>(defArgs.fpRegisters);
	args.doubleRegisters = std::vector<uint32_t>(defArgs.doubleRegisters);
	args.vectorRegisters = std::vector<uint32_t>(defArgs.vectorRegisters);
	args.knownOrder = defArgs.knownOrder;

	leaveOnlyContinuousStack(args);
	leaveSameStacks(args, defArgs);
}

void Filter::filterRets(FilterableLayout& rets) const
{
	if (!rets.knownTypes.empty() && rets.knownTypes.front())
	{
		filterRetsByKnownTypes(rets);
	}
	else
	{
		leaveOnlyContinuousRetRegisters(rets);
	}
}

void Filter::filterRetsByDefLayout(
			FilterableLayout& rets,
			const FilterableLayout& defRets) const
{
	rets.gpRegisters = std::vector<uint32_t>(defRets.gpRegisters);
	rets.fpRegisters = std::vector<uint32_t>(defRets.fpRegisters);
	rets.doubleRegisters = std::vector<uint32_t>(defRets.doubleRegisters);
	rets.vectorRegisters = std::vector<uint32_t>(defRets.vectorRegisters);
	rets.knownOrder = defRets.knownOrder;

	leaveOnlyContinuousStack(rets);
	leaveSameStacks(rets, defRets);
}

void Filter::filterArgsByKnownTypes(FilterableLayout& lay) const
{
	FilterableLayout newLayout;
	auto& gpRegs = _cc->getParamRegisters();
	auto& fpRegs = _cc->getParamFPRegisters();
	auto& doubleRegs = _cc->getParamDoubleRegisters();
	auto& vecRegs = _cc->getParamVectorRegisters();

	// Indexes of registers to be used next as particular parameter.
	auto sIt = lay.stacks.begin();

	std::size_t gpEnd = gpRegs.size();
	std::size_t fpEnd = fpRegs.size();
	std::size_t doubleEnd = doubleRegs.size();
	std::size_t vecEnd = vecRegs.size();

	std::vector<llvm::Type*> types = expandTypes(lay.knownTypes);

	for (auto t: types)
	{
		std::size_t requiredStacks = 0;
		OrderID stackOrd = OrderID::ORD_STACK;

		if (!doubleRegs.empty() && t->isDoubleTy())
		{
			if (newLayout.doubleRegisters.size() < doubleEnd)
			{
				requiredStacks = fetchDoubleRegsForType(t, newLayout);
				stackOrd = OrderID::ORD_STACK_GROUP;
			}
		}
		else if (!fpRegs.empty() && t->isFloatingPointTy())
		{
			if (newLayout.fpRegisters.size() < fpEnd)
			{
				requiredStacks = fetchFPRegsForType(t, newLayout);
				stackOrd = OrderID::ORD_STACK_GROUP;
			}
		}
		else if (!vecRegs.empty() && t->isVectorTy())
		{
			if (newLayout.vectorRegisters.size() < vecEnd)
			{
				requiredStacks = fetchVecRegsForType(t, newLayout);
				stackOrd = OrderID::ORD_STACK_GROUP;
			}
		}
		else if (!gpRegs.empty())
		{
			if (newLayout.gpRegisters.size() < gpEnd)
			{
				requiredStacks = fetchGPRegsForType(t, newLayout);
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

	lay = newLayout;
}

std::vector<Type*> Filter::expandTypes(const std::vector<Type*>& types) const
{
	if (_cc->passesLargeObjectsByReference())
	{
		return types;
	}
	else
	{
		std::vector<Type*> expanded;

		std::deque<llvm::Type*> toExpand(
				types.begin(),
				types.end());

		while (!toExpand.empty())
		{
			auto t = toExpand.front();
			toExpand.pop_front();

			if (t == nullptr) {
				expanded.push_back(_abi->getDefaultType());
			}
			else if (auto* st = dyn_cast<StructType>(t))
			{
				for (auto& e : st->elements())
				{
					toExpand.push_back(e);
				}
			}
			else
			{
				expanded.push_back(t);
			}
		}

		return expanded;
	}
}

size_t Filter::fetchGPRegsForType(Type* type, FilterableLayout& lay) const
{
	std::size_t sizeBefore = lay.gpRegisters.size();
	std::size_t reqStacks = fetchRegsForType(
		type,
		lay.gpRegisters,
		_cc->getParamRegisters(),
		_cc->getMaxNumOfRegsPerParam());

	std::size_t change = lay.gpRegisters.size() - sizeBefore;
	if (change)
	{
		lay.knownOrder.push_back(OrderID::ORD_GPR);
		lay.knownOrder.resize(
			lay.knownOrder.size() + change - 1, OrderID::ORD_GPR_GROUP);
	}

	return reqStacks;
}

size_t Filter::fetchFPRegsForType(Type* type, FilterableLayout& lay) const
{
	std::size_t sizeBefore = lay.fpRegisters.size();
	std::size_t reqStacks = fetchRegsForType(
		type,
		lay.fpRegisters,
		_cc->getParamFPRegisters(),
		_cc->getMaxNumOfFPRegsPerParam());

	std::size_t change = lay.fpRegisters.size() - sizeBefore;
	if (change)
	{
		lay.knownOrder.push_back(OrderID::ORD_FPR);
		lay.knownOrder.resize(
			lay.knownOrder.size() + change - 1, OrderID::ORD_FPR_GROUP);
	}

	return reqStacks;
}

size_t Filter::fetchDoubleRegsForType(Type* type, FilterableLayout& lay) const
{
	std::size_t sizeBefore = lay.doubleRegisters.size();
	std::size_t reqStacks = fetchRegsForType(
		type,
		lay.doubleRegisters,
		_cc->getParamDoubleRegisters(),
		_cc->getMaxNumOfDoubleRegsPerParam());

	std::size_t change = lay.doubleRegisters.size() - sizeBefore;
	if (change)
	{
		lay.knownOrder.push_back(OrderID::ORD_DOUBR);
		lay.knownOrder.resize(
			lay.knownOrder.size() + change - 1, OrderID::ORD_DOUBR_GROUP);
	}

	return reqStacks;
}

size_t Filter::fetchVecRegsForType(Type* type, FilterableLayout& lay) const
{
	std::size_t sizeBefore = lay.vectorRegisters.size();
	std::size_t reqStacks = fetchRegsForType(
		type,
		lay.vectorRegisters,
		_cc->getParamVectorRegisters(),
		_cc->getMaxNumOfVectorRegsPerParam());

	std::size_t change = lay.vectorRegisters.size() - sizeBefore;
	if (change)
	{
		lay.knownOrder.push_back(OrderID::ORD_VECR);
		lay.knownOrder.resize(
			lay.knownOrder.size() + change - 1, OrderID::ORD_VECR_GROUP);
	}

	return reqStacks;
}

size_t Filter::fetchRegsForType(
			Type* type,
			std::vector<uint32_t>& store,
			const std::vector<uint32_t>& regs,
			std::size_t maxRegsPerObject) const
{
	if (regs.empty())
	{
		return  getNumberOfStacksForType(type);
	}
	auto* reg = _abi->getRegister(regs.front());
	if (reg == nullptr)
	{
		return  getNumberOfStacksForType(type);
	}

	Type* registerType = reg->getType();
	std::size_t registerSize = _abi->getTypeByteSize(registerType);
	std::size_t typeSize = type->isVoidTy() ?
					_abi->getWordSize() : _abi->getTypeByteSize(type);

	if (typeSize <= registerSize)
	{
		if (regs.size() <= store.size())
		{
			return  getNumberOfStacksForType(registerType);
		}

		auto reg = regs[store.size()];
		store.push_back(reg);

		return 0;
	}

	if ((typeSize > registerSize)
		&& (typeSize <= registerSize*maxRegsPerObject))
	{
		std::size_t numberOfRegs = typeSize / registerSize;
		auto regIt = store.size();

		if (_cc->respectsRegisterCouples())
		{
			if ((regIt+1)%2 == 0)
			{
				regIt++;
			}
		}

		for (std::size_t i = 0; i < numberOfRegs; i++)
		{
			if (regs.size() <= regIt)
			{
				return getNumberOfStacksForType(registerType)*(numberOfRegs-i);
			}

			auto reg = regs[regIt];
			store.push_back(reg);
			regIt++;
		}

		return 0;
	}

	if (_cc->passesLargeObjectsByReference())
	{
		if (regs.size() <= store.size())
		{
			return  getNumberOfStacksForType(registerType);
		}

		auto reg = regs[store.size()];
		store.push_back(reg);

		return 0;
	}

	return getNumberOfStacksForType(type);
}

size_t Filter::getNumberOfStacksForType(Type* type) const
{
	auto maxBytesPerParam = _cc->getMaxBytesPerStackParam();

	if (maxBytesPerParam == 0)
	{
		return 0;
	}

	std::size_t num = _abi->getTypeByteSize(type) / maxBytesPerParam;

	return num < 1 ? 1 : num;
}

void Filter::filterRetsByKnownTypes(FilterableLayout& lay) const
{
	std::vector<uint32_t> regGPValues, regFPValues, regDoubleValues, regVecValues;

	auto& gpRegs = _cc->getReturnRegisters();
	auto& fpRegs = _cc->getReturnFPRegisters();
	auto& doubleRegs = _cc->getReturnDoubleRegisters();
	auto& vecRegs = _cc->getReturnVectorRegisters();

	Type* retType = lay.knownTypes.empty() ? nullptr
				: lay.knownTypes.front();

	if (retType == nullptr)
	{
		return;
	}

	if (retType->isVectorTy() && !vecRegs.empty())
	{
		std::size_t typeSize = _abi->getTypeByteSize(retType);
		Type* registerType = _abi->getRegister(vecRegs.front())->getType();
		std::size_t registerSize = _abi->getTypeByteSize(registerType);

		if (typeSize <= registerSize ||
				(typeSize > registerSize*vecRegs.size()))
		{
			regVecValues.push_back(vecRegs.front());
		}

		std::size_t numOfRegs = typeSize/registerSize;
		for (std::size_t i = 0; i < numOfRegs && i < vecRegs.size(); i++)
		{
			regVecValues.push_back(vecRegs[i]);
		}
	}
	else if (retType->isDoubleTy() && !doubleRegs.empty())
	{
		std::size_t typeSize = _abi->getTypeByteSize(retType);
		Type* registerType = _abi->getRegister(doubleRegs.front())->getType();
		std::size_t registerSize = _abi->getTypeByteSize(registerType);

		if (typeSize <= registerSize ||
				(typeSize > registerSize*doubleRegs.size()))
		{
			regDoubleValues.push_back(doubleRegs.front());
		}

		std::size_t numOfRegs = typeSize/registerSize;
		for (std::size_t i = 0; i < numOfRegs && i < doubleRegs.size(); i++)
		{
			regDoubleValues.push_back(doubleRegs[i]);
		}
	}
	else if (retType->isFloatingPointTy() && !fpRegs.empty())
	{
		std::size_t typeSize = _abi->getTypeByteSize(retType);
		Type* registerType = _abi->getRegister(fpRegs.front())->getType();
		std::size_t registerSize = _abi->getTypeByteSize(registerType);

		if (typeSize <= registerSize ||
				(typeSize > registerSize*fpRegs.size()))
		{
			regFPValues.push_back(fpRegs.front());
		}

		std::size_t numOfRegs = typeSize/registerSize;
		for (std::size_t i = 0; i < numOfRegs && i < fpRegs.size(); i++)
		{
			regFPValues.push_back(fpRegs[i]);
		}
	}
	else if (!retType->isVoidTy())
	{
		assert(!gpRegs.empty());
		if (auto* defaultReg = _abi->getRegister(gpRegs.front()))
		{
			std::size_t typeSize = _abi->getTypeByteSize(retType);
			Type* registerType = defaultReg->getType();
			std::size_t registerSize = _abi->getTypeByteSize(registerType);

			if (typeSize <= registerSize ||
					(typeSize > registerSize*gpRegs.size()))
			{
				regGPValues.push_back(gpRegs.front());
			}

			std::size_t numOfRegs = typeSize/registerSize;
			for (std::size_t i = 0; i < numOfRegs && i < gpRegs.size(); i++)
			{
				regGPValues.push_back(gpRegs[i]);
			}
		}
		else
		{
			retType = nullptr;
		}

	}

	lay.gpRegisters = std::move(regGPValues);
	lay.fpRegisters = std::move(regFPValues);
	lay.doubleRegisters = std::move(regDoubleValues);
	lay.vectorRegisters = std::move(regVecValues);
	lay.knownTypes = {retType};
}

void Filter::leaveCommonArgs(std::vector<FilterableLayout>& allArgs) const
{
	leaveCommon(allArgs);
}

void Filter::leaveCommonRets(std::vector<FilterableLayout>& allRets) const
{
	leaveCommon(allRets);
}

void Filter::leaveCommon(std::vector<FilterableLayout>& lays) const
{
	if (lays.empty())
	{
		return;
	}

	auto& firstGPR = lays.front().gpRegisters;
	auto& firstFPR = lays.front().fpRegisters;
	auto& firstDR = lays.front().doubleRegisters;
	auto& firstVR = lays.front().vectorRegisters;

	std::set<uint32_t> commonGPR(firstGPR.begin(), firstGPR.end());
	std::set<uint32_t> commonFPR(firstFPR.begin(), firstFPR.end());
	std::set<uint32_t> commonDR(firstDR.begin(), firstDR.end());
	std::set<uint32_t> commonVR(firstVR.begin(), firstVR.end());

	std::size_t minStacks = lays.front().stacks.size();

	for (auto& lay : lays)
	{

		auto& gpr = lay.gpRegisters;
		auto& fpr = lay.fpRegisters;
		auto& dr = lay.doubleRegisters;
		auto& vr = lay.vectorRegisters;

		commonGPR.insert(gpr.begin(), gpr.end());
		commonFPR.insert(fpr.begin(), fpr.end());
		commonDR.insert(dr.begin(), dr.end());
		commonVR.insert(vr.begin(), vr.end());

	//	if (lay.stacks.empty())
	//	{
	//		continue;
	//	}
	//	else if (!minStacks || (minStacks > lay.stacks.size()))
		if (minStacks > lay.stacks.size())
		{
			minStacks = lay.stacks.size();
		}
	}

	for (auto& lay : lays)
	{
		lay.gpRegisters.assign(commonGPR.begin(), commonGPR.end());
		lay.fpRegisters.assign(commonFPR.begin(), commonFPR.end());
		lay.doubleRegisters.assign(commonDR.begin(), commonDR.end());
		lay.vectorRegisters.assign(commonVR.begin(), commonVR.end());
		lay.stacks.resize(minStacks, nullptr);

		orderFiterableLayout(lay);
	}
}

void Filter::orderFiterableLayout(FilterableLayout& lay) const
{
	orderStacks(lay.stacks, _cc->getStackParamOrder());
	orderRegistersBy(lay.gpRegisters, _cc->getParamRegisters());
	orderRegistersBy(lay.fpRegisters, _cc->getParamFPRegisters());
	orderRegistersBy(lay.doubleRegisters, _cc->getParamDoubleRegisters());
	orderRegistersBy(lay.vectorRegisters, _cc->getParamVectorRegisters());
}

void Filter::orderStacks(std::vector<llvm::Value*>& stacks, bool asc) const
{
	if (stacks.empty())
	{
		return;
	}

	auto config = _abi->getConfig();

	std::stable_sort(
			stacks.begin(),
			stacks.end(),
			[config, asc](Value* a, Value* b) -> bool
	{
		auto aOff = config->getStackVariableOffset(a);
		auto bOff = config->getStackVariableOffset(b);
		if (!aOff.has_value())
		{
			return !bOff.has_value();
		}
		else if (aOff.has_value() && !bOff.has_value())
		{
			return true;
		}

		bool ascOrd = aOff.value() < bOff.value();

		return asc ? ascOrd : !ascOrd;
	});
}

void Filter::orderRegistersBy(
	std::vector<uint32_t>& regs,
	const std::vector<uint32_t>& orderedVector) const
{
	std::stable_sort(
			regs.begin(),
			regs.end(),
			[orderedVector](uint32_t a, uint32_t b) -> bool
	{
		auto it1 = std::find(orderedVector.begin(), orderedVector.end(), a);
		auto it2 = std::find(orderedVector.begin(), orderedVector.end(), b);

		return std::distance(it1, it2) > 0;
	});
}

FilterableLayout Filter::createArgsFilterableLayout(
			const std::vector<llvm::Value*>& group,
			const std::vector<llvm::Type*>& knownTypes) const
{
	FilterableLayout layout = separateArgValues(group);
	layout.knownTypes = knownTypes;

	orderFiterableLayout(layout);

	return layout;
}

FilterableLayout Filter::createRetsFilterableLayout(
			const std::vector<llvm::Value*>& group,
			llvm::Type* knownType) const
{
	std::vector<Type*> knownTypes = {knownType};
	return createRetsFilterableLayout(group, knownTypes);
}

FilterableLayout Filter::createRetsFilterableLayout(
			const std::vector<llvm::Value*>& group,
			const std::vector<llvm::Type*>& knownTypes) const
{
	FilterableLayout layout = separateRetValues(group);
	layout.knownTypes = knownTypes;

	orderFiterableLayout(layout);

	return layout;
}

FilterableLayout Filter::separateArgValues(const std::vector<llvm::Value*>& paramValues) const
{
	auto& regs = _cc->getParamRegisters();
	auto& fpRegs = _cc->getParamFPRegisters();
	auto& doubleRegs = _cc->getParamDoubleRegisters();
	auto& vecRegs = _cc->getParamVectorRegisters();

	return separateValues(paramValues, regs, fpRegs, doubleRegs, vecRegs);
}

FilterableLayout Filter::separateRetValues(const std::vector<llvm::Value*>& paramValues) const
{
	auto& regs = _cc->getReturnRegisters();
	auto& fpRegs = _cc->getReturnFPRegisters();
	auto& doubleRegs = _cc->getReturnDoubleRegisters();
	auto& vecRegs = _cc->getReturnVectorRegisters();

	FilterableLayout lay = separateValues(paramValues, regs, fpRegs, doubleRegs, vecRegs);
	lay.stacks.clear();

	return lay;
}

FilterableLayout Filter::separateValues(
		const std::vector<llvm::Value*>& paramValues,
		const std::vector<uint32_t>& gpRegs,
		const std::vector<uint32_t>& fpRegs,
		const std::vector<uint32_t>& doubleRegs,
		const std::vector<uint32_t>& vecRegs) const
{
	FilterableLayout layout;

	for (auto pv: paramValues)
	{
		if (_abi->isStackVariable(pv))
		{
			layout.stacks.push_back(pv);
		}
		else if (!_abi->isRegister(pv))
		{
			continue;
		}
		if (std::find(gpRegs.begin(), gpRegs.end(),
				_abi->getRegisterId(pv)) != gpRegs.end())
		{
			layout.gpRegisters.push_back(_abi->getRegisterId(pv));
		}
		else if (std::find(doubleRegs.begin(), doubleRegs.end(),
				_abi->getRegisterId(pv)) != doubleRegs.end())
		{
			layout.doubleRegisters.push_back(_abi->getRegisterId(pv));
		}
		else if (std::find(fpRegs.begin(), fpRegs.end(),
				_abi->getRegisterId(pv)) != fpRegs.end())
		{
			layout.fpRegisters.push_back(_abi->getRegisterId(pv));
		}
		else if (std::find(vecRegs.begin(), vecRegs.end(),
				_abi->getRegisterId(pv)) != vecRegs.end())
		{
			layout.vectorRegisters.push_back(_abi->getRegisterId(pv));
		}
	}

	return layout;
}

std::vector<llvm::Value*> Filter::createGroupedArgValues(const FilterableLayout& lay) const
{
	return createGroupedValues(lay);
}

std::vector<llvm::Value*> Filter::createGroupedRetValues(const FilterableLayout& lay) const
{
	return createGroupedValues(lay);
}

std::vector<llvm::Value*> Filter::createGroupedValues(const FilterableLayout& lay) const
{
	std::vector<Value*> paramValues;

	auto ri = lay.gpRegisters.begin();
	auto fi = lay.fpRegisters.begin();
	auto di = lay.doubleRegisters.begin();
	auto vi = lay.vectorRegisters.begin();
	auto si = lay.stacks.begin();

	if (!lay.knownOrder.empty())
	{
		for (auto ord : lay.knownOrder)
		{
			switch (ord)
			{
				case OrderID::ORD_GPR:
					if (ri != lay.gpRegisters.end())
					{
						paramValues.push_back(_abi->getRegister(*ri));
						ri++;
					}
				break;

				case OrderID::ORD_FPR:
					if (fi != lay.fpRegisters.end())
					{
						paramValues.push_back(_abi->getRegister(*fi));
						fi++;
					}
				break;

				case OrderID::ORD_DOUBR:
					if (di != lay.doubleRegisters.end())
					{
						paramValues.push_back(_abi->getRegister(*di));
						di++;
					}
				break;

				case OrderID::ORD_VECR:
					if (vi != lay.vectorRegisters.end())
					{
						paramValues.push_back(_abi->getRegister(*vi));
						vi++;
					}
				break;

				case OrderID::ORD_STACK:
					if (si != lay.stacks.end())
					{
						paramValues.push_back(*si);
						si++;
					}
				break;

				case OrderID::ORD_GPR_GROUP:
					if (ri != lay.gpRegisters.end())
					{
						ri++;
					}
				break;

				case OrderID::ORD_FPR_GROUP:
					if (fi != lay.fpRegisters.end())
					{
						fi++;
					}
				break;

				case OrderID::ORD_DOUBR_GROUP:
					if (di != lay.doubleRegisters.end())
					{
						di++;
					}
				break;

				case OrderID::ORD_VECR_GROUP:

					if (vi != lay.vectorRegisters.end())
					{
						vi++;
					}
				break;

				case OrderID::ORD_STACK_GROUP:
					if (si != lay.stacks.end())
					{
						si++;
					}
				break;

				default:
					continue;
			}
		}

		return paramValues;
	}

	while (ri != lay.gpRegisters.end())
	{
		paramValues.push_back(_abi->getRegister(*ri));
		ri++;
	}

	while (fi != lay.fpRegisters.end())
	{
		paramValues.push_back(_abi->getRegister(*fi));
		fi++;
	}

	while (di != lay.doubleRegisters.end())
	{
		paramValues.push_back(_abi->getRegister(*di));
		di++;
	}

	while (vi != lay.vectorRegisters.end())
	{
		paramValues.push_back(_abi->getRegister(*vi));
		vi++;
	}

	paramValues.insert(paramValues.end(), si, lay.stacks.end());

	return paramValues;
}

void Filter::leaveOnlyPositiveStacks(FilterableLayout& lay) const
{
	auto* config = _abi->getConfig();

	lay.stacks.erase(
		std::remove_if(lay.stacks.begin(), lay.stacks.end(),
			[config](const Value* li)
			{
				auto aOff = config->getStackVariableOffset(li);
				return aOff.has_value() && aOff.value() < 0;
			}),
		lay.stacks.end());
}

void Filter::leaveOnlyContinuousStack(FilterableLayout& lay) const
{
	std::optional<int> prevOff;
	int gap = _cc->getMaxBytesPerStackParam();
	auto* config = _abi->getConfig();

	auto it = lay.stacks.begin();
	while (it != lay.stacks.end())
	{
		auto off = config->getStackVariableOffset(*it);

		if (!off.has_value())
		{
			++it;
			continue;
		}
		else if (!prevOff.has_value())
		{
			prevOff = off;
		}
		else if (std::abs(prevOff.value() - off.value()) > gap)
		{
			it = lay.stacks.erase(it);
			continue;
		}
		else
		{
			prevOff = off;
		}

		++it;
	}
}

void Filter::leaveOnlyContinuousArgRegisters(FilterableLayout& lay) const
{
	leaveOnlyContinuousRegisters(lay.gpRegisters, _cc->getParamRegisters());
	leaveOnlyContinuousRegisters(lay.fpRegisters, _cc->getParamFPRegisters());
	leaveOnlyContinuousRegisters(lay.doubleRegisters, _cc->getParamDoubleRegisters());
	leaveOnlyContinuousRegisters(lay.vectorRegisters, _cc->getParamVectorRegisters());

	bool usingGPR = !_cc->getParamRegisters().empty();
	bool usingFPR = !_cc->getParamFPRegisters().empty();
	bool usingDR = !_cc->getParamDoubleRegisters().empty();
	bool usingVR = !_cc->getParamVectorRegisters().empty();

	bool missingGPR = lay.gpRegisters.size() < _cc->getParamRegisters().size();
	bool missingFPR = lay.fpRegisters.size() < _cc->getParamFPRegisters().size();
	bool missingDR = lay.doubleRegisters.size() < _cc->getParamDoubleRegisters().size();
	bool missingVR = lay.vectorRegisters.size() < _cc->getParamVectorRegisters().size();

	// If calling convention passes large objects on stacks (not by refetence)
	// usage of another registers will be omitted.
	//
	// Stacks can be erased only if all types of registers that a cc
	// uses are missing some register usage.

	bool eraseStacks = false;
	if (_cc->passesLargeObjectsByReference())
	{
		if (usingGPR)
		{
			eraseStacks = missingGPR;
		}

		if (usingFPR)
		{
			eraseStacks = eraseStacks && missingFPR;
		}

		if (usingDR)
		{
			eraseStacks = eraseStacks && missingDR;
		}

		if (usingVR)
		{
			eraseStacks = eraseStacks && missingVR;
		}
	}

	if (eraseStacks)
	{
		lay.stacks.clear();
	}
}

void Filter::createContinuousArgRegisters(FilterableLayout& lay) const
{
	std::vector<uint32_t> gpRegs, fpRegs, dbRegs, veRegs;

	if (!lay.gpRegisters.empty())
	{
		uint32_t regId = lay.gpRegisters.back();

		for (auto ccR : _cc->getParamRegisters())
		{
			gpRegs.push_back(ccR);
			if (regId == ccR)
			{
				break;
			}
		}
	}

	if (!lay.fpRegisters.empty())
	{
		uint32_t regId = lay.fpRegisters.back();

		for (auto ccR : _cc->getParamFPRegisters())
		{
			fpRegs.push_back(ccR);
			if (regId == ccR)
			{
				break;
			}
		}
	}

	if (!lay.doubleRegisters.empty())
	{
		uint32_t regId = lay.doubleRegisters.back();

		for (auto ccR : _cc->getParamDoubleRegisters())
		{
			dbRegs.push_back(ccR);
			if (regId == ccR)
			{
				break;
			}
		}
	}

	if (!lay.vectorRegisters.empty())
	{
		uint32_t regId = lay.vectorRegisters.back();

		for (auto ccR : _cc->getParamRegisters())
		{
			veRegs.push_back(ccR);
			if (regId == ccR)
			{
				break;
			}
		}
	}

	lay.gpRegisters = std::move(gpRegs);
	lay.fpRegisters = std::move(fpRegs);
	lay.doubleRegisters = std::move(dbRegs);
	lay.vectorRegisters = std::move(veRegs);
}

void Filter::leaveOnlyContinuousRetRegisters(FilterableLayout& lay) const
{
	leaveOnlyContinuousRegisters(lay.gpRegisters, _cc->getReturnRegisters());
	leaveOnlyContinuousRegisters(lay.fpRegisters, _cc->getReturnFPRegisters());
	leaveOnlyContinuousRegisters(lay.doubleRegisters, _cc->getReturnDoubleRegisters());
	leaveOnlyContinuousRegisters(lay.vectorRegisters, _cc->getReturnVectorRegisters());
}

void Filter::leaveOnlyContinuousRegisters(
				std::vector<uint32_t>& regs,
				const std::vector<uint32_t>& templRegs) const
{
	auto itEnd = regs.end();
	auto it = regs.begin();
	for (auto regId : templRegs)
	{
		if (it == itEnd)
		{
			break;
		}

		if (regId != *it)
		{
			regs.erase(it, itEnd);
			break;
		}

		it++;
	}
}

void Filter::leaveSameStacks(FilterableLayout& lay, const FilterableLayout& fig) const
{
	lay.stacks.resize(fig.stacks.size(), nullptr);
}

//
//=============================================================================
//  FilterProvider
//=============================================================================
//

Filter::Ptr FilterProvider::createFilter(Abi* abi, const CallingConvention::ID& id)
{
	auto* cc = abi->getCallingConvention(id);
	if (cc == nullptr)
	{
		cc = abi->getDefaultCallingConvention();
	}

	assert(cc);

	auto c = abi->getConfig();
	bool isMinGW = c->getConfig().tools.isGcc()
			&& c->getConfig().fileFormat.isPe();

	if (abi->isX64() && (isMinGW || c->getConfig().tools.isMsvc()))
	{
		return std::make_unique<MSX64Filter>(abi, cc);
	}

	return std::make_unique<Filter>(abi, cc);
}

}
}

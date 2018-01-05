/**
* @file src/bin2llvmir/analyses/indirectly_called_funcs_analysis.cpp
* @brief Implementation of indirectly called functions analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/analyses/indirectly_called_funcs_analysis.h"
#include "retdec/bin2llvmir/utils/instruction.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/**
* @brief Returns @c true if arguments in @a callInst and parameters in @a func
*        are equal, otherwise @c false.
*/
bool hasEqArgsAndParams(const CallInst &call, Function &func)
{
	if (func.arg_size() != call.getNumArgOperands())
	{
		return false;
	}

	auto it = func.arg_begin();
	int pos = 0;
	while (it != func.arg_end())
	{
		if (it->getType() != call.getArgOperand(pos)->getType())
		{
			return false;
		}
		++it;
		++pos;
	}

	return true;
}

} // anonymous namespace

/**
* @brief Tries to find functions that can be called by indirect calls.
*
* @par Preconditions
*  - @a callInsts are a calls that calls some function indirectly.
*
* @param[in] call We try to find functions for this indirect calls.
* @param[in] funcsToCheck We are finding functions that can be indirectly called
*            only in this functions.
*
* @return Found functions that can be called indirectly.
*/
FuncSet IndirectlyCalledFuncsAnalysis::getFuncsForIndirectCalls(
		const CallInstSet &call,
		Module::FunctionListType &funcsToCheck)
{
	FuncVec funcVec;
	for (Function &func : funcsToCheck)
	{
		funcVec.push_back(&func);
	}

	FuncSet indirectlyCalledFuncs;
	for (CallInst *callInst : call)
	{
		addToSet(getFuncsForIndirectCall(*callInst, funcVec),
			indirectlyCalledFuncs);
	}

	return indirectlyCalledFuncs;
}

/**
* @brief Tries to find functions that can be called by indirect call.
*
* @par Preconditions
*  - @a callInst is a call that calls some function indirectly.
*
* @param[in] call We try to find functions for this indirect call.
* @param[in] funcsToCheck We are finding functions that can be indirectly called
*            only in this functions.
*
* @return Found functions that can be called indirectly.
*/
FuncSet IndirectlyCalledFuncsAnalysis::getFuncsForIndirectCall(
		const CallInst &call,
		const FuncVec &funcsToCheck)
{
	assert(isIndirectCall(call) && "Expected an indirect call.");

	FuncSet result;
	Type *callReturnType = call.getType();
	for (Function *func : funcsToCheck)
	{
		if (func->getReturnType() != callReturnType)
		{
			continue;
		}

		if (!func->isVarArg())
		{
			if (!hasEqArgsAndParams(call, *func))
			{
				continue;
			}
		}

		result.insert(func);
	}

	return result;
}

} // namespace bin2llvmir
} // namespace retdec

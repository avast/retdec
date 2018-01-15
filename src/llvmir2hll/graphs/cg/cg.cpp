/**
* @file src/llvmir2hll/graphs/cg/cg.cpp
* @brief Implementation of CG.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstddef>

#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new information about called functions.
*
* For the description of parameters, see the description of data members of
* CalledFuncs.
*/
CG::CalledFuncs::CalledFuncs(ShPtr<Function> caller, bool callsOnlyDefinedFuncs,
	bool callsByPointer): caller(caller),
		callsOnlyDefinedFuncs(callsOnlyDefinedFuncs),
		callsByPointer(callsByPointer) {}

/**
* @brief Constructs a new call graph.
*
* @param[in] module Module for which this call graph is created.
*/
CG::CG(ShPtr<Module> module): module(module), callerCalleeMap() {}

/**
* @brief Destructs the call graph.
*/
CG::~CG() {}

/**
* @brief Returns the module for which this call graph has been created.
*/
ShPtr<Module> CG::getCorrespondingModule() const {
	return module;
}

/**
* @brief Returns called functions from the given function.
*
* @param[in] func Function for which called functions are obtained.
* @param[in] includeIndirectCalls If @c true, also indirect calls are
*                                 considered, e.g. if @a func calls @c foo()
*                                 and @c foo() calls @c bar(), then @c bar() is
*                                 included into the result.
*
* If @a func is a declaration, then the @c callees data member of the result
* will be empty.
*
* If @a func doesn't belong to the underlying module, the null pointer is
* returned.
*/
ShPtr<CG::CalledFuncs> CG::getCalledFuncs(ShPtr<Function> func,
		bool includeIndirectCalls) const {
	auto i = callerCalleeMap.find(func);
	if (i != callerCalleeMap.end()) {
		if (includeIndirectCalls) {
			return computeIndirectCalls(i->second);
		} else {
			return i->second;
		}
	}

	// func is not present in the underlying module.
	return ShPtr<CalledFuncs>();
}

/**
* @brief Computes indirect calls from the given called functions.
*
* This function doesn't change @a calledFuncs.
*/
ShPtr<CG::CalledFuncs> CG::computeIndirectCalls(ShPtr<CalledFuncs> calledFuncs) const {
	// Initialization.
	ShPtr<CalledFuncs> indCalledFuncs(new CalledFuncs(calledFuncs->caller));
	indCalledFuncs->callees = calledFuncs->callees;
	indCalledFuncs->callsOnlyDefinedFuncs = calledFuncs->callsOnlyDefinedFuncs;
	indCalledFuncs->callsByPointer = calledFuncs->callsByPointer;

	// We keep calling getCalledFuncs() for each obtained function until the
	// set of called functions doesn't change (i.e. until we find a fixed
	// point). Notice that we cannot call getCalledFuncs() with the second
	// argument being true because we would end up in an infinite recursion.
	//
	// Since we increase the number of called functions at each iteration,
	// it suffices to keep a counter of how many functions were originally
	// there. To find out whether we should continue, we just compare the
	// number of functions in the current result with the previous one.
	std::size_t oldNumOfCallees;
	do {
		oldNumOfCallees = indCalledFuncs->callees.size();

		// Since we're iterating over indCalledFuncs->callees, we cannot change
		// this container (C++ doesn't allow modifying a set while iterating
		// over it). Therefore, we first store which new functions we should
		// add, and we add them after the iteration.
		FuncSet newFuncCalls;
		// For each callee...
		for (const auto &callee : indCalledFuncs->callees) {
			// Update the result.
			ShPtr<CalledFuncs> calleeCalledFuncs(getCalledFuncs(callee));
			addToSet(calleeCalledFuncs->callees, newFuncCalls);
			if (!calleeCalledFuncs->callsOnlyDefinedFuncs) {
				indCalledFuncs->callsOnlyDefinedFuncs = false;
			}
			if (calleeCalledFuncs->callsByPointer) {
				indCalledFuncs->callsByPointer = true;
			}
		}
		addToSet(newFuncCalls, indCalledFuncs->callees);
	} while (oldNumOfCallees < indCalledFuncs->callees.size());

	return indCalledFuncs;
}

/**
* @brief Returns an iterator to the first caller.
*/
CG::caller_iterator CG::caller_begin() const {
	return callerCalleeMap.begin();
}

/**
* @brief Returns an iterator past the last caller.
*/
CG::caller_iterator CG::caller_end() const {
	return callerCalleeMap.end();
}

} // namespace llvmir2hll
} // namespace retdec

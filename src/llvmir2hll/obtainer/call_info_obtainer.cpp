/**
* @file src/llvmir2hll/obtainer/call_info_obtainer.cpp
* @brief Implementation of CallInfoObtainer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstddef>

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/graphs/cfg/cfg_builders/non_recursive_cfg_builder.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/container.h"

using namespace retdec::llvm_support;

using retdec::utils::hasItem;
using retdec::utils::setDifference;
using retdec::utils::setUnion;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new piece of information about the given function call.
*/
CallInfo::CallInfo(ShPtr<CallExpr> call):
	call(call) {}

/**
* @brief Destructs the piece of information.
*
* A default implementation is provided.
*/
CallInfo::~CallInfo() {}

/**
* @brief Returns the function call for which the piece of information has been
*        computed.
*/
ShPtr<CallExpr> CallInfo::getCall() const {
	return call;
}

/**
* @brief Constructs a new piece of information about the given function.
*/
FuncInfo::FuncInfo(ShPtr<Function> func):
	func(func) {}

/**
* @brief Destructs the piece of information.
*
* A default implementation is provided.
*/
FuncInfo::~FuncInfo() {}

/**
* @brief Returns the function for which the piece of information has been
*        computed.
*/
ShPtr<Function> FuncInfo::getFunc() const {
	return func;
}

/**
* @brief Constructs a new obtainer.
*/
CallInfoObtainer::CallInfoObtainer():
	module(), cg(), va(), funcCFGMap(),
	cfgBuilder(NonRecursiveCFGBuilder::create()) {}

/**
* @brief Destructs the obtainer.
*/
CallInfoObtainer::~CallInfoObtainer() {}

/**
* @brief Returns the call graph with which the obtainer has been initialized.
*
* If the obtainer hasn't been initialized, this function returns the null
* pointer.
*/
ShPtr<CG> CallInfoObtainer::getCG() const {
	return cg;
}

/**
* @brief Returns the CFG for @a func after the obtainer has been initialized.
*
* If the obtainer hasn't been initialized or there is no CFG for @a func, it
* returns the null pointer.
*/
ShPtr<CFG> CallInfoObtainer::getCFGForFunc(ShPtr<Function> func) const {
	auto i = funcCFGMap.find(func);
	return i != funcCFGMap.end() ? i->second : ShPtr<CFG>();
}

/**
* @brief Initializes the obtainer.
*
* @param[in] cg The obtainer will be initialized with this call graph.
* @param[in] va The used analysis of values.
*
* This member function has to be called (1) when an instance of this class (or
* its subclass) is created and (2) whenever the current module is changed in a
* way that changes the call graph of the module and/or the variables which are
* read/modified in a function.
*
* @par Preconditions
*  - both @a va and @a cg are non-null
*  - @a va is in a valid state
*
* This function leaves @a va in a valid state.
*/
void CallInfoObtainer::init(ShPtr<CG> cg, ShPtr<ValueAnalysis> va) {
	PRECONDITION_NON_NULL(cg);
	PRECONDITION(va->isInValidState(), "it is not in a valid state");

	this->cg = cg;
	this->va = va;
	module = cg->getCorrespondingModule();
	funcCFGMap.clear();

	// To speedup the initialization, compute and store the CFG for each
	// function.
	for (auto i = module->func_begin(), e = module->func_end(); i != e; ++i) {
		funcCFGMap[*i] = cfgBuilder->getCFG(*i);
	}
}

/**
* @brief Returns @c true if the obtainer has been initialized, @c false
*        otherwise.
*/
bool CallInfoObtainer::isInitialized() const {
	return cg && module;
}

/**
* @brief Computes an order in which FuncInfos should be computed.
*
* See the description of FuncInfoCompOrder for some more information.
*/
ShPtr<CallInfoObtainer::FuncInfoCompOrder> CallInfoObtainer::getFuncInfoCompOrder(
		ShPtr<CG> cg) {
	ShPtr<FuncInfoCompOrder> fico(new FuncInfoCompOrder());

	// Below, remainingFuncs contains functions which haven't been added into
	// the computation order. In computedFuncs, we store functions which have
	// been added into the computation order. Our algorithm terminates when
	// remainingFuncs is empty.
	//
	// In the initialization, we add all function declarations into fico->order
	// and into computedFuncs because they have to be computed before FuncInfos
	// for function definitions are computed.
	FuncSet remainingFuncs(
		module->func_definition_begin(),
		module->func_definition_end()
	);
	FuncSet computedFuncs(
		module->func_declaration_begin(),
		module->func_declaration_end()
	);
	fico->order.assign(
		module->func_declaration_begin(),
		module->func_declaration_end()
	);

	fico->sccs = computeSCCs();

	// The main algorithm.
	while (!remainingFuncs.empty()) {
		// Keep including functions which call just functions from
		// computedFuncs into fico->order until fico->order is unchanged.
		std::size_t oldFicoOrderSize;
		do {
			oldFicoOrderSize = fico->order.size();
			// Since remainingFuncs may be modified during the following
			// iteration over it, iterate over a copy of it.
			FuncSet remainingFuncsCopy(remainingFuncs);
			for (const auto &func : remainingFuncsCopy) {
				if (callsJustComputedFuncs(func, computedFuncs)) {
					fico->order.push_back(func);
					remainingFuncs.erase(func);
					computedFuncs.insert(func);
				}
			}
		} while (oldFicoOrderSize < fico->order.size());

		if (!remainingFuncs.empty()) {
			// There has to be an SCC. We find a next SCC, include a member of
			// it into fico->order, mark all functions in the SCC as computed,
			// and move to the next iteration.
			SCCWithRepresent sccWithRepresent(findNextSCC(fico->sccs,
				computedFuncs, remainingFuncs));
			fico->order.push_back(sccWithRepresent.represent);
			for (auto i = sccWithRepresent.scc.begin(),
					e = sccWithRepresent.scc.end(); i != e; ++i) {
				computedFuncs.insert(*i);
				remainingFuncs.erase(*i);
			}
		}
	}

	return fico;
}

/**
* @brief Returns @c true if @a func calls just functions from @a computedFuncs,
*        @c false otherwise.
*/
bool CallInfoObtainer::callsJustComputedFuncs(ShPtr<Function> func,
		const FuncSet &computedFuncs) const {
	ShPtr<CG::CalledFuncs> calledFuncs(cg->getCalledFuncs(func));
	for (const auto &callee : calledFuncs->callees) {
		if (!hasItem(computedFuncs, callee)) {
			return false;
		}
	}
	return true;
}

/**
* @brief Finds a next SCC and its represent and returns them.
*
* @param[in] sccs All SCCs in the call graph.
* @param[in] computedFuncs Functions that already have been included in
*                          FuncInfoCompOrder::order.
* @param[in] remainingFuncs Functions that haven't been included in
*                           FuncInfoCompOrder::order.
*
* @par Preconditions
*  - @a remainingFuncs is non-empty
*  - @a remainingFuncs doesn't contain a function which calls just functions
*    from @a computedFuncs.
*/
CallInfoObtainer::SCCWithRepresent CallInfoObtainer::findNextSCC(const FuncSetSet &sccs,
		const FuncSet &computedFuncs, const FuncSet &remainingFuncs) const {
	PRECONDITION(!remainingFuncs.empty(), "it should not be empty");

	//
	// We try to locate an SCC whose members call just the functions in
	// the SCC or in computedFuncs. Then, if the found SCC contains a function
	// from remainingFuncs, return the function.
	//
	// For every SCC...
	for (const auto &scc : sccs) {
		bool sccFound = true;
		ShPtr<Function> funcFromRemainingFuncs;
		// For every function in the SCC...
		for (const auto &func : scc) {
			// Check whether the function calls just the functions in the SCC
			// or in computedFuncs.
			ShPtr<CG::CalledFuncs> calledFuncs(cg->getCalledFuncs(func));
			FuncSet mayCall(setUnion(scc, computedFuncs));
			if (!setDifference(calledFuncs->callees, mayCall).empty()) {
				sccFound = false;
			} else {
				// Have we encountered a function from remainingFuncs?
				if (hasItem(remainingFuncs, func)) {
					funcFromRemainingFuncs = func;
				}
			}
		}
		if (sccFound && funcFromRemainingFuncs) {
			return SCCWithRepresent(scc, funcFromRemainingFuncs);
		}
	}

	// TODO Can this happen?
	printWarningMessage("[SCCComputer] No viable SCC has been found.");
	FuncSet scc;
	ShPtr<Function> func(*(remainingFuncs.begin()));
	scc.insert(func);
	return SCCWithRepresent(scc, func);
}

/**
* @brief Computes all SCCs in the current call graph and returns them.
*
* A single function is not considered to be an SCC unless it contains a call to
* itself (see the description of FuncInfoCompOrder).
*/
CallInfoObtainer::FuncSetSet CallInfoObtainer::computeSCCs() {
	return SCCComputer::computeSCCs(cg);
}

/**
* @brief Emits the order to standard error.
*
* Only for debugging purposes.
*/
void CallInfoObtainer::FuncInfoCompOrder::debugPrint() const {
	llvm::errs() << "[FuncInfoCompOrder] Debug info:\n";

	// order
	llvm::errs() << "order: <";
	dump(order, dumpFuncGetName<ShPtr<Function>>, ", ", ">\n");

	// SCCs
	bool setPrinted = false;
	llvm::errs() << "sccs: {";
	for (const auto &scc : sccs) {
		if (setPrinted) {
			llvm::errs() << ", ";
		}
		llvm::errs() << "{";
		dump(scc, dumpFuncGetName<ShPtr<Function>>, ", ", "}");
		setPrinted = true;
	}
	llvm::errs() << "}\n\n";
}

/**
* @brief Constructs a computer.
*
* @param[in] cg Call graph of the current module.
*
* @par Preconditions
*  - @a cg is non-null
*/
CallInfoObtainer::SCCComputer::SCCComputer(ShPtr<CG> cg): cg(cg), index(0) {
	PRECONDITION_NON_NULL(cg);

	for (auto i = cg->caller_begin(), e = cg->caller_end(); i != e; ++i) {
		calledFuncInfoMap[i->second] = CalledFuncInfo();
	}
}

/**
* @brief Destructs the computer.
*/
CallInfoObtainer::SCCComputer::~SCCComputer() {}

/**
* @brief Computes and returns all strongly connected components (SCCs) in the
*        given call graph.
*
* @par Preconditions
*  - @a cg is non-null
*
* A single function is not considered to be an SCC unless it contains a call to
* itself (see the description of FuncInfoCompOrder).
*/
CallInfoObtainer::FuncSetSet CallInfoObtainer::SCCComputer::computeSCCs(
		ShPtr<CG> cg) {
	PRECONDITION_NON_NULL(cg);

	ShPtr<SCCComputer> sccComputer(new SCCComputer(cg));
	return sccComputer->findSCCs();
}

/**
* @brief Finds and returns all strongly connected components (SCCs) in the
*        given call graph.
*
* A single function is not considered to be an SCC unless it contains a call to
* itself (see the description of FuncInfoCompOrder).
*/
CallInfoObtainer::FuncSetSet CallInfoObtainer::SCCComputer::findSCCs() {
	// The following code corresponds to the code from
	// http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm

	// Initialization.
	index = 0;
	while (!stack.empty()) {
		stack.pop();
	}

	// Computation.
	for (auto &p : calledFuncInfoMap) {
		if (p.second.index < 0) { // '< 0' means 'undefined'
			visit(p.first, p.second);
		}
	}

	return sccs;
}

/**
* @brief Visits the given node in the call graph.
*
* @param[in] calledFunc The given node.
* @param[in,out] calledFuncInfo Information about @a calledFunc.
*
* Corresponds to the strongconnect(v) function from
* http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm
*/
void CallInfoObtainer::SCCComputer::visit(ShPtr<CG::CalledFuncs> calledFunc,
		CalledFuncInfo &calledFuncInfo) {
	// Set the depth index for calledFunc to the smallest unused index.
	calledFuncInfo.index = calledFuncInfo.lowlink = index;
	index++;

	// Push calledFunc onto the stack.
	stack.push(calledFunc);
	calledFuncInfo.onStack = true;

	// Consider the successors of calledFunc.
	for (const auto &callee : calledFunc->callees) {
		ShPtr<CG::CalledFuncs> succ(cg->getCalledFuncs(callee));
		CalledFuncInfo &succInfo(calledFuncInfoMap[succ]);
		if (succInfo.index < 0) { // '< 0' means 'undefined'
			// The successor has not yet been visited; recurse on it.
			visit(succ, succInfo);
			calledFuncInfo.lowlink = std::min(calledFuncInfo.lowlink,
				succInfo.lowlink);
		} else if (succInfo.onStack) {
			// The successor is on the stack and hence in the current SCC.
			calledFuncInfo.lowlink = std::min(calledFuncInfo.lowlink,
				succInfo.index);
		}
	}

	// If calledFunc is a root node, pop the stack and generate an SCC.
	if (calledFuncInfo.lowlink == calledFuncInfo.index) {
		// Generate a new SCC.
		FuncSet scc;
		ShPtr<CG::CalledFuncs> poppedCalledFunc;
		do {
			poppedCalledFunc = stack.top();
			stack.pop();
			calledFuncInfoMap[cg->getCalledFuncs(
				poppedCalledFunc->caller)].onStack = false;

			scc.insert(poppedCalledFunc->caller);
		} while (calledFunc != poppedCalledFunc);

		// Store the generated SCC. However, if the SCC contains just a single
		// function, do this only if it calls itself (see the description of
		// computeSCCs()).
		if (scc.size() != 1 || hasItem(calledFunc->callees, calledFunc->caller)) {
			sccs.insert(scc);
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec

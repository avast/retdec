/**
* @file src/bin2llvmir/analyses/reachable_funcs_analysis.cpp
* @brief Implementation of reachable functions analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/InstVisitor.h>

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/analyses/indirectly_called_funcs_analysis.h"
#include "retdec/bin2llvmir/analyses/reachable_funcs_analysis.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/**
* @brief Call analysis.
*/
class CallAnalysis: private InstVisitor<CallAnalysis> {
public:
	CallAnalysis();
	~CallAnalysis();

	bool isFuncDirectlySelfRecursive(Function &func);

private:
	friend class InstVisitor<CallAnalysis>;
	void visitCallInst(CallInst &callInst);

private:
	/// Signals if we have self recursive function.
	bool isSelfRecursive;

	/// Function to analyze.
	Function *funcToAnalyze;
};

/**
* @brief Constructs a call analysis.
*/
CallAnalysis::CallAnalysis(): isSelfRecursive(false), funcToAnalyze(nullptr) {}

/**
* @brief Destructs a call analysis.
*/
CallAnalysis::~CallAnalysis() {}

/**
* @brief Returns @c true if @a func is self directly recursive, otherwise
*        @c false.
*/
bool CallAnalysis::isFuncDirectlySelfRecursive(Function &func) {
	funcToAnalyze = &func;
	isSelfRecursive = false;

	// Go through calls.
	visit(funcToAnalyze);

	return isSelfRecursive;
}

/**
* @brief Finds out if function is self recursive.
*/
void CallAnalysis::visitCallInst(CallInst &callInst) {
	Function *calledFunc(callInst.getCalledFunction());

	if (!calledFunc) {
		// Indirect call, so skip.
		return;
	}

	if (calledFunc == funcToAnalyze) {
		isSelfRecursive = true;
	}
}

/**
* @brief Indirect calls finder.
*/
class IndirectCallsFinder: private InstVisitor<IndirectCallsFinder> {
public:
	IndirectCallsFinder();
	~IndirectCallsFinder();

	std::set<llvm::CallInst*> getIndirectCallsFor(const std::set<llvm::Function*> &funcs);

private:
	friend class InstVisitor<IndirectCallsFinder>;
	void visitCallInst(CallInst &callInst);

private:
	/// Set of indirect calls.
	std::set<llvm::CallInst*> indirectCalls;
};

/**
* @brief Constructs an indirect calls finder.
*/
IndirectCallsFinder::IndirectCallsFinder() {}

/**
* @brief Destructs an indirect calls finder.
*/
IndirectCallsFinder::~IndirectCallsFinder() {}

/**
* @brief Finds indirect calls.
*/
void IndirectCallsFinder::visitCallInst(CallInst &callInst) {
	if (callInst.getCalledFunction() == nullptr) {
		indirectCalls.insert(&callInst);
	}
}

/**
* @brief Returns all indirect calls that are in @a funcs.
*/
std::set<llvm::CallInst*> IndirectCallsFinder::getIndirectCallsFor(const std::set<llvm::Function*>& funcs) {
	for (Function *func : funcs) {
		visit(*func);
	}

	return indirectCalls;
}

/**
* @brief Returns @c true if @a func is self recursive, otherwise @c false.
*/
bool isDirectlySelfRecursive(Function &toCheck) {
	CallAnalysis callAnalysis;
	return callAnalysis.isFuncDirectlySelfRecursive(toCheck);
}

/**
* @brief Returns @c true if @a funcNodeToCheck contains defined function,
*        otherwise @c false.
*/
bool containsDefinedFunc(CallGraphNode &funcNodeToCheck) {
	Function *funcToCheck(funcNodeToCheck.getFunction());
	if (!funcToCheck) {
		// We have for example end node of call graph.
		return false;
	}

	if (funcToCheck->isDeclaration()) {
		// We have only declared function.
		return false;
	}

	return true;
}

} // anonymous namespace

/**
* @brief Constructs a new reachable functions analysis.
*/
ReachableFuncsAnalysis::ReachableFuncsAnalysis() {}

/**
* @brief Destructs a reachable functions analysis.
*/
ReachableFuncsAnalysis::~ReachableFuncsAnalysis() {}

/**
* @brief Returns defined functions that are reachable directly and indirectly
*        from function @a func.
*
* @param[in] func We are finding defined functions that are reachable from
*            this function.
* @param[in] module We are considering only functions in this module.
* @param[in] callGraph We are finding in this call graph.
*/
std::set<llvm::Function*> ReachableFuncsAnalysis::getReachableDefinedFuncsFor(
		llvm::Function &func, Module &module, llvm::CallGraph &callGraph) {
	std::set<llvm::Function*> reachableFuncs{&func};
	std::size_t reachableSize(0);
	ReachableFuncsAnalysis reachableFuncsAnalysis;

	addToSet(reachableFuncsAnalysis.getDirectlyReachableDefinedFuncsFor(
			reachableFuncs, callGraph), reachableFuncs);

	do {
		// Need to iterate while changing, because reachable functions can call
		// indirect calls and from this indirect calls can be called some other
		// functions, so all of these functions are reachable from the start
		// function.
		reachableSize = reachableFuncs.size();

		// Calculate direct reachable functions for current reachable functions.
		addToSet(reachableFuncsAnalysis.getDirectlyReachableDefinedFuncsFor(
			reachableFuncs, callGraph), reachableFuncs);

		// Calculate indirect reachable functions for current reachable
		// functions.
		addToSet(reachableFuncsAnalysis.getIndirectlyReachableDefinedFuncsFor(
			reachableFuncs, module), reachableFuncs);
	} while (reachableSize != reachableFuncs.size());

	return reachableFuncs;
}

/**
* @brief Returns functions that are referenced from global variables,
* such as virtual function tables
*
* @param[in] module We are considering only globals and functions in this module.
*/
std::set<llvm::Function*> ReachableFuncsAnalysis::getGloballyReachableFuncsFor(llvm::Module &module) {
	std::set<llvm::Function*> reachableFuncs;
	for (GlobalVariable &global : module.getGlobalList()) {
		if (global.hasInitializer() && isa<ConstantStruct>(global.getInitializer())) {
			ConstantStruct *Struct = cast<ConstantStruct>(global.getInitializer());
			for (unsigned i = 0; i < Struct->getNumOperands(); ++i) {
				Value *el = Struct->getOperand(i);
				if (isa<Function>(el)) {
					reachableFuncs.insert(cast<Function>(el));
				}
			}
		}
	}
	return reachableFuncs;
}

/**
* @brief Returns defined functions that are directly reachable from @a funcs
*
* @param[in] funcs We are finding defined functions that are reachable from
*            this functions.
* @param[in] callGraph We are finding in this call graph.
*/
std::set<llvm::Function*> ReachableFuncsAnalysis::getDirectlyReachableDefinedFuncsFor(
		const std::set<llvm::Function*> &funcs, llvm::CallGraph &callGraph) const {
	std::set<llvm::Function*> reachableFuncs;
	for (Function *func : funcs) {
		CallGraphNode *funcNode(callGraph[func]);
		addToSet(getDirectlyReachableDefinedFuncsFor(*funcNode),
			reachableFuncs);
	}

	return reachableFuncs;
}

/**
* @brief Returns defined functions that are directly reachable from function in
*        @a reachableFrom.
*/
std::set<llvm::Function*> ReachableFuncsAnalysis::getDirectlyReachableDefinedFuncsFor(
		llvm::CallGraphNode &reachableFrom) const {
	std::set<llvm::Function*> reachableDefinedFuncs;
	for (scc_iterator<CallGraphNode *> i = scc_begin(&reachableFrom),
			e = scc_end(&reachableFrom); i != e; ++i) {
		// For example we have this code:
		// void func() {
		//   return;
		// }
		// int main() {
		//   func();
		// }
		// This iteration goes through functions that are reachable from
		// function which is in input parameter of this method. Unfortunately
		// call graph contains end call graph node and consider reachable
		// function same function from which we do an analysis. So if we want to
		// get reachable functions from main we get in this iteration functions
		// like main, func and end call graph node. So we need to check if main
		// is self recursive and we want to add only defined functions. So we
		// don't want to add end node for example.
		const std::vector<llvm::CallGraphNode*> &callNodesVec(*i);
		for (auto &node : callNodesVec) {
			// Goes through functions that created one strongly connected
			// component. But here we don't need to consider that we have
			// strongly connected component. Just go through functions.
			Function *funcToCheck(node->getFunction());
			if (node == &reachableFrom) {
				// Need to check if function from which we do analysis is
				// self recursive because this means that is reachable from its
				// own.
				if (isDirectlySelfRecursive(*funcToCheck)) {
					reachableDefinedFuncs.insert(funcToCheck);
				}
				continue;
			}

			if (containsDefinedFunc(*node)) {
				reachableDefinedFuncs.insert(funcToCheck);
			}
		}
	}

	return reachableDefinedFuncs;
}

/**
* @brief Returns indirectly reachable functions from @a funcs that are in
*        @a module.
*/
std::set<llvm::Function*> ReachableFuncsAnalysis::getIndirectlyReachableDefinedFuncsFor(
		const std::set<llvm::Function*> &funcs, Module &module) const {
	IndirectCallsFinder indirectCallsFinder;
	// Calculate indirect calls for current reachable functions.
	std::set<llvm::CallInst*> indirectCalls(indirectCallsFinder.
		getIndirectCallsFor(funcs));
	return IndirectlyCalledFuncsAnalysis::getFuncsForIndirectCalls(
		indirectCalls, module.getFunctionList());
}

} // namespace bin2llvmir
} // namespace retdec

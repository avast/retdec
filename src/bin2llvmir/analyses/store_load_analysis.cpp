/**
* @file src/bin2llvmir/analyses/store_load_analysis.cpp
* @brief Implementation of store-load analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/analyses/indirectly_called_funcs_analysis.h"
#include "retdec/bin2llvmir/analyses/store_load_analysis.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
* @brief Emits all functions info to standard error.
*
* Only for debugging purposes.
*/
void StoreLoadAnalysis::printFuncInfos() {
	errs() << "[StoreLoadAnalysis] Debug for functions info.\n";
	errs() << "--------------------------------------------------\n";
	for (auto &item : funcInfoMap) {
		item.second->printFuncInfo();
	}
}

/**
* @brief Emits all basic blocks info to standard error.
*
* Only for debugging purposes.
*/
void StoreLoadAnalysis::printBBInfos() {
	errs() << "[StoreLoadAnalysis] Debug for basic blocks info.\n";
	errs() << "-----------------------------------------------\n";
	for (auto &item : bbInfoMap) {
		item.second->printBBInfo();
	}
}

/**
* @brief Emits basic block info to standard error.
*
* Only for debugging purposes.
*/
void StoreLoadAnalysis::BBInfo::printBBInfo() {
	errs() << "[StoreLoadAnalysis] Debug info for basic block: '" <<
		bb.getName() << "':\n";
	errs() << "*******************************************\n";
	bbInfo->printExtRUses();
	bbInfo->printNotGoThrough();
	bbInfo->printGlobsForIndirectCalls();
	bbInfo->printGlobsForCallsForFuncsOutOfModule();
	errs() << "Ordered instructions:\n";
	for (Instruction *inst : orderedInstVec) {
		errs() << "     Ordered instruction: '" << *inst << "'\n";
	}
	errs() << "*******************************************\n";
}

/**
* @brief Emits function info for @a func to standard error.
*
* Only for debugging purposes.
*/
void StoreLoadAnalysis::printFuncInfo(Function &func) {
	getFuncInfoFor(func).printFuncInfo();
}

/**
* @brief Emits function info to standard error.
*
* Only for debugging purposes.
*/
void StoreLoadAnalysis::FuncInfo::printFuncInfo() {
	errs() << "[StoreLoadAnalysis] Debug info for function: '" <<
		func.getName() << "':\n";
	errs() << "*******************************************\n";
	funcInfo->printExtRUses();
	funcInfo->printNotGoThrough();
	funcInfo->printLastLUses();
	funcInfo->printGlobsForIndirectCalls();
	funcInfo->printGlobsForCallsForFuncsOutOfModule();
	errs() << "Right uses for left use:\n";
	for (auto &item : rUsesForLUse) {
		errs() << "     Left use: '" << *item.first << "'\n";
		for (Instruction *rUse : item.second) {
			errs() << "          Right use: '" << *rUse << "'\n";
		}

	}
	errs() << "*******************************************\n";
}

/**
* @brief Creates a new store load analysis.
*/
StoreLoadAnalysis::StoreLoadAnalysis(): countWithFuncsOutOfModule(false),
	currFuncInfo(nullptr), currBBInfo(nullptr) {}

/**
* @brief Destructs a store load analysis.
*/
StoreLoadAnalysis::~StoreLoadAnalysis() {
	clear();
}

/**
* @brief Runs store load analysis and saves contained info.
*
* This method is need to run before methods that finds out results of this
* store load analysis.
*
* @param[in] module We want do analyze on this module.
* @param[in] globs We want to do analyze on these global variables.
* @param[in] callGraph We want to do analyze on functions in this call graph.
* @param[in] funcsOutOfModule Signalizes if analysis have to count with
*            functions defined out of module.
*/
void StoreLoadAnalysis::doAnalysis(Module &module, std::set<llvm::GlobalVariable*> &globs,
		CallGraph &callGraph, bool funcsOutOfModule) {
	// If analysis was run before than now is need to clear everything.
	clear();

	globsToAnalyze = globs;
	countWithFuncsOutOfModule = funcsOutOfModule;

	setFuncsInModule(module);

	// Initiate analysis for uses of global variables.
	usesAnalysis.doUsesAnalysis(globsToAnalyze);

	// Initiate analysis for functions.
	funcTraversalAnalysis.doFuncsAnalysis(callGraph);

	// Need to create function info before start analyze for all functions.
	createInfoForAllFuncs();

	runAnalysis();
}

/**
* @brief Clears allocated info.
*/
void StoreLoadAnalysis::clear() {
	// Clear functions info.
	for (auto &item : funcInfoMap) {
		delete item.second;
	}

	// Clear basic blocks info.
	for (auto &item : bbInfoMap) {
		delete item.second;
	}
}

/**
* @brief Returns @c true if @a store can reach function call of function that is
*        defined out of this module, otherwise @c false.
*/
bool StoreLoadAnalysis::isInLUsesForFuncOutOfModule(StoreInst &store) {
	return hasItem(lUsesForFuncsOutOfModule, &store);
}

/**
* @brief Returns if for @a globValue exists some right uses in @a func that can
*        be connected with some left use out of function.
*
* @par Preconditions
*  - Function @a func have to be analyzed.
*
* @code
* func() {
*   x = g; <- this right use can be connected with left use out of function.
* }
* @endcode
*
* @return @c true if exists some right use, otherwise @c false.
*/
bool StoreLoadAnalysis::hasSomeRUseEffectOutOfFunc(Value &globValue,
		Function &func) {
	return getFuncInfoFor(func).isInExtRUses(globValue);
}

/**
* @brief Tries to get instruction for extended right uses specified by
*        @a leftOp and @a rightOp in @a func.
*
* @code
* leftOp = load ... rightOp.
* @endcode
*
* @param[in] leftOp Left operand of an instruction.
* @param[in] rightOp Right operand of an instruction.
* @param[in] func We try to find from extended right uses in this function.
*
* @return Found instruction, otherwise the null pointer.
*/
Instruction *StoreLoadAnalysis::getInstFromExtRUses(Value &leftOp,
		Value &rightOp, Function &func) {
	return getFuncInfoFor(func).getInstFromExtRUses(leftOp, rightOp);
}

/**
* @brief Returns @c true if is some not go through for @a globValue in @a func,
*        otherwise @c false.
*/
bool StoreLoadAnalysis::isInNotGoThrough(Value &globValue, Function &func) {
	return getFuncInfoFor(func).isInNotGoThrough(globValue);
}

/**
* @brief Returns right uses that can be reached from left use @a lUse.
*
* @par Preconditions
*  - @a lUse have to be analyzed..
*/
std::set<llvm::Instruction*> StoreLoadAnalysis::getRUsesForLUse(Instruction &lUse) {
	return getFuncInfoFor(*lUse.getFunction()).getRUsesForLUse(lUse);

}

/**
* @brief Saves all functions that are in @a module.
*/
void StoreLoadAnalysis::setFuncsInModule(Module &module) {
	for (auto &item : module) {
		funcsInModule.push_back(&item);
	}
}

/**
* @brief Creates and map info for all functions.
*/
void StoreLoadAnalysis::createInfoForAllFuncs() {
	for (Function *func : funcsInModule) {
		FuncInfo *funcInfo = new FuncInfo(*func);
		funcInfoMap[func] = funcInfo;

		if (func->isDeclaration()) {
			funcInfo->markAsAnalyzed();
		}
	}
}

/**
* @brief Runs analysis.
*/
void StoreLoadAnalysis::runAnalysis() {
	while (funcTraversalAnalysis.hasSomethingToReturn()) {
		if (funcTraversalAnalysis.isNextInSCC()) {
			analyzeFuncsInSCC();
		} else {
			analyzeFuncNotInSCC();
		}
	}
}

/**
* @brief Analyzes functions that are in SCC.
*/
void StoreLoadAnalysis::analyzeFuncsInSCC() {
	while (goThroughFuncsInSCCAndReturnIfChanged()) {
		// Do nothing, just keep iterating.
	}

	funcTraversalAnalysis.stopIteratingSCC();
}

/**
* @brief Analyzes function that is not in SCC.
*/
void StoreLoadAnalysis::analyzeFuncNotInSCC() {
	processFunc(*funcTraversalAnalysis.getNextFunc());
}

/**
* @brief Goes through functions that are in SCC and analyzes them.
*
* This method visits all function in SCC one time. Than returns if something
* changed.
*
* @return @c true if something changed in one SCC iteration, otherwise @c false.
*/
bool StoreLoadAnalysis::goThroughFuncsInSCCAndReturnIfChanged() {
	bool needNextSCCIter(false);
	// One SCC iteration.
	do {
		Function *func(funcTraversalAnalysis.getNextFuncInSCC());
		initBeforeProcessFuncInSCC(*func);
		processFunc(*func);
		if (!needNextSCCIter) {
			needNextSCCIter = currFuncInfo->isDiffFuncInfoFromLastVisit();
		}
	} while (!funcTraversalAnalysis.causeNextNewSCCIteration());

	return needNextSCCIter;
}

/**
* @brief Initiate to start state the functions info for @a func.
*
* This method is need to call before process function more than once.
*/
void StoreLoadAnalysis::initBeforeProcessFuncInSCC(Function &func) {
	FuncInfo &funcInfo(getFuncInfoFor(func));
	funcInfo.doCopyOfFuncInfoAndCreateNew();
	funcInfo.clearVisitedBBs();
	clearBBInfosIn(funcInfo.getFunc());
}

/**
* @brief Clears in all basic blocks in @a func contained info from analysis.
*
* This is need before new visit of function.
*/
void StoreLoadAnalysis::clearBBInfosIn(Function &func) {
	for (auto &item : func) {
		BBInfo *bbInfo(getBBInfoFor(item));
		if (!bbInfo) {
			continue;
		}
		bbInfo->clearInfo();
	}
}

/**
* @brief Processes function @a func.
*/
void StoreLoadAnalysis::processFunc(Function &func) {
	if (func.isDeclaration()) {
		// Nothing to optimize for function that is defined out of module.
		return;
	}

	setCurrFuncInfo(func);

	goThroughBBsAndAnalyzeThem(func);

	afterAnalysisBBsInFunc();
}

/**
* @brief Goes through basic blocks in @a func and analyzes them.
*/
void StoreLoadAnalysis::goThroughBBsAndAnalyzeThem(Function &func) {
	bbTraversalAnalysis.doBBsAnalysis(func);
	while (bbTraversalAnalysis.hasSomethingToReturn()) {
		if (bbTraversalAnalysis.isNextInSCC()) {
			visitBBsInSCC();
		} else {
			visitBBNotInSCC();
		}
	}
}

/**
* Makes what is need after analysis basic blocks in function.
*/
void StoreLoadAnalysis::afterAnalysisBBsInFunc() {
BBInfo *entryBBInfo(getBBInfoFor(currFuncInfo->getFunc().getEntryBlock()));
	currFuncInfo->setFuncInfo(*entryBBInfo);
	if (currFuncInfo->funcInfo->emptyLastLUses() &&
			!currFuncInfo->funcInfo->emptyNotGoThrough()) {
		// Now we know that we spread not go through because we have some not
		// analyzed function in recursion and this means that doesn't exist some
		// way that is analyzed whole to the end of function.
		currFuncInfo->markAsNotAnalyzed();
	} else {
		currFuncInfo->markAsAnalyzed();
	}
}

/**
* @brief Analyzes basic blocks that are in SCC.
*/
void StoreLoadAnalysis::visitBBsInSCC() {
	spreadNotGoThroughInSCC();
	while (goThroughBBsSCCAndReturnIfChanged()) {
		// Do nothing, just keep iterating.
	}

	bbTraversalAnalysis.stopIteratingSCC();
}

/**
* @brief Adds for all basic blocks in one SCC all global variables to not go
*        through.
*
* This is needed because:
* @code
*   scc1:
*     g = 4
*     br label %scc2
*   scc2:
*     g = 2;
*     br i1 1, label %bb, label %scc1
*   bb:
* @endcode
* In some more complicated situations can be basic block scc1 be returned
* earlier than scc2. If if happens that g = 4 is added to last left uses, but
* this is not good. We ensure with add to not go through that nothing is add
* until we make intersection not go through with basic blocks out of SCC and
* than we can safe add left use to last left uses.
*/
void StoreLoadAnalysis::spreadNotGoThroughInSCC() {
	do {
		BasicBlock *bb(bbTraversalAnalysis.getNextBBInSCC());
		setCurrBBInfo(*bb);
		currBBInfo->addAllGlobsToNotGoThrough(globsToAnalyze);
	} while (!bbTraversalAnalysis.causeNextNewSCCIteration());
}

/**
* @brief Analyzes basic block that is not in SCC.
*/
void StoreLoadAnalysis::visitBBNotInSCC() {
	processBB(*bbTraversalAnalysis.getNextBB());
}

/**
* @brief Goes through basic blocks that are in SCC and analyzes them.
*
* This method visits all basic blocks in SCC one time. Than returns if something
* changed.
*
* @return @c true if something changed in one SCC iteration, otherwise @c false.
*/
bool StoreLoadAnalysis::goThroughBBsSCCAndReturnIfChanged() {
	bool needNextSCCIter(false);
	// One SCC iteration.
	do {
		BasicBlock *bb(bbTraversalAnalysis.getNextBBInSCC());
		processBB(*bb);
		if (currBBInfo->hasChangedInfo()) {
			needNextSCCIter = true;
		}
	} while (!bbTraversalAnalysis.causeNextNewSCCIteration());
	return needNextSCCIter;
}

/**
* @brief Processes one basic block @a bb.
*/
void StoreLoadAnalysis::processBB(BasicBlock &bb) {
	// Init.
	setCurrBBInfo(bb);
	bool isBBVisited(currFuncInfo->isBBVisited(bb));
	currBBInfo->markAsNotChangedInfo();

	if (!isNeedToProcessBB(bb, isBBVisited)) {
		return;
	}

	if (isBBVisited) {
		// Make a snapshot.
		currBBInfo->doCopyOfBBInfoAndCreateNew();
	}

	// Process info from predecessors basic blocks.
	addInfoFromSuccBBsFor(bb, isBBVisited);

	if (currBBInfo->hasAnalyzedOrdsInsts()) {
		// We have saved useful instructions from last visit.
		processInstsInBB();
	} else {
		processInstsInBB(bb.getInstList());
	}

	if (isBBVisited) {
		// If we visit this basic block more than once than is need to compare
		// if something was changed from last visit.
		currBBInfo->diffBBInfoFromLastVisitAndSetIfChanged();
	} else {
		// In first time visit we count that something was changed.
		currBBInfo->markAsChangedInfo();
	}

	currFuncInfo->markBBAsVisited(bb);
}

/**
* @brief Returns @c true if is need to process @a bb, otherwise @c false.
*
* @param[in] bb Basic block that have to be processed.
* @param[in] isBBVisited If this basic block was visited.
*/
bool StoreLoadAnalysis::isNeedToProcessBB(BasicBlock &bb, bool isBBVisited) {
	if (!isBBVisited) {
		// If this basic block hasn't been visited yet than is need to process
		// it.
		return true;
	}

	// Go through all successors and if none of them was changed than this
	// basic block will not change.
	for (auto i = succ_begin(&bb), e = succ_end(&bb); i != e; ++i) {
		BBInfo *succBBInfo(getBBInfoFor(**i));
		if (succBBInfo->hasChangedInfo()) {
			return true;
		}
	}

	return false;
}

/**
* @brief Processes basic block info from all successors basic blocks for
*        basic block @a bb.
*/
void StoreLoadAnalysis::addInfoFromSuccBBsFor(BasicBlock &bb,
		bool isVisitedBB) {
	std::set<llvm::BasicBlock*> visitedSuccs;
	bool hasToIntersect(false);
	for (auto i = succ_begin(&bb), e = succ_end(&bb); i != e; ++i) {
		if (hasItem(visitedSuccs, *i)) {
			// We don't want to get info more than once from some predecessor
			// basic block. This is useful because basic block can have one
			// basic block more than once as predecessor.
			continue;
		}

		visitedSuccs.insert(*i);

		BBInfo *bbInfo(getBBInfoFor(**i));
		if (!bbInfo) {
			// Predecessors have not been processed yet.
			continue;
		}

		AnalysisInfo *bbAnalysisInfo(nullptr);
		if (*i == &bb && isVisitedBB) {
			// When predecessor is same basic block we have saved info in
			// snapshot.
			bbAnalysisInfo = bbInfo->copyBBInfo;
		} else {
			bbAnalysisInfo = bbInfo->bbInfo;
		}

		//// Process Info from predecessors.
		currBBInfo->bbInfo->addExtRUses(*bbAnalysisInfo);
		currBBInfo->bbInfo->addToGlobsForIndirectCalls(*bbAnalysisInfo);
		currBBInfo->bbInfo->addGlobsForCallsForFuncsOutOfModule(*bbAnalysisInfo);
		// We make a intersect but first time is need to add first info because
		// if not, we do intersect with empty set which is empty set and this
		// is not what we want.
		if (!hasToIntersect) {
			currBBInfo->bbInfo->addNotGoThrough(*bbAnalysisInfo);
			hasToIntersect = true;
		} else {
			currBBInfo->bbInfo->intersectNotGoThrough(*bbAnalysisInfo);
		}
		////
	}
}

/**
* @brief Processes instructions in @a instList.
*
* @param[in] instList List of instructions to process.
*
* This is used when we visit basic block first time and we don't have saved
* useful instructions.
*/
void StoreLoadAnalysis::processInstsInBB(
		llvm::BasicBlock::InstListType &instList) {
	// We are doing traversal from bottom to up so we need visit instructions
	// from bottom to top.
	for (BasicBlock::reverse_iterator ri = instList.rbegin(),
			re = instList.rend(); ri != re; ++ri) {
		tryToProcessInst(*ri);
	}

	// We process this basic block so we have ordered useful instructions.
	currBBInfo->markAsAnalyzedOrdInsts();
}

/**
* @brief Processes saved useful instructions for current basic block.
*
* This is used when we visit basic block more than once and we have saved
* useful instructions.
*/
void StoreLoadAnalysis::processInstsInBB() {
	// In this place we have ordered instruction in order that we need.
	// If in last visit we have Inst1, Inst2, now we have in this vector saved
	// instructions in order Inst2, Inst1.
	for (auto i = currBBInfo->ordInsts_begin(), e = currBBInfo->ordInsts_end();
			i != e; ++i) {
		tryToProcessInst(**i);
	}
}

/**
* @brief Tries to process @a inst.
*/
void StoreLoadAnalysis::tryToProcessInst(Instruction &inst) {
	if (CallInst *callInst = dyn_cast<CallInst>(&inst)) {
		processFuncCall(*callInst);
		return;
	}

	const UsesAnalysis::UseInfo *useInfo(usesAnalysis.getUseInfo(
		currBBInfo->getBB(), inst));
	if (!useInfo) {
		// If instruction is not useful.
		return;
	}

	// Save useful instruction.
	currBBInfo->tryToAddInstToOrderedList(inst);

	if (useInfo->isLUse) {
		processLUse(*useInfo->value, inst);
	} else {
		// We have right use so save it.
		currBBInfo->bbInfo->addExtRUse(*useInfo->value, inst);
	}
}

/**
* @brief Process called function and info from this function.
*
* @param[in] callInst Instruction that contains called function.
*/
void StoreLoadAnalysis::processFuncCall(CallInst &callInst) {
	currBBInfo->tryToAddInstToOrderedList(callInst);

	Function *func(callInst.getCalledFunction());
	if (!func) {
		solveIndirectCall(callInst);
		return;
	}

	if (func->isDeclaration() && countWithFuncsOutOfModule) {
		solveCallForFuncsOutOfModule();
		return;
	}

	FuncInfo &calledFuncInfo(getFuncInfoFor(*func));
	if (!calledFuncInfo.isAnalyzed()) {
		// When we have in recursion don't analyzed called function we don't
		// want to spread extended right uses because they can be not correct
		// connect with left uses.
		// processedFunc() <- LastLeftUses = {g = 2}
		// notProcessed() <- not analyzed. We don't know if is it here last left
		//                   use for global variable g.
		// x = g;
		//
		// For same reason we don't want to spread indirect calls and calls
		// for functions defined out of module.
		currBBInfo->clearExtRUses();
		currBBInfo->clearGlobsForIndirectCalls();
		currBBInfo->clearCallsForFuncsOutOfModule();
		currBBInfo->addAllGlobsToNotGoThrough(globsToAnalyze);
		return;

	}
	AnalysisInfo *funcAnalysisInfo(nullptr);
	if (&currFuncInfo->getFunc() == func) {
		// If we have recursion on same function than we have info saved in
		// snapshot.
		funcAnalysisInfo = calledFuncInfo.copyFuncInfo;
	} else {
		funcAnalysisInfo = calledFuncInfo.funcInfo;
	}

	processCalledFuncInfo(*funcAnalysisInfo);
}

/**
* @brief Processes @a calledFuncInfo.
*
* Process means that we update info for current basic block with info from
* called function.
*/
void StoreLoadAnalysis::processCalledFuncInfo(
		const AnalysisInfo &calledFuncInfo) {
	processExtRUsesAfterFuncCall(calledFuncInfo);
	addToLastLUsesWithCheck(calledFuncInfo);
	currBBInfo->bbInfo->addNotGoThrough(calledFuncInfo);
	processGlobsForIndirectCallAfterFuncCall(calledFuncInfo);
	processCallsForFuncOutOfModuleAfterFuncCall(calledFuncInfo);
}

/**
* @brief Solves indirect call for @a callInst.
*/
void StoreLoadAnalysis::solveIndirectCall(CallInst &callInst) {
	std::set<llvm::Function*> funcs(IndirectlyCalledFuncsAnalysis::getFuncsForIndirectCall(
		callInst, funcsInModule));
	AnalysisInfo::ValInstSetMap extRUses;
	currBBInfo->bbInfo->copyExtRUses(extRUses);
	for (Function *func : funcs) {
		// We save all extended right uses from this basic block to functions
		// that can be called and after that we connect it with last left uses.
		addToExtRUsesForIndirectCall(extRUses, *func);
	}

	// Need to add all global variables that are not connected with some last
	// left use for this indirect call.
	currBBInfo->addAllGlobsToGlobsForIndirectCall(globsToAnalyze);
}

/**
* @brief Solves call of functions that is defined out of module.
*/
void StoreLoadAnalysis::solveCallForFuncsOutOfModule() {
	// Need to add all global variables that are not connected with some last
	// left use for call of function defined out of module.
	currBBInfo->addAllGlobsToGlobsForCallsForFuncsOutOfModule(
		globsToAnalyze);
}

/**
* @brief Adds extended right uses to mapping extended right uses to function
*        after indirect call.
*
* @param[in] extRUses Extended right uses to add.
* @param[in] func We add for this function.
*/
void StoreLoadAnalysis::addToExtRUsesForIndirectCall(
		const AnalysisInfo::ValInstSetMap &extRUses, Function &func) {
	auto it(extRUsesForIndirectCall.find(&func));
	if (it == extRUsesForIndirectCall.end()) {
		extRUsesForIndirectCall[&func] = extRUses;
	} else {
		it->second.addFrom(extRUses);
	}
}

/**
* @brief Processes extended right uses after function call.
*
* @param[in] calledFuncInfo Function info of called function.
*/
void StoreLoadAnalysis::processExtRUsesAfterFuncCall(
		const AnalysisInfo &calledFuncInfo) {
	for (auto i = calledFuncInfo.lastLUses_begin(),
			e = calledFuncInfo.lastLUses_end(); i != e; ++i) {
		if (currBBInfo->bbInfo->isInExtRUses(*i->first)) {
			// Example:
			// func() (lastLUse = g = 2, notGoThrough = empty/g)
			// x = g
			// In this situation is need to add extended right use for store
			// g = 2.
			std::set<llvm::Instruction*> rUses;
			currBBInfo->bbInfo->appendFromExtRUses(*i->first, rUses);
			addInRUsesForLUses(i->second, rUses);
		} else {
			// We don't have some right use for this global variable so go to
			// next global variable with last left uses.
			continue;
		}

		// We can have two situations:
		// 1. func() (lastLUse = g, notGoThrough = empty)
		//    x = g
		// 2. func() (lastLUse = g, notGoThrough = g)
		//    x = g
		//
		// In first situation is possible that right use can go through the
		// function without connection to some assign for this right use.
		//
		// In second situation we need to not to propagate extended right use
		// upper because we know that this use can't go through the function
		// without some connection to assign for this use.
		// So the condition below is for second situation when we need to remove
		// extended right use.
		if (calledFuncInfo.isInNotGoThrough(*i->first)) {
			currBBInfo->bbInfo->removeValFromExtRUses(*i->first);
		}
	}

	// Add extended right uses from called function.
	currBBInfo->bbInfo->addExtRUses(calledFuncInfo);
}

/**
* @brief Processes indirect calls after function call.
*
* @param[in] calledFuncInfo Function info of called function.
*/
void StoreLoadAnalysis::processGlobsForIndirectCallAfterFuncCall(
		const AnalysisInfo &calledFuncInfo) {
	for (auto i = calledFuncInfo.lastLUses_begin(),
			e = calledFuncInfo.lastLUses_end(); i != e; ++i) {
		// Need to check if we can connect some last left uses with some
		// indirect calls.
		solveIndirectCallsForLUses(*i->first, i->second);
	}

	// Add indirect calls from called function.
	currBBInfo->bbInfo->addToGlobsForIndirectCalls(calledFuncInfo);
}

/**
* @brief Processes calls for functions defined out of module.
*
* @param[in] calledFuncInfo Function info of called function.
*/
void StoreLoadAnalysis::processCallsForFuncOutOfModuleAfterFuncCall(
		const AnalysisInfo &calledFuncInfo) {
	for (auto i = calledFuncInfo.lastLUses_begin(),
			e = calledFuncInfo.lastLUses_end(); i != e; ++i) {
		// Need to check if we can connect some last left uses with some
		// calls for functions defined out of module.
		solveCallsForFuncsOutOfModuleForLUses(*i->first, i->second);
	}

	// Add calls for functions defined out of module.
	currBBInfo->bbInfo->addGlobsForCallsForFuncsOutOfModule(calledFuncInfo);
}

/**
* @brief Adds right uses for left uses which has same global variable.
*
* @param[in] lUses Left uses.
* @param[in, out] rUses Right uses to add.
*/
void StoreLoadAnalysis::addInRUsesForLUses(const std::set<llvm::Instruction*> &lUses,
		const std::set<llvm::Instruction*> &rUses) {
	for (Instruction *lUse : lUses) {
		addInRUsesForLUse(*lUse, rUses);
	}
}

/**
* @brief Adds @a lUses that can reach the indirect call.
*/
void StoreLoadAnalysis::addInLUsesForIndirectCalls(const std::set<llvm::Instruction*> &lUses) {
	addToSet(lUses, lUsesForIndirectCall);
}

/**
* @brief Adds @a lUses into left uses that can reach call of functions defined
*        out of module.
*/
void StoreLoadAnalysis::addInLUsesForFuncsOutOfModule(const std::set<llvm::Instruction*> &lUses) {
	addToSet(lUses, lUsesForFuncsOutOfModule);
}

/**
* @brief Adds @a rUses for @a lUse.
*
* Also find for which function add @a lUse with @a rUses. We add @a rUses for
* @a lUse in parent function for this instruction.
*/
void StoreLoadAnalysis::addInRUsesForLUse(Instruction &lUse,
		const std::set<llvm::Instruction*> &rUses) {
	getFuncInfoFor(*lUse.getFunction()).addInRUsesForLUse(lUse, rUses);
}

/**
* @brief Tries to add last left uses from @a toAdd.
*
* Example:
* g = 2;
* g = 5;
* In this case is last left use g = 5.
* This method check and make decision if can add last left use. If in example
* we try to add to last left use g = 2, nothing to be added.
*/
void StoreLoadAnalysis::addToLastLUsesWithCheck(const AnalysisInfo &toAdd) {
	for (auto i = toAdd.lastLUses_begin(), e = toAdd.lastLUses_end(); i != e;
			++i) {
		if (currBBInfo->hasLastLUse(*i->first)) {
			// Some last left use for this global variable exists.
			continue;
		}

		currFuncInfo->funcInfo->addLastLUses(*i->first, i->second);
	}
}

/**
* @brief Processes left use.
*
* @param[in] globValue Value of global variable in left uses.
* @param[in] lUse Left uses.
*/
void StoreLoadAnalysis::processLUse(Value &globValue, Instruction &lUse) {
	// Connect right uses with left use.
	std::set<llvm::Instruction*> rUses;
	currBBInfo->bbInfo->appendFromExtRUses(globValue, rUses);
	addInRUsesForLUses(std::set<llvm::Instruction*>{&lUse}, rUses);

	solveIndirectCallsForLUses(globValue, std::set<llvm::Instruction*>{&lUse});
	solveCallsForFuncsOutOfModuleForLUses(globValue, std::set<llvm::Instruction*>{&lUse});

	// We found store for saved extended right uses. Now we don't want to
	// propagate these extended right uses.
	currBBInfo->bbInfo->removeValFromExtRUses(globValue);

	// Need to add last left use before adding not go through because last use
	// depends on not go through.
	tryToAddLastLUse(globValue, lUse);

	// After this store instruction is need to propagate not go through for
	// a global variable that is used in this store instruction.
	currBBInfo->bbInfo->addNotGoThrough(globValue);
}

/**
* @brief Solves indirect calls in processing left uses.
*
* @param[in] globValue Value of global variable in left uses.
* @param[in] lUses Left uses
*/
void StoreLoadAnalysis::solveIndirectCallsForLUses(Value &globValue,
		const std::set<llvm::Instruction*> &lUses) {
	if (currBBInfo->bbInfo->isInGlobsForIndirectCalls(globValue)) {
		// We connect this global variable with left use. We don't want to
		// spread it to next basic blocks.
		currBBInfo->bbInfo->removeGlobFromGlobsForIndirectCalls(globValue);

		// Need to mark this left uses because they can reach indirect call.
		addInLUsesForIndirectCalls(lUses);
	}
}

/**
* @brief Solves calls for functions defined out of module in processing left uses.
*
* @param[in] globValue Value of global variable in left uses.
* @param[in] lUses Left uses
*/
void StoreLoadAnalysis::solveCallsForFuncsOutOfModuleForLUses(Value &globValue,
		const std::set<llvm::Instruction*> &lUses) {
	if (currBBInfo->bbInfo->isInGlobsForCallsForFuncsOutOfModule(globValue)) {
		// We connect this global variable with left use. We don't want to
		// spread it to next basic blocks.
		currBBInfo->bbInfo->removeGlobFromGlobsForCallForFuncsOutOfModule(
			globValue);

		// Need to mark this left uses because they can reach indirect call.
		addInLUsesForFuncsOutOfModule(lUses);
	}
}

/**
* @brief Tries to add @a lUse to last left uses. We add this left use only if it
*        is last left use.
*
* @param[in] globValue Value of global variable that is in @a lUse.
* @param[in] lUse Left use to add.
*/
void StoreLoadAnalysis::tryToAddLastLUse(Value &globValue, Instruction &lUse) {
	if (!currBBInfo->hasLastLUse(globValue)) {
		currFuncInfo->funcInfo->addLastLUse(globValue, lUse);
	}
}

/**
* @brief Sets to the current function info a function info for @a func.
*
* If not exists than is created new one.
*/
void StoreLoadAnalysis::setCurrFuncInfo(Function &func) {
	auto it(funcInfoMap.find(&func));
	if (it != funcInfoMap.end()) {
		currFuncInfo = it->second;
	} else {
		currFuncInfo = new FuncInfo(func);
		funcInfoMap[&func] = currFuncInfo;
	}
}

/**
* @brief Sets to the current basic block info a basic block info for @a bb.
*
* If not exists than is created new one.
*/
void StoreLoadAnalysis::setCurrBBInfo(BasicBlock &bb) {
	auto it(bbInfoMap.find(&bb));
	if (it != bbInfoMap.end()) {
		currBBInfo = it->second;
	} else {
		currBBInfo = new BBInfo(bb);
		bbInfoMap[&bb] = currBBInfo;
	}
}

/**
* @brief Returns function info for @a func.
*
* @par Preconditions
*  - Function info have to exist for @a func.
*/
StoreLoadAnalysis::FuncInfo &StoreLoadAnalysis::getFuncInfoFor(
		Function &func) const {
	auto it(funcInfoMap.find(&func));
	assert(it != funcInfoMap.end() && "Search function have to exist in"
		" mapping. You don't have analyzed this function.");
	return *it->second;
}

/**
* @brief Tries to find basic block info for @a bb.
*
* @return Found basic block info, otherwise the null pointer.
*/
StoreLoadAnalysis::BBInfo *StoreLoadAnalysis::getBBInfoFor(BasicBlock &bb) {
	auto it(bbInfoMap.find(&bb));
	return it != bbInfoMap.end()? it->second : nullptr;
}

/**
* @brief Returns a constant begin iterator for right uses for left use in
*        @a func.
*
* @par Preconditions
*  - Function @a func have to be analyzed.
*/
StoreLoadAnalysis::rUsesForLUse_iterator StoreLoadAnalysis::rUsesForLUse_begin(
		Function &func) const {
	return getFuncInfoFor(func).rUsesForLUse_begin();
}

/**
* @brief Returns a constant end iterator for right uses for left use in
*        @a func.
*
* @par Preconditions
*  - Function @a func have to be analyzed.
*/
StoreLoadAnalysis::rUsesForLUse_iterator StoreLoadAnalysis::rUsesForLUse_end(
		Function &func) const {
	return getFuncInfoFor(func).rUsesForLUse_end();
}

/**
* @brief Returns a constant begin iterator for extended right uses for @a func.
*
* @par Preconditions
*  - Function @a func have to be analyzed.
*/
StoreLoadAnalysis::extRUses_iterator StoreLoadAnalysis::extRUses_begin(
		Function &func) const {
	return getFuncInfoFor(func).extRUses_begin();
}

/**
* @brief Returns a constant end iterator for extended right uses for @a func.
*
* @par Preconditions
*  - Function @a func have to be analyzed.
*/
StoreLoadAnalysis::extRUses_iterator StoreLoadAnalysis::extRUses_end(
		Function &func) const {
	return getFuncInfoFor(func).extRUses_end();
}

/**
* @brief Returns a constant begin iterator for last left uses for @a func.
*
* @par Preconditions
*  - Function @a func have to be analyzed.
*/
StoreLoadAnalysis::lastLUses_iterator StoreLoadAnalysis::lastLUses_begin(
		Function &func) const {
	return getFuncInfoFor(func).lastLUses_begin();
}

/**
* @brief Returns a constant end iterator for last left uses for @a func.
*
* @par Preconditions
*  - Function @a func have to be analyzed.
*/
StoreLoadAnalysis::lastLUses_iterator StoreLoadAnalysis::lastLUses_end(
		Function &func) const {
	return getFuncInfoFor(func).lastLUses_end();
}

/**
* @brief Returns a constant begin iterator for left uses that can reach call of
*        functions defined out of module.
*/
StoreLoadAnalysis::lUsesOutFunc_iterator StoreLoadAnalysis::
		lUsesOutFunc_begin() const {
	return lUsesForFuncsOutOfModule.begin();
}

/**
* @brief Returns a constant end iterator for left uses that can reach call of
*        functions defined out of module.
*/
StoreLoadAnalysis::lUsesOutFunc_iterator StoreLoadAnalysis::
		lUsesOutFunc_end() const {
	return lUsesForFuncsOutOfModule.end();
}

/**
* @brief Returns a constant begin iterator for left uses that can reach indirect
*        call.
*/
StoreLoadAnalysis::lUsesIndir_iterator StoreLoadAnalysis::
		lUsesIndir_begin() const {
	return lUsesForIndirectCall.begin();
}

/**
* @brief Returns a constant end iterator for left uses that can reach indirect
*        call.
*/
StoreLoadAnalysis::lUsesIndir_iterator StoreLoadAnalysis::
		lUsesIndir_end() const {
	return lUsesForIndirectCall.end();
}

/**
* @brief Returns a constant begin iterator for extended right uses that can
*        reach indirect call.
*/
StoreLoadAnalysis::extRUsesIndir_iterator StoreLoadAnalysis::
		extRUsesIndir_begin() const {
	return extRUsesForIndirectCall.begin();
}

/**
* @brief Returns a constant end iterator for extended right uses that can reach
*        indirect call.
*/
StoreLoadAnalysis::extRUsesIndir_iterator StoreLoadAnalysis::
		extRUsesIndir_end() const {
	return extRUsesForIndirectCall.end();
}

/**
* @brief Creates new function info for @a func.
*/
StoreLoadAnalysis::FuncInfo::FuncInfo(Function &func):
	funcInfo(new AnalysisInfo()), copyFuncInfo(new AnalysisInfo()),
	func(func), isAnalyzedFunc(false) {}

/**
* @brief Destructs a function info;
*/
StoreLoadAnalysis::FuncInfo::~FuncInfo() {
	delete funcInfo;
	delete copyFuncInfo;
}

/**
* @brief Returns a function for which is this function info created.
*/
Function &StoreLoadAnalysis::FuncInfo::getFunc() {
	return func;
}

/**
* Appends @a rUses for @a lUse that can be reached from this @a lUse.
*/
void StoreLoadAnalysis::FuncInfo::addInRUsesForLUse(llvm::Instruction &lUse,
		const std::set<llvm::Instruction*> &rUses) {
	auto it(rUsesForLUse.find(&lUse));
	if (it == rUsesForLUse.end()) {
		rUsesForLUse[&lUse] = rUses;
	} else {
		addToSet(rUses, it->second);
	}
}

/**
* @brief Returns right uses that can be reached from left use @a lUse.
*
* @par Preconditions
*  - @a lUse have to be analyzed..
*/
std::set<llvm::Instruction*> StoreLoadAnalysis::FuncInfo::getRUsesForLUse(Instruction &lUse) {
	auto it(rUsesForLUse.find(&lUse));
	assert(it != rUsesForLUse.end() && "This left use was not analyzed.");
	return it->second;
}

/**
* @brief Returns @c true if @a bb was visited, otherwise @c false.
*/
bool StoreLoadAnalysis::FuncInfo::isBBVisited(llvm::BasicBlock &bb) {
	return hasItem(visitedBBs, &bb);
}

/**
* @brief Tries to get instruction for extended right uses specified by
*        @a leftOp and @a rightOp.
*/
Instruction *StoreLoadAnalysis::FuncInfo::getInstFromExtRUses(Value &leftOp,
		Value &rightOp) {
	return funcInfo->getInstFromExtRUses(leftOp, rightOp);
}

/**
* @brief Marks that basic block @a bb was visited.
*/
void StoreLoadAnalysis::FuncInfo::markBBAsVisited(llvm::BasicBlock &bb) {
	visitedBBs.insert(&bb);
}

/**
* @brief Marks that function was analyzed.
*/
void StoreLoadAnalysis::FuncInfo::markAsAnalyzed() {
	isAnalyzedFunc = true;
}

/**
* @brief Marks that function was not analyzed.
*/
void StoreLoadAnalysis::FuncInfo::markAsNotAnalyzed() {
	isAnalyzedFunc = false;
}

/**
* @brief Returns @c true if this function was analyzed, otherwise @c false.
*/
bool StoreLoadAnalysis::FuncInfo::isAnalyzed() {
	return isAnalyzedFunc;
}

/**
* @brief Makes a snapshot for function info.
*/
void StoreLoadAnalysis::FuncInfo::doCopyOfFuncInfoAndCreateNew() {
	delete copyFuncInfo;
	copyFuncInfo = funcInfo;
	funcInfo = new AnalysisInfo();
}

/**
* @brief Sets that none basic block was visited.
*/
void StoreLoadAnalysis::FuncInfo::clearVisitedBBs() {
	visitedBBs.clear();
}

/**
* @brief Returns @c true if contained info from analysis is different from last
*        visit, otherwise @c false.
*/
bool StoreLoadAnalysis::FuncInfo::isDiffFuncInfoFromLastVisit() {
	return funcInfo->areNotGoThroughDiff(*copyFuncInfo) ||
		funcInfo->areExtRUsesDiff(*copyFuncInfo) ||
		funcInfo->areLastLUsesDiff(*copyFuncInfo) ||
		funcInfo->areGlobsForIndirectCallsDiff(*copyFuncInfo) ||
		funcInfo->areGlobsForCallsForFuncsOutOfModuleDiff(*copyFuncInfo);
}

/**
* @brief Returns @c true if for @a globValue exists some right uses, otherwise
*        @c false.
*/
bool StoreLoadAnalysis::FuncInfo::isInExtRUses(Value &globValue) {
	return funcInfo->isInExtRUses(globValue);
}

/**
* @brief Returns @c true if for @a globValue exists some not go through,
*        otherwise @c false.
*/
bool StoreLoadAnalysis::FuncInfo::isInNotGoThrough(Value &globValue) {
	return funcInfo->isInNotGoThrough(globValue);
}

/**
* @brief Sets the function info from @a bbInfo.
*/
void StoreLoadAnalysis::FuncInfo::setFuncInfo(BBInfo &bbInfo) {
	funcInfo->replaceExceptLastLUses(*bbInfo.bbInfo);
}

/**
* @brief Removes @a lUse from right uses for left use.
*/
void StoreLoadAnalysis::FuncInfo::removeFromRUsesForLUse(Instruction &lUse) {
	rUsesForLUse.erase(&lUse);
}

/**
* @brief Returns a constant begin iterator for right uses for left use.
*/
StoreLoadAnalysis::rUsesForLUse_iterator StoreLoadAnalysis::FuncInfo::
		rUsesForLUse_begin() const {
	return rUsesForLUse.begin();
}

/**
* @brief Returns a constant end iterator for right uses for left use.
*/
StoreLoadAnalysis::rUsesForLUse_iterator StoreLoadAnalysis::FuncInfo::
		rUsesForLUse_end() const {
	return rUsesForLUse.end();
}

/**
* @brief Returns a constant begin iterator for extended right uses.
*/
StoreLoadAnalysis::extRUses_iterator StoreLoadAnalysis::FuncInfo::
		extRUses_begin() const {
	return funcInfo->extRUses_begin();
}

/**
* @brief Returns a constant end iterator for extended right uses.
*/
StoreLoadAnalysis::extRUses_iterator StoreLoadAnalysis::FuncInfo::
		extRUses_end() const {
	return funcInfo->extRUses_end();
}

/**
* @brief Returns a constant begin iterator for last left uses.
*/
StoreLoadAnalysis::lastLUses_iterator StoreLoadAnalysis::FuncInfo::
		lastLUses_begin() const {
	return funcInfo->lastLUses_begin();
}

/**
* @brief Returns a constant end iterator for last left uses.
*/
StoreLoadAnalysis::lastLUses_iterator StoreLoadAnalysis::FuncInfo::
		lastLUses_end() const {
	return funcInfo->lastLUses_end();
}

/**
* @brief Creates a new basic block info for @a bb.
*/
StoreLoadAnalysis::BBInfo::BBInfo(BasicBlock &bb): bbInfo(new AnalysisInfo()),
	copyBBInfo(new AnalysisInfo), bb(bb), hasAnalyzedOrdInsts(false),
	changedInfo(false) {}

/**
* @brief Destroys basic block info.
*/
StoreLoadAnalysis::BBInfo::~BBInfo() {
	delete bbInfo;
	delete copyBBInfo;
}

/**
* @brief Returns a constant begin iterator for ordered instructions.
*/
StoreLoadAnalysis::BBInfo::ordInsts_iterator StoreLoadAnalysis::BBInfo::
		ordInsts_begin() {
	return orderedInstVec.begin();
}

/**
* @brief Returns a constant end iterator for ordered instructions.
*/
StoreLoadAnalysis::BBInfo::ordInsts_iterator StoreLoadAnalysis::BBInfo::
		ordInsts_end() {
	return orderedInstVec.end();
}

/**
* @brief Returns basic block for which is this basic block info.
*/
BasicBlock &StoreLoadAnalysis::BBInfo::getBB() {
	return bb;
}

/**
* @brief Returns if for @a globValue we have last left use.
*
* Last left use is only if we don't have store before this store for the
* same global variable. We can check this thanks to not go through.
*/
bool StoreLoadAnalysis::BBInfo::hasLastLUse(Value &globValue) {
	return bbInfo->isInNotGoThrough(globValue);
}

/**
* @brief Adds @a callInst to indirect calls.
*/
void StoreLoadAnalysis::BBInfo::addIndirectCall(CallInst &callInst) {
	bbInfo->addGlobForIndirectCalls(callInst);
}

/**
* @brief Adds @a callInst to calls for functions defined out of module.
*/
void StoreLoadAnalysis::BBInfo::addCallForFuncOutOfModule(CallInst &callInst) {
	bbInfo->addToGlobsForCallsForFuncsOutOfModule(callInst);
}

/**
* @brief Adds @a globs to not go through.
*/
void StoreLoadAnalysis::BBInfo::addAllGlobsToNotGoThrough(
		const std::set<llvm::GlobalVariable*> &globs) {
	for (GlobalVariable *glob : globs) {
		bbInfo->addNotGoThrough(*glob);
	}
}

/**
* @brief Adds @a globs to global variables for indirect call.
*/
void StoreLoadAnalysis::BBInfo::addAllGlobsToGlobsForIndirectCall(
		const std::set<llvm::GlobalVariable*> &globs) {
	for (GlobalVariable *glob : globs) {
		bbInfo->addGlobForIndirectCalls(*glob);
	}
}

/**
* @brief Adds @a globs to global variables for calls of functions defined out of
*        module.
*/
void StoreLoadAnalysis::BBInfo::addAllGlobsToGlobsForCallsForFuncsOutOfModule(
		const std::set<llvm::GlobalVariable*> &globs) {
	for (GlobalVariable *glob : globs) {
		bbInfo->addToGlobsForCallsForFuncsOutOfModule(*glob);
	}
}

/**
* @brief Clears extended right uses for basic block.
*/
void StoreLoadAnalysis::BBInfo::clearExtRUses() {
	bbInfo->clearExtRUses();
}

/**
* @brief Clears global variables for indirect calls for basic block.
*/
void StoreLoadAnalysis::BBInfo::clearGlobsForIndirectCalls() {
	bbInfo->clearGlobsForIndirectCalls();
}

/**
* @brief Clears calls for functions defined out of module.
*/
void StoreLoadAnalysis::BBInfo::clearCallsForFuncsOutOfModule() {
	bbInfo->clearGlobsForCallsForFuncsOutOfModule();
}

/**
* @brief Clears info contained thorough analysis for basic block.
*/
void StoreLoadAnalysis::BBInfo::clearInfo() {
	delete bbInfo;
	bbInfo = new AnalysisInfo();
}

/**
* @brief Marks that we have analyzed and ordered useful instructions.
*/
void StoreLoadAnalysis::BBInfo::markAsAnalyzedOrdInsts() {
	hasAnalyzedOrdInsts = true;
}

/**
* @brief Returns @c true if basic block info was changed, otherwise @c false.
*/
bool StoreLoadAnalysis::BBInfo::hasChangedInfo() {
	return changedInfo;
}

/**
* @brief Marks that info was changed.
*/
void StoreLoadAnalysis::BBInfo::markAsChangedInfo() {
	changedInfo = true;
}

/**
* @brief Marks that info was not changed.
*/
void StoreLoadAnalysis::BBInfo::markAsNotChangedInfo() {
	changedInfo = false;
}

/**
* @brief Returns @c true if we analyzed useful ordered instructions, otherwise
*        @c false.
*/
bool StoreLoadAnalysis::BBInfo::hasAnalyzedOrdsInsts() {
	return hasAnalyzedOrdInsts;
}

/**
* @brief Creates a snapshot for basic block info.
*/
void StoreLoadAnalysis::BBInfo::doCopyOfBBInfoAndCreateNew() {
	delete copyBBInfo;
	copyBBInfo = bbInfo;
	bbInfo = new AnalysisInfo();
}

/**
* @brief Returns @c true if basic block info was changed from last visit,
*        otherwise @c false.
*/
void StoreLoadAnalysis::BBInfo::diffBBInfoFromLastVisitAndSetIfChanged() {
	changedInfo = bbInfo->areNotGoThroughDiff(*copyBBInfo) ||
		bbInfo->areExtRUsesDiff(*copyBBInfo) ||
		bbInfo->areGlobsForIndirectCallsDiff(*copyBBInfo) ||
		bbInfo->areGlobsForCallsForFuncsOutOfModuleDiff(*copyBBInfo);
}

/**
* @brief Tries to add @a inst to ordered list of instructions for current
*        processed basic block.
*/
void StoreLoadAnalysis::BBInfo::tryToAddInstToOrderedList(Instruction &inst) {
	if (hasAnalyzedOrdInsts) {
		// We have saved ordered instructions for the current basic block.
		return;
	}

	orderedInstVec.push_back(&inst);
}

/**
* @brief Emits the extended right uses.
*
* Only for debugging purposes.
*/
void AnalysisInfo::printExtRUses() {
	errs() << "Extended right uses:\n";
	extRUses.print();
}

/**
* @brief Emits the not go through variables.
*
* Only for debugging purposes.
*/
void AnalysisInfo::printNotGoThrough() {
	errs() << "Not go through global variables:\n";
	for (Value *value : notGoThrough) {
		errs() << "     Not go through: '" << value->getName() << "'\n";
	}
}

/**
* @brief Emits the last left uses.
*
* Only for debugging purposes.
*/
void AnalysisInfo::printLastLUses() {
	errs() << "Last left uses:\n";
	lastLUses.print();
}

/**
* @brief Emits the global variables for indirect calls.
*
* Only for debugging purposes.
*/
void AnalysisInfo::printGlobsForIndirectCalls() {
	errs() << "Global variables for indirect calls:\n";
	for (Value *value : globsForIndirectCalls) {
		errs() << "     Global variable: '" << value->getName() << "'\n";
	}
}

/**
* @brief Emits the global variables for calls for functions defined out of
*        module.
*
* Only for debugging purposes.
*/
void AnalysisInfo::printGlobsForCallsForFuncsOutOfModule() {
	errs() << "Global variables for calls for functions defined out of module:\n";
	for (Value *value : globsForCallsForFuncsOutOfModule) {
		errs() << "     Global variable: '" << value->getName() << "'\n";
	}
}

/**
* @brief Emits the map.
*
* Only for debugging purposes.
*/
void AnalysisInfo::ValInstSetMap::print() {
	for (auto &item : storage) {
		errs() << "     Value: '" << item.first->getName() << "'\n";
		for (Instruction *inst : item.second) {
			if (!inst) {
				errs() << "          Instruction: '" << "nullptr" << "'\n";
			} else {
				errs() << "          Instruction: '" << *inst << "'\n";
			}
		}
	}
}

/**
* @brief Constructs a new analysis info.
*/
AnalysisInfo::AnalysisInfo() {}

/**
* @brief Destructs an analysis info.
*/
AnalysisInfo::~AnalysisInfo() {}

/**
* @brief Adds @a inst for @a value to extended right uses.
*/
void AnalysisInfo::addExtRUse(Value &value, Instruction &inst) {
	extRUses.addInst(value, inst);
}

/**
* @brief Adds @a toAdd to extended right uses.
*/
void AnalysisInfo::addExtRUses(const AnalysisInfo &toAdd) {
	extRUses.addFrom(toAdd.extRUses);
}

/**
* @brief Return @c true if @a value is in extended right uses, otherwise
*        @c false.
*/
bool AnalysisInfo::isInExtRUses(Value &value) {
	return extRUses.isValIn(value);
}

/**
* @brief Tries to get instruction for extended right uses specified by
*        @a leftOp and @a rightOp.
*
* @code
* leftOp = load ... rightOp.
* @endcode
*
* @param[in] leftOp Left operand of an instruction.
* @param[in] rightOp Right operand of an instruction.
*
* @return Found instruction, otherwise the null pointer.
*/
Instruction *AnalysisInfo::getInstFromExtRUses(Value &leftOp, Value &rightOp) {
	return extRUses.getInstFor(leftOp, rightOp);
}

/**
* @brief Appends to @a std::set<llvm::Instruction*> from extended right uses. What is appended is
*        specified by @a value.
*
* @param[in, out] value What is appended is specified by this value.
* @param[in] instSet To this set is appended instructions.
*/
void AnalysisInfo::appendFromExtRUses(Value &value, std::set<llvm::Instruction*> &instSet) {
	extRUses.appendInstsFor(value, instSet);
}

/**
* @brief Compare if extended right uses are different with @a toDiff.
*
* @return @c true if are different, otherwise @c false.
*/
bool AnalysisInfo::areExtRUsesDiff(const AnalysisInfo &toDiff) {
	return extRUses.isDifferentFrom(toDiff.extRUses);
}

/**
* @brief Copies extended right uses to @a toCopy.
*/
void AnalysisInfo::copyExtRUses(ValInstSetMap &toCopy) {
	toCopy = extRUses;
}

/**
* @brief Tries to remove @a value from extended right uses.
*/
void AnalysisInfo::removeValFromExtRUses(Value &value) {
	extRUses.tryToRemoveValue(value);
}

/**
* @brief Clears extended right uses.
*/
void AnalysisInfo::clearExtRUses() {
	extRUses.clear();
}

/**
* @brief Clears global variables for indirect calls.
*/
void AnalysisInfo::clearGlobsForIndirectCalls() {
	globsForIndirectCalls.clear();
}

/**
* @brief Clears global variables for calls for function defines out of module.
*/
void AnalysisInfo::clearGlobsForCallsForFuncsOutOfModule() {
	globsForCallsForFuncsOutOfModule.clear();
}

/**
* @brief Adds @a value to not go through variables.
*/
void AnalysisInfo::addNotGoThrough(llvm::Value &value) {
	notGoThrough.insert(&value);
}

/**
* @brief Adds from @a toAdd to not go through variables.
*/
void AnalysisInfo::addNotGoThrough(const AnalysisInfo &toAdd) {
	addToSet(toAdd.notGoThrough, notGoThrough);
}

/**
* @brief Returns @c true if @a value is in not go through global variables,
*        otherwise @c false.
*/
bool AnalysisInfo::isInNotGoThrough(Value &value) const {
	return hasItem(notGoThrough, &value);
}

/**
* @brief Intersects not go through global variables with not go through global
*        variables in @a toIntersect.
*/
void AnalysisInfo::intersectNotGoThrough(const AnalysisInfo &toIntersect) {
	auto it(notGoThrough.begin());
	auto itE(notGoThrough.end());
	while (it != itE) {
		if (!hasItem(toIntersect.notGoThrough, *it)) {
			notGoThrough.erase(it++);
		} else {
			++it;
		}
	}
}

/**
* @brief Compare if not go through variables are different with @a toDiff.
*
* @return @c true if are different, otherwise @c false.
*/
bool AnalysisInfo::areNotGoThroughDiff(const AnalysisInfo &toDiff) {
	return notGoThrough != toDiff.notGoThrough;
}

/**
* @brief Replaces all info except last left uses.
*/
void AnalysisInfo::replaceExceptLastLUses(
		const AnalysisInfo toReplace) {
	extRUses.clear();
	notGoThrough.clear();
	globsForIndirectCalls.clear();
	globsForCallsForFuncsOutOfModule.clear();
	addExtRUses(toReplace);
	addNotGoThrough(toReplace);
	addToGlobsForIndirectCalls(toReplace);
	addGlobsForCallsForFuncsOutOfModule(toReplace);
}

/**
* @brief Returns @c true if not go through are empty, otherwise @c false.
*/
bool AnalysisInfo::emptyNotGoThrough() {
	return notGoThrough.empty();
}

/**
* @brief Adds @a inst to last left uses specified by @a value.
*/
void AnalysisInfo::addLastLUse(Value &value, Instruction &inst) {
	lastLUses.addInst(value, inst);
}

/**
* @brief Adds from @a instSet to last left uses specified by @a value.
*/
void AnalysisInfo::addLastLUses(Value &value, const std::set<llvm::Instruction*> &instSet) {
	lastLUses.addInsts(value, instSet);
}

/**
* @brief Compare if last left uses are different with @a toDiff.
*
* @return @c true if they are different, otherwise @c false.
*/
bool AnalysisInfo::areLastLUsesDiff(const AnalysisInfo &toDiff) {
	return lastLUses.isDifferentFrom(toDiff.lastLUses);
}

/**
* @brief Returns @c true if last left uses are empty, otherwise @c false.
*/
bool AnalysisInfo::emptyLastLUses() {
	return lastLUses.empty();
}

/**
* @brief Adds @a value to global variables for indirect calls.
*/
void AnalysisInfo::addGlobForIndirectCalls(Value &value) {
	globsForIndirectCalls.insert(&value);
}

/**
* @brief Adds @a toAdd to global variables for indirect calls.
*/
void AnalysisInfo::addToGlobsForIndirectCalls(const AnalysisInfo &toAdd) {
	addToSet(toAdd.globsForIndirectCalls, globsForIndirectCalls);
}

/**
* @brief Returns @c true if @a value is in global variables for indirect calls,
*        otherwise @c false.
*/
bool AnalysisInfo::isInGlobsForIndirectCalls(Value &value) const {
	return hasItem(globsForIndirectCalls, &value);
}

/**
* @brief Returns @c true if @a value is in global variables for calls for
*        functions defined out of module, otherwise @c false.
*/
bool AnalysisInfo::isInGlobsForCallsForFuncsOutOfModule(Value &value) const {
	return hasItem(globsForCallsForFuncsOutOfModule, &value);
}

/**
* @brief Removes @a value from global variables for indirect calls.
*/
void AnalysisInfo::removeGlobFromGlobsForIndirectCalls(Value &value) {
	globsForIndirectCalls.erase(&value);
}

/**
* @brief Adds @a value to global variables for calls for functions defined out
*        of module.
*/
void AnalysisInfo::addToGlobsForCallsForFuncsOutOfModule(Value &value) {
	globsForCallsForFuncsOutOfModule.insert(&value);
}

/**
* @brief Adds @a toAdd to global variables for calls for functions defined out
*        of module.
*/
void AnalysisInfo::addGlobsForCallsForFuncsOutOfModule(
		const AnalysisInfo &toAdd) {
	addToSet(toAdd.globsForCallsForFuncsOutOfModule,
		globsForCallsForFuncsOutOfModule);
}

/**
* @brief Compare if global variables for indirect calls are different with
*        @a toDiff.
*
* @return @c true if are different, otherwise @c false.
*/
bool AnalysisInfo::areGlobsForIndirectCallsDiff(const AnalysisInfo &toDiff) {
	return globsForIndirectCalls != toDiff.globsForIndirectCalls;
}

/**
* @brief Compare if global variables for calls for functions defined out of
*        module with @a toDiff.
*
* @return @c true if are different, otherwise @c false.
*/
bool AnalysisInfo::areGlobsForCallsForFuncsOutOfModuleDiff(
		const AnalysisInfo &toDiff) {
	return globsForCallsForFuncsOutOfModule !=
		toDiff.globsForCallsForFuncsOutOfModule;
}

/**
* @brief Removes @a value from global variables for calls for functions defined
*        out of module.
*/
void AnalysisInfo::removeGlobFromGlobsForCallForFuncsOutOfModule(Value &value) {
	globsForCallsForFuncsOutOfModule.erase(&value);
}

/**
* @brief Returns a constant begin iterator for extended right uses.
*/
AnalysisInfo::extRUses_iterator AnalysisInfo::extRUses_begin() const {
	return extRUses.begin();
}

/**
* @brief Returns a constant end iterator for extended right uses.
*/
AnalysisInfo::extRUses_iterator AnalysisInfo::extRUses_end() const {
	return extRUses.end();
}

/**
* @brief Returns a constant begin iterator for not go through global variables.
*/
AnalysisInfo::notGoThrough_iterator AnalysisInfo::notGoThrough_begin() const {
	return notGoThrough.begin();
}

/**
* @brief Returns a constant end iterator for not go through global variables.
*/
AnalysisInfo::notGoThrough_iterator AnalysisInfo::notGoThrough_end() const {
	return notGoThrough.end();
}

/**
* @brief Returns a constant begin iterator for last left uses.
*/
AnalysisInfo::lastLUses_iterator AnalysisInfo::lastLUses_begin() const {
	return lastLUses.begin();
}

/**
* @brief Returns a constant end iterator for last left uses.
*/
AnalysisInfo::lastLUses_iterator AnalysisInfo::lastLUses_end() const {
	return lastLUses.end();
}

/**
* @brief Constructs a new map where is mapped a value to instruction set.
*/
AnalysisInfo::ValInstSetMap::ValInstSetMap() {}

/**
* @brief Destructs a map where is mapped a value to instruction set.
*/
AnalysisInfo::ValInstSetMap::~ValInstSetMap() {}

/**
* @brief Compares @c this with @a toCompare.
*
* @return @c true if they are different, otherwise @c false.
*/
bool AnalysisInfo::ValInstSetMap::isDifferentFrom(const ValInstSetMap &toDiff) {
	if (storage.size() != toDiff.storage.size()) {
		return true;
	}

	auto itFirst(storage.begin());
	auto itFirstE(storage.end());
	auto itSecond(toDiff.storage.begin());
	while (itFirst != itFirstE) {
		if (itFirst->first != itSecond->first) {
			// Values are different.
			return true;
		}

		if (itFirst->second != itSecond->second) {
			// Instruction sets are different.
			return true;
		}
		// Go to next item.
		++itFirst;
		++itSecond;
	}

	return false;
}

/**
* @brief Returns @c true if @a value is in, otherwise @c false.
*/
bool AnalysisInfo::ValInstSetMap::isValIn(Value &value) {
	return mapHasKey(storage, &value);
}

/**
* @brief Returns @c true if @a inst is in for @a value, otherwise @c false.
*/
bool AnalysisInfo::ValInstSetMap::isIn(Value &value, Instruction &inst) {
	auto it(storage.find(&value));
	if (it == storage.end()) {
		return false;
	}

	return hasItem(it->second, &inst);
}

/**
* @brief Clears all.
*/
void AnalysisInfo::ValInstSetMap::clear() {
	storage.clear();
}

/**
* @brief Returns @c true if contains some instruction that is not in @a except,
*        otherwise @c false.
*
* @param[in] value Value for which we want to find out it.
* @param[in] except Set with instructions to except compare.
*/
bool AnalysisInfo::ValInstSetMap::hasExcept(Value &value,
		const std::set<llvm::Instruction*> &except) {
	auto it(find(value));
	if (it == end()) {
		return false;
	}

	for (Instruction *inst : it->second) {
		if (!hasItem(except, inst)) {
			return true;
		}
	}

	return false;
}

/**
* @brief Removes @a value.
*/
void AnalysisInfo::ValInstSetMap::tryToRemoveValue(Value &value) {
	storage.erase(&value);
}

/**
* @brief Returns @c true if is empty, otherwise @c false.
*/
bool AnalysisInfo::ValInstSetMap::empty() {
	return storage.empty();
}

/**
* @brief Adds @a inst and map it by @a value.
*/
void AnalysisInfo::ValInstSetMap::addInst(Value &value, Instruction &inst) {
	// Do not bother checking whether storage[&value] exists because if not,
	// storage[&value] automatically creates an empty set for us.
	storage[&value].insert(&inst);
}

/**
* @brief Adds instructions from @a std::set<llvm::Instruction*> and map them by @a value.
*/
void AnalysisInfo::ValInstSetMap::addInsts(Value &value,
		const std::set<llvm::Instruction*> &instSet) {
	// Do not bother checking whether storage[&value] exists because if not,
	// storage[&value] automatically creates an empty set for us. This
	// significantly speeds up running time on big files.
	addToSet(instSet, storage[&value]);
}

/**
* @brief Adds new items from @a toAdd.
*/
void AnalysisInfo::ValInstSetMap::addFrom(const ValInstSetMap &toAdd) {
	for (auto &item : toAdd) {
		addInsts(*item.first, item.second);
	}
}

/**
* @brief Finds instructions for @a value and appends its into @a std::set<llvm::Instruction*>.
*
* @param[in] value For this value we find instructions.
* @param[in, out] instSet We append to this set.
*/
void AnalysisInfo::ValInstSetMap::appendInstsFor(Value &value,
		std::set<llvm::Instruction*>& instSet) {
	auto it(storage.find(&value));
	if (it != storage.end()) {
		addToSet(it->second, instSet);
	}
}

/**
* @brief Tries to find @a value.
*
* @return Iterator for searched value.
*/
AnalysisInfo::ValInstSetMap::iterator AnalysisInfo::ValInstSetMap::find (
		Value &value) const {
	return storage.find(&value);
}

/**
* @brief Tries to get instruction specified by @a leftOp and @a rightOp.
*
* @param[in] leftOp Left operand of instruction.
* @param[in] rightOp Right operand of instruction.
*
* @return Found instruction, otherwise the null pointer.
*/
Instruction *AnalysisInfo::ValInstSetMap::getInstFor(Value &leftOp,
		Value &rightOp) {
	auto it(storage.find(&rightOp));
	if (it == storage.end()) {
		return nullptr;
	}

	for (Instruction *inst : it->second) {
		if (&leftOp == inst) {
			return inst;
		}
	}

	return nullptr;
}

/**
* @brief Returns a constant begin iterator.
*/
AnalysisInfo::ValInstSetMap::iterator AnalysisInfo::ValInstSetMap::
		begin() const {
	return storage.begin();
}

/**
* @brief Returns a constant end iterator.
*/
AnalysisInfo::ValInstSetMap::iterator AnalysisInfo::ValInstSetMap::
		end() const {
	return storage.end();
}

} // namespace bin2llvmir
} // namespace retdec

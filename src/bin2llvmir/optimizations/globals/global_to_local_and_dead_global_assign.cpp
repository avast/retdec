/**
* @file src/bin2llvmir/optimizations/globals/global_to_local_and_dead_global_assign.cpp
* @brief Implementation of GlobalToLocalAndDeadGlobalAssign optimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include <llvm/ADT/Statistic.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/CallGraphSCCPass.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/analyses/uses_analysis.h"
#include "retdec/bin2llvmir/optimizations/globals/dead_global_assign.h"
#include "retdec/bin2llvmir/optimizations/globals/global_to_local.h"
#include "retdec/bin2llvmir/optimizations/globals/global_to_local_and_dead_global_assign.h"

#define DEBUG_TYPE "global-to-local-and-dead-global-assign"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/// Suffix of name for new created local variable.
const std::string SUFFIX_OF_LOC = ".global-to-local";

cl::opt<bool> NotAggressive("not-aggressive", cl::desc("Aggressive variant"
	" does not count, that there is some use in functions that are defined"
	" outside the module."));

/**
* @brief Finds out if address of @a glob can be taken.

* We support only two types of assigns which ensures that address is not taken.
* @code
* store ..., i32* @glob - means save ... to global variable @glob.
* load i32, i32* @glob - means load value from global variable @glob.
* @endcode
*
* @return @c true if address can be taken for @a glob, otherwise @c false.
*/
bool canHaveAddressTaken(GlobalVariable &glob) {
	for (auto i = glob.user_begin(), e = glob.user_end(); i != e; ++i) {
		if (isa<LoadInst>(*i)) {
			// With load instruction can't get the address of the global
			// variable.
			continue;
		}

		if (StoreInst *storeInst = dyn_cast<StoreInst>(*i)) {
			// Global variable must be the second operand of store instruction.
			// Than we know that address is not taken and stored in another
			// variable because something is stored to this global variable.
			if (storeInst->getPointerOperand()->getValueName() ==
					glob.getValueName()) {
				continue;
			}
		}

		// Not load or supported store.
		return true;
	}

	// All uses of global variable don't take its address.
	return false;
}

/**
* @brief Returns @c true if @a glob can be optimized, otherwise @c false.
*
* Can't be optimized in these situations:
* 1. Global variable is not single type (array, structure, etc.).
* 2. Global variable is a pointer.
* 3. Address of global variable can be taken.
* 4. Global variable that doesn't have private or internal linkage.
*/
bool globalVarCanBeOptimized(GlobalVariable &glob) {
	// TODO: use only this? localize all registers, do not localize anything
	// else.
	//
	auto* config = ConfigProvider::getConfig(glob.getParent());
	if (config && config->isRegister(&glob)) {
		return true;
	}

	Type *globType(glob.getType()->getElementType());
	if (!globType->isSingleValueType()) {
		// We don't want to optimize aggregate types (array, structure, ..).
		// We want optimize only single value types (int, double, ...).
		return false;
	}

	if (globType->isPointerTy()) {
		// Don't optimize pointers.
		// For example:
		// @v = common global i64* null, align 4
		return false;
	}

	if (!glob.hasInternalLinkage() && !glob.hasPrivateLinkage()) {
		return false;
	}

	if (canHaveAddressTaken(glob)) {
		return false;
	}

	return true;
}

/**
* @brief Goes through the @a globs and returns the global variables that can be
*        optimized.
*
* We can't optimize in these situations:
* @see globVarCanBeOptimized()
*
* @param[in] globs Global variables to check.
*
* @return Global variables that can be optimized.
*/
std::set<llvm::GlobalVariable*> getGlobsToOptimize(Module::GlobalListType &globs) {
	std::set<llvm::GlobalVariable*> globsToOptimize;
	for (GlobalVariable &glob : globs) {
		if (globalVarCanBeOptimized(glob)) {
			globsToOptimize.insert(&glob);
		}
	}

	return globsToOptimize;
}

/**
* @brief Find if all instructions in @a std::set<llvm::Instruction*> have same first operand.
*
* If @a std::set<llvm::Instruction*> is empty than nothing to analyze so return @c false.
*
* @return @c true if all instructions have same first operand, otherwise
*         @c false.
*/
bool hasSameFirstOp(const std::set<llvm::Instruction*> &insnSet) {
	if (insnSet.empty()) {
		return false;
	}

	Value *value((*insnSet.begin())->getOperand(0));
	for (Instruction *inst : insnSet) {
		if (inst->getOperand(0) != value) {
			return false;
		}
	}
	return true;
}
/**
* @brief Returns @c true if all instructions in @a std::set<llvm::Instruction*> are in same function
*        otherwise @c false.
*
* If @a std::set<llvm::Instruction*> is empty than nothing to analyze so return @c false.
*/
bool isInstsInSameFunc(const std::set<llvm::Instruction*> &insnSet) {
	if (insnSet.empty()) {
		return false;
	}

	Function *func((*insnSet.begin())->getFunction());
	for (Instruction *inst : insnSet) {
		if (func != inst->getFunction()) {
			return false;
		}
	}

	return true;
}

/**
* @brief Adds a mapping of @c localVarName to @c globalVarName to the config.
*
* This mapping is needed in the back-end to emit the name of the original
* global variable (= register) from which the local variable comes.
*
* TODO: move to config
*/
void addMappingOfLocalVarToGlobalVarInConfig(Config* config, const llvm::Function* func,
		const std::string &localVarName, const std::string &globalVarName) {
	if (!config) {
		return;
	}
	auto f = config->getConfigFunction(func);
	if (!f) {
		return;
	}

	retdec::config::Object localVar(localVarName, retdec::config::Storage::inRegister(globalVarName));
	f->locals.insert(localVar);
}

} // anonymous namespace

STATISTIC(CreatedLocVars, "Number of created local variables");
STATISTIC(NumDeadGlobalAssign, "Number of removed dead global assigns");
STATISTIC(NumGlobalDeclDeleted, "Number of removed declarations for global "
	"variables");

// It is the address of the variable that matters, not the value, so we can
// initialize the ID to anything.
char GlobalToLocalAndDeadGlobalAssign::ID = 0;

/**
* @brief Emits all functions info to standard error.
*
* Only for debugging purposes.
*/
void GlobalToLocalAndDeadGlobalAssign::printFuncInfos() {
	errs() << "[GlobalToLocalAndDeadGlobalAssign] Debug for functions info.\n";
	errs() << "--------------------------------------------------\n";
	for (auto &item : funcInfoMap) {
		item.second->printFuncInfo();
	}
}

/**
* @brief Emits function info to standard error.
*
* Only for debugging purposes.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::printFuncInfo() {
	errs() << "[GlobalToLocalAndDeadGlobalAssign] Debug info for function: '" <<
		func.getName() << "':\n";
	errs() << "*******************************************\n";
	errs() << "Filtered left uses in function:\n";
	filteredLUses.print();
	errs() << "Filtered right uses in function:\n";
	filteredRUses.print();
	errs() << "Found pattern instructions:\n";
	for (Instruction *inst : patternInsts) {
		errs() << "     Pattern instruction: '" << *inst << "'\n";
	}
	errs() << "Converted global variables to local variables:\n";
	for (auto &item : convertedGlobsToLoc) {
		errs() << "     Global variable :'" << item.first << "' is converted"
			" to local variable :'" << *item.second << "'\n";
	}
	errs() << "*******************************************\n";
}

/**
* @brief Creates a new global to local and dead global assign optimizer.
*/
GlobalToLocalAndDeadGlobalAssign::GlobalToLocalAndDeadGlobalAssign():
	ModulePass(ID), globalToLocal(false), deadGlobalAssign(false) {}

/**
* @brief Destructs a global to local and dead global assign optimizer.
*/
GlobalToLocalAndDeadGlobalAssign::~GlobalToLocalAndDeadGlobalAssign() {
	for (auto &item : funcInfoMap) {
		delete item.second;
	}
}

void GlobalToLocalAndDeadGlobalAssign::getAnalysisUsage(
		AnalysisUsage &au) const {
	au.addRequired<CallGraphWrapperPass>();
}

bool GlobalToLocalAndDeadGlobalAssign::runOnModule(Module &module) {
	// Subclasses should set either globalToLocal or deadGlobalAssign to true,
	// but not both of the same time (both optimizations cannot be run at the
	// same time because the result may be incorrect).
	assert(globalToLocal ^ deadGlobalAssign &&
		"Both -global-to-local and -dead-global-assign cannot run as one optimization.");

	std::set<llvm::GlobalVariable*> globsToOptimize(getGlobsToOptimize(module.getGlobalList()));
	if (globsToOptimize.empty()) {
		// Try to optimize variables without use.
		removeGlobsWithoutUse(module.getGlobalList());
		return false;
	}

	// Initiate store load analysis.
	CallGraph &callGraph(getAnalysis<CallGraphWrapperPass>().getCallGraph());
	storeLoadAnalysis.doAnalysis(module, globsToOptimize, callGraph,
		NotAggressive);

	createInfoForAllFuncs(module);

	solveIndirectCallsAndNotAggressive();

	filterUsesThatCannotBeOptimized();

	doOptimization(module, globsToOptimize);

	return wasSomethingOptimized();
}

/**
* @brief Creates and map info for all functions.
*
* @param[in] module Module with functions for which is created info.
*/
void GlobalToLocalAndDeadGlobalAssign::createInfoForAllFuncs(Module &module) {
	for (auto &item : module) {
		FuncInfo *funcInfo = new FuncInfo(item, storeLoadAnalysis);
		funcInfoMap[&item] = funcInfo;
	}
}

/**
* @brief Solves the indirect calls and left uses when we have not aggressive
*        variant.
*/
void GlobalToLocalAndDeadGlobalAssign::solveIndirectCallsAndNotAggressive() {
	solveNotAggressive();
	solveLUsesForIndirectCalls();
	solveLastLUsesForIndirectCalls();
}

/**
* @brief Solves left uses that can reach call of functions defined out of
*        module.
*
* This left uses are solved only in not aggressive variant.
*/
void GlobalToLocalAndDeadGlobalAssign::solveNotAggressive() {
	if (!NotAggressive) {
		// We have aggressive variant.
		return;
	}

	for (auto i = storeLoadAnalysis.lUsesOutFunc_begin(),
			e = storeLoadAnalysis.lUsesOutFunc_end(); i != e; ++i) {
		// We don't want to optimize store that can reach function defined out
		// of module with his loads.
		addFilteredLUse(**i);
	}
}

/**
* @brief Filters left uses which can be connected with indirectly called
*        functions.
*
* @code
* func() {
*   g = 2 <-- This can't be optimized.
*   indirectCall();
* }
*
* indirectlyCalledFunction() {
*   x = g;
* }
* @endcode
*
* We can do this after analyze all functions.
*/
void GlobalToLocalAndDeadGlobalAssign::solveLUsesForIndirectCalls() {
	for (auto i = storeLoadAnalysis.lUsesIndir_begin(),
			e = storeLoadAnalysis.lUsesIndir_end(); i != e; ++i) {
		// We don't want to optimize store that can reach function defined out
		// of module with his loads.
		addFilteredLUse(**i);
	}
}

/**
* @brief Filters last left uses that can be connected with extended right uses
*        by indirect call.
*
* @code
* func() {
*   indirectCall();
*   x = g;
* }
*
* indirectlyCalledFunction() {
*   g = 2; <-- This can be connected and so not optimized.
* }
* @endcode
*
* We can do this after analyze all functions.
*/
void GlobalToLocalAndDeadGlobalAssign::solveLastLUsesForIndirectCalls() {
	for (auto i = storeLoadAnalysis.extRUsesIndir_begin(),
			e = storeLoadAnalysis.extRUsesIndir_end(); i != e; ++i) {
		goThroughLastLUsesAndSolveIndirectCalls(*i->first, i->second);
	}
}

/**
* @brief Goes through last left uses in @a func and solves indirect calls.
*
* For more details @c see solveLastLUsesForIndirectCalls().
*
* @param[in] extRUses Extended right uses that were saved for @a func.
* @param[in] func Function that can be reached by @a extRUses.
*/
void GlobalToLocalAndDeadGlobalAssign::goThroughLastLUsesAndSolveIndirectCalls(
		Function &func, const AnalysisInfo::ValInstSetMap &extRUses) {
	for (auto i = storeLoadAnalysis.lastLUses_begin(func),
			e = storeLoadAnalysis.lastLUses_end(func); i != e; ++i) {
		auto it(extRUses.find(*i->first));
		if (it == extRUses.end()) {
			// We don't have global variable in right uses for global variable
			// in last left uses.
			continue;
		}

		addFilteredLUses(i->second);

		for (Instruction *rUse : it->second) {
			if (!isa<LoadInst>(*rUse)) {
				// We can have in right uses indirect call. But this nothing
				// means for us, just skip it.
				continue;
			}
			rUsesNotToOptimize.insert(rUse);
		}
	}
}

/**
* @brief Filter in contained info instructions that can't be optimized.
*/
void GlobalToLocalAndDeadGlobalAssign::filterUsesThatCannotBeOptimized() {
	std::set<llvm::Instruction*> lUsesNotToOptimize;
	while (goThroughFuncsInfoFilterAndReturnIfChanged(lUsesNotToOptimize,
			rUsesNotToOptimize)) {
		// Do nothing, just keep iterating.
	}

	/// Need to add filtered left uses.
	addFilteredLUses(lUsesNotToOptimize);

	// Need to add to functions where right uses are situated that these right
	// uses were filtered as not to optimize.
	addFilteredRUses(rUsesNotToOptimize);
}

/**
* @brief Goes through functions info and filter instructions that can't be
*        optimized.
*
* @param[in, out] lUsesNotToOptimize Sets of left uses that can't be optimized.
* @param[in, out] rUsesNotToOptimize Sets of right uses that can't be optimized.
*
* @return @c true if right uses to not optimize was changed from last filter,
*         otherwise @c false.
*/
bool GlobalToLocalAndDeadGlobalAssign::goThroughFuncsInfoFilterAndReturnIfChanged(
		std::set<llvm::Instruction*> &lUsesNotToOptimize, std::set<llvm::Instruction*> &rUsesNotToOptimize) {
	bool changed(false);
	for (auto &item : funcInfoMap) {
		item.second->addExtRUsesToNotToOptimize(rUsesNotToOptimize);
		if (item.second->filterUsesThatCannotBeOptimizedReturnIfChanged(
				lUsesNotToOptimize, rUsesNotToOptimize)) {
			changed = true;
		}
	}

	return changed;
}

/**
* @brief Adds extended right uses to @a notToOptimize.
*
* This is need because all right uses that reach top of function can't be
* optimized.
*
* @param[in, out] notToOptimize We add to this.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::addExtRUsesToNotToOptimize(
		std::set<llvm::Instruction*> &notToOptimize) {
	for (auto i = storeLoadAnalysis.extRUses_begin(func),
			e = storeLoadAnalysis.extRUses_end(func); i != e; ++i) {
		addToSet(i->second, notToOptimize);
	}
}

/**
* @brief Makes an optimization in @a module for global variables
*        in @a globstoOptimize.
*
*/
void GlobalToLocalAndDeadGlobalAssign::doOptimization(Module &module,
		const std::set<llvm::GlobalVariable*> &globsToOptimize) {
	for (auto &item : funcInfoMap) {
		if (globalToLocal) {
			item.second->findPatterns();
			item.second->convertGlobsToLocs(deadGlobalAssign);
		}
	}

	// Here we erase instructions so need to run after previous for loop.
	for (auto &item : funcInfoMap) {
		if (deadGlobalAssign) {
			item.second->removeDeadGlobalAssigns();
		}
		if (globalToLocal) {
			item.second->removePatternInsts();
		}
	}

	if (globalToLocal) {
		convertGlobsToLocUseInOneFunc(globsToOptimize);
	}
	removeGlobsWithoutUse(module.getGlobalList());
}

/**
* @brief Converts global variables in @a globs to local in specific situation
*        which is mentioned below.
*
* @code
* int g = 2;
* func() {
*   x = g;
* }
* @endcode
* In this situation we can convert global variable to local but only if global
* variable @c g is not used in another function. We create new local variable
* for which we assign value 2.
*/
void GlobalToLocalAndDeadGlobalAssign::convertGlobsToLocUseInOneFunc(
		const std::set<llvm::GlobalVariable*> &globs) {
	for (GlobalVariable *glob : globs) {
		if (!UsesAnalysis::hasUsesOnlyInOneFunc(*glob)) {
			continue;
		}

		if (NotAggressive && hasSomeLUseForFuncOutOfModule(*glob)) {
			// Some use for this global variable was checked as no to optimize
			// because can be connected with function defined out of module.
			continue;
		}

		if (UsesAnalysis::hasSomeUseVolatileLoadOrStore(*glob)) {
			// We don't optimize volatile store or load.
			continue;
		}

		// Here we can cast first use to instruction safely because here we know
		// that we have only global variables which can be optimized so all
		// uses are instructions.
		Function *parFunc(cast<Instruction>(
			*glob->user_begin())->getFunction());
		getFuncInfoFor(*parFunc).convertGlobToLocUseInOneFunc(*glob);
	}
}

/**
* @brief Removes global variables that don't have use.
*
* @param[in] globs Global variables that can be deleted if they don't
*            have use.
*/
void GlobalToLocalAndDeadGlobalAssign::removeGlobsWithoutUse(
		Module::GlobalListType &globs) {
	auto it(globs.begin());
	while (it != globs.end()) {
		if (UsesAnalysis::hasNoUse(*it)) {
			++NumGlobalDeclDeleted;
			globs.erase(it++);
		} else {
			++it;
		}
	}
}

/**
* @brief Go through uses for @a glob and finds out if some left use can reach
*        call of function defined out of module.
*
* @return @c true if is some left use can reach it, otherwise @c false.
*/
bool GlobalToLocalAndDeadGlobalAssign::hasSomeLUseForFuncOutOfModule(
		GlobalVariable &glob) {
	for (auto i = glob.user_begin(), e = glob.user_end(); i != e; ++i) {
		if (StoreInst *store = dyn_cast<StoreInst>(*i)) {
			if (storeLoadAnalysis.isInLUsesForFuncOutOfModule(*store)) {
				return true;
			}
		}
	}

	return false;
}

/**
* @brief Adds filtered left use @a lUse.
*/
void GlobalToLocalAndDeadGlobalAssign::addFilteredLUse(Instruction &lUse) {
	getFuncInfoFor(*lUse.getFunction()).addFilteredLUse(lUse);
}

/**
* @brief Adds filtered right use @a rUse.
*/
void GlobalToLocalAndDeadGlobalAssign::addFilteredRUse(Instruction &rUse) {
	getFuncInfoFor(*rUse.getFunction()).addFilteredRUse(rUse);
}

/**
* @brief Adds filtered left uses @a lUses.
*/
void GlobalToLocalAndDeadGlobalAssign::addFilteredLUses(const std::set<llvm::Instruction*> &lUses) {
	for (Instruction *lUse : lUses) {
		addFilteredLUse(*lUse);
	}
}

/**
* @brief Adds filtered right uses @a rUses.
*/
void GlobalToLocalAndDeadGlobalAssign::addFilteredRUses(const std::set<llvm::Instruction*> &rUses) {
	for (Instruction *rUse : rUses) {
		addFilteredRUse(*rUse);
	}
}

/**
* @brief Returns @c true if something was optimized, otherwise @c false.
*/
bool GlobalToLocalAndDeadGlobalAssign::wasSomethingOptimized() {
	return CreatedLocVars > 0 || NumGlobalDeclDeleted > 0 ||
		NumDeadGlobalAssign > 0;
}

/**
* @brief Returns function info for @a func.
*
* @par Preconditions
*  - Function info have to exist for @a func.
*/
GlobalToLocalAndDeadGlobalAssign::FuncInfo &GlobalToLocalAndDeadGlobalAssign::
		getFuncInfoFor(Function &func) {
	auto it(funcInfoMap.find(&func));
	assert(it != funcInfoMap.end() && "Searched function have to exist in"
		" mapping.");
	return *it->second;
}

/**
* @brief Creates new function info for @a func.
*
* @param[in] func For this function is created info.
* @param[in] storeLoadAnalysis Analysis for which store can reach some loads.
*/
GlobalToLocalAndDeadGlobalAssign::FuncInfo::FuncInfo(Function &func,
	StoreLoadAnalysis &storeLoadAnalysis): func(func),
		storeLoadAnalysis(storeLoadAnalysis) {}

/**
* @brief Destructs a function info;
*/
GlobalToLocalAndDeadGlobalAssign::FuncInfo::~FuncInfo() {}

/**
* @brief Returns a function for which is this function info created.
*/
Function &GlobalToLocalAndDeadGlobalAssign::FuncInfo::getFunc() {
	return func;
}

/**
* @brief Filters instructions that can't be optimized and returns if new one
*        appeared against last visit.
*
* @param[in, out] lUsesNotToOptimize Sets of left uses that can't be optimized.
* @param[in, out] rUsesNotToOptimize Sets of right uses that can't be optimized.
*
* @return @c true if right uses to not optimize was changed, otherwise @c false.
*/
bool GlobalToLocalAndDeadGlobalAssign::FuncInfo::
		filterUsesThatCannotBeOptimizedReturnIfChanged(
			std::set<llvm::Instruction*> &lUsesNotToOptimize, std::set<llvm::Instruction*> &rUsesNotToOptimize) {
	bool changed(false);
	for (auto i = storeLoadAnalysis.rUsesForLUse_begin(func),
			e = storeLoadAnalysis.rUsesForLUse_end(func); i != e; ++i) {
		if (hasItem(lUsesNotToOptimize, i->first)) {
			// We analyzed this left use.
			continue;
		}
		if (!canBeOptimized(*i->first, *i->first->getFunction(),
				i->second, rUsesNotToOptimize)) {
			lUsesNotToOptimize.insert(i->first);
			addToSet(i->second, rUsesNotToOptimize);
			changed = true;
		}
	}

	return changed;
}

/**
* @brief Returns @c true if @a lUse with its @a rUses can be optimized,
*        otherwise @c false.
*
* @param[in] lUse Left use.
* @param[in] func Parent function of @a lUse.
* @param[in] rUses Right uses that can be reached from @a lUse.
* @param[in] rUsesNotToOptimize Sets of right uses that can't be optimized.
*/
bool GlobalToLocalAndDeadGlobalAssign::FuncInfo::canBeOptimized(
		Instruction &lUse, Function &func, const std::set<llvm::Instruction*> &rUses,
		const std::set<llvm::Instruction*> &rUsesNotToOptimize) {
	if (isInFilteredLUses(lUse)) {
		// We know, that we don't want to optimize this left use.
		return false;
	}

	if (cast<StoreInst>(lUse).isVolatile()) {
		// We don't want to optimize volatile stores.
		// @see http://llvm.org/docs/LangRef.html#store-instruction
		return false;
	}

	for (Instruction *rUse : rUses) {
		if (rUse->getFunction() != &func) {
			// Right use is in another function.
			//
			// void func() {
			//   g = 2; <-- Don't want optimize.
			//   func1();
			// }
			// void func1() {
			//   x = g;
			// }
			//
			return false;
		}

		if (cast<LoadInst>(*rUse).isVolatile()) {
			// We don't want to optimize volatile loads.
			// @see http://llvm.org/docs/LangRef.html#load-instruction
			return false;
		}

		if (hasItem(rUsesNotToOptimize, rUse)) {
			// When we know that some right use can't be optimized from some
			// store instruction than we can't optimize another store which
			// can reach this right use.
			return false;
		}
	}

	return true;
}

/**
* @brief Returns @c true if @a inst is part of pattern, otherwise @c false.
*/
bool GlobalToLocalAndDeadGlobalAssign::FuncInfo::isPartOfPattern(
		Instruction &inst) {
	return hasItem(patternInsts, &inst);
}

/**
* @brief Finds the patterns in function.
*
* Pattern is something like that.
* @code
* func() {
*    tmp = g; // Part of pattern.
*    g = 4;
*    printf("%d", g);
*    g = 5;
*    printf("%d", g);
*    g = tmp; // Part of pattern.
* }
* @endcode
*
* In this situation we can change global variable @c g to local and remove
* assign to @c tmp variable and from this @c tmp variable.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::findPatterns() {
	for (auto i = storeLoadAnalysis.lastLUses_begin(func),
			e = storeLoadAnalysis.lastLUses_end(func); i != e; ++i) {
		if (!hasPattern(*i->first, i->second)) {
			continue;
		}

		Instruction *loadInst(findBeginfOfPattern(*i->first,
			**i->second.begin()));
		savePatterns(*loadInst, i->second);
	}
}

/**
* @brief returns @c true if we have some pattern, otherwise @c false.
*
* @param[in] globValue We tries to find pattern for this global variable.
* @param[in] lastLUses Last left uses for @a globValue.
*/
bool GlobalToLocalAndDeadGlobalAssign::FuncInfo::hasPattern(Value &globValue,
		const std::set<llvm::Instruction*> &lastLUses) {
	if (lastLUses.empty()) {
		return false;
	}

	if (!hasSameFirstOp(lastLUses)) {
		// All last left uses have to have same first operand, than we know
		// that in all exit blocks from functions we have assign temporary
		// variable to this global variable.
		return false;
	}

	if (!isInstsInSameFunc(lastLUses)) {
		// We have to have all last left uses from this function.
		return false;
	}

	if (!storeLoadAnalysis.isInNotGoThrough(globValue, func)) {
		// Exists some exit basic block where we don't have assign temporary
		// variable to global variable.
		return false;
	}

	Instruction *loadInst(findBeginfOfPattern(globValue, **lastLUses.begin()));
	if (!loadInst) {
		// If we don't have tmp = g than continue.
		return false;
	}

	if (&func != loadInst->getFunction()) {
		// We know that pattern is in another function.
		// In this situation below is spread last left use and right use to
		// function main so is need to check if we have function with pattern.
		// func() {
		//   v = g;
		//   g = v;
		// }
		// main() {
		//  func()
		// }
		return false;
	}

	std::set<llvm::Instruction*> uses(lastLUses.begin(), lastLUses.end());
	uses.insert(loadInst);
	if (UsesAnalysis::hasValueUsesExcept(*loadInst, uses)) {
		// Checks if tmp is not used in another place.
		// We can't have something like this:
		// tmp = g;
		// printf("%d", g);
		return false;
	}

	if (filteredRUses.hasExcept(globValue, std::set<llvm::Instruction*>{loadInst})) {
		// We know that some right use can't be optimized in this function.
		// So we can remove pattern.
		return false;
	}

	if (filteredLUses.hasExcept(globValue, lastLUses)) {
		// We know that some left use except last left uses can't be
		// optimize, so we can remove pattern.
		return false;
	}

	return true;
}

/**
* @brief Tries to find the start of pattern.
*
* @param[in] globValue We tries to find begin of pattern for this global
*            variable.
* @param[in] endInst Instruction that creates end of pattern.
*
* @return Found begin instruction of pattern, otherwise if not exists returns
*         the null pointer.
*/
Instruction *GlobalToLocalAndDeadGlobalAssign::FuncInfo::findBeginfOfPattern(
		Value &globValue, Instruction &endInst) {
	return storeLoadAnalysis.getInstFromExtRUses(*endInst.getOperand(0), globValue,
		func);
}

/**
* @brief Saves which instructions create patterns.
*
* This instructions can be removed at the end.
*
* @param[in] rUse Assign from global variable to @c tmp.
* @param[in] lUses Set of assigns @c tmp to global variable.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::savePatterns(Instruction &rUse,
		const std::set<llvm::Instruction*> &lUses) {
	patternInsts.insert(&rUse);
	addToSet(lUses, patternInsts);
}

/**
* @brief Optimized dead global assigns.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::removeDeadGlobalAssigns() {
	for (auto i = storeLoadAnalysis.rUsesForLUse_begin(func),
			e = storeLoadAnalysis.rUsesForLUse_end(func); i != e; ++i) {
		if (isInFilteredLUses(*i->first)) {
			// We don't want to optimize this left use.
			continue;
		}

		if (isPartOfPattern(*i->first)) {
			// Don't optimize parts of saved pattern.
			continue;
		}

		if (i->second.empty()) {
			++NumDeadGlobalAssign;
			i->first->eraseFromParent();
		}
	}
}

/**
* @brief Converts global variables to locals and replaces all uses of global
*        variables with new local variables.
*
* @param[in] deadGlobalAssign If is turned on dead global assign optimization.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::convertGlobsToLocs(
		bool deadGlobalAssign) {
	for (auto i = storeLoadAnalysis.rUsesForLUse_begin(func),
			e = storeLoadAnalysis.rUsesForLUse_end(func); i != e; ++i) {
		if (deadGlobalAssign) {
			if (i->second.empty()) {
				// We optimized this left use in removing dead global assigns.
				continue;
			}
		}

		if (isInFilteredLUses(*i->first)) {
			// We don't want to optimize this left use.
			continue;
		}

		if (isPartOfPattern(*i->first)) {
			// We don't want to optimize parts of pattern.
			continue;
		}

		Value *globValue(i->first->getOperand(1));
		Value *locVar(getLocVarFor(*globValue));
		replaceGlobToLocInInsts(*globValue, *locVar, *i->first, i->second);
	}
}

/**
* @brief Replaces global variable @a from in @a rUses and @a lUse with local
*        variable @a to.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::replaceGlobToLocInInsts(
		Value &from, Value &to, Instruction &lUse, const std::set<llvm::Instruction*> &rUses) {
	lUse.replaceUsesOfWith(&from, &to);
	for (Instruction *rUse : rUses) {
		rUse->replaceUsesOfWith(&from, &to);
	}
}

/**
* @brief Returns the first instruction that is not @c AllocaInst.
*
* @param[in] bb In this basic block we try to found instruction.
*
* @return First instruction that is not @c AllocaInst, if not exists returns
*         the null pointer.
*/
llvm::Instruction *GlobalToLocalAndDeadGlobalAssign::FuncInfo::getFirstNonAllocaInst(llvm::BasicBlock &bb) {
	for (auto &inst : bb) {
		if (!llvm::isa<llvm::AllocaInst>(inst)) {
			return &inst;
		}
	}

	return nullptr;
}

/**
* @brief Converts global variable @a glob to local when global variable is used
*        only in one function.
*
* For more details @see convertGlobsToLocUseInOneFunc().
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::convertGlobToLocUseInOneFunc(
		GlobalVariable &glob) {
	Value *globVal(glob.getValueName()->second);
	Value *locVar(getLocVarFor(glob));
	Instruction *nonAllocaInst(getFirstNonAllocaInst(func.getEntryBlock()));
	if (storeLoadAnalysis.hasSomeRUseEffectOutOfFunc(glob, func)
			&& glob.hasInitializer()) {
		// Creates assign of value to local variable only if it is needed.
		// It is needed when we don't have in all places left uses before right
		// uses.
		StoreInst *storeInst(new StoreInst(glob.getInitializer(), locVar));
		if (!nonAllocaInst) {
			func.getEntryBlock().getInstList().push_back(storeInst);
		} else {
			storeInst->insertBefore(nonAllocaInst);
		}
	}

	// Need to save it into set because replacing uses while iterating through
	// these uses causes problems.
	std::set<llvm::Instruction*> toReplace;
	for (auto i = glob.user_begin(), e = glob.user_end(); i != e; ++i) {
		Instruction *inst(dyn_cast<Instruction>(*i));
		assert(inst && "Not supported instruction.");
		toReplace.insert(inst);
	}

	// Replace all uses of this global variable in function.
	for (Instruction *inst : toReplace) {
		inst->replaceUsesOfWith(globVal, locVar);
	}
}

/**
* @brief Removes saved pattern instructions.
*
* Need to do this at the end because removed instructions before another
* part optimizations can causes missing instructions in contained info.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::removePatternInsts() {
	// Need to first erase left uses.
	for (auto i = patternInsts.begin(), e = patternInsts.end(); i != e; ) {
		if (StoreInst *lUse = dyn_cast<StoreInst>(*i)) {
			if (lUse->isVolatile()) {
				patternInsts.erase(i++);
				continue;
			}
			patternInsts.erase(i++);
			lUse->eraseFromParent();
		} else {
			++i;
		}
	}

	// Now we can erase all right uses.
	for (Instruction *rUse : patternInsts) {
		rUse->eraseFromParent();
	}
}

/**
* @brief Returns a local variable which replaces global variable @a globValue.
*/
Value *GlobalToLocalAndDeadGlobalAssign::FuncInfo::getLocVarFor(
		Value &globValue) {
	auto it(convertedGlobsToLoc.find(globValue.getName()));
	if (it != convertedGlobsToLoc.end()) {
		// For this value was created some local variable.
		return it->second;
	}

	auto lowerIt(convertedGlobsToLoc.lower_bound(globValue.getName()));
	AllocaInst *allocaInst(nullptr);
	std::string newVarName(getLocalVarNameFor(globValue));
	if (lowerIt != convertedGlobsToLoc.begin()) {
		// We get here lower sorted local variable(by name) so we add new local
		// variable after this local variable.
		--lowerIt;
		allocaInst = new AllocaInst(
			globValue.getType()->getPointerElementType(),
			newVarName
		);
		allocaInst->insertAfter(lowerIt->second);
	} else {
		// For example we have in map g1 and we are finding where is need to
		// place g0. Here we don't have lower sorted local variable so is need
		// to add this at the beginning of basic block.
		BasicBlock &entryBB(func.getEntryBlock());
		allocaInst = new AllocaInst(
			globValue.getType()->getPointerElementType(),
			newVarName,
			&entryBB.front()
		);
	}
	addMappingOfLocalVarToGlobalVarInConfig(
		ConfigProvider::getConfig(func.getParent()),
		&func,
		newVarName,
		globValue.getName()
	);
	convertedGlobsToLoc[globValue.getName()] = allocaInst;
	++CreatedLocVars;

	return allocaInst;
}

/**
* @brief Creates and returns a local-variable name for @a globValue.
*/
std::string GlobalToLocalAndDeadGlobalAssign::FuncInfo::getLocalVarNameFor(
		Value &globValue) {
	return globValue.getName().str() + SUFFIX_OF_LOC;
}

/**
* @brief Adds filtered right use @a rUse.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::addFilteredRUse(
		Instruction &rUse) {
	filteredRUses.addInst(*rUse.getOperand(0), rUse);
}

/**
* @brief Adds filtered left use @a lUse.
*/
void GlobalToLocalAndDeadGlobalAssign::FuncInfo::addFilteredLUse(
		Instruction &lUse) {
	filteredLUses.addInst(*lUse.getOperand(1), lUse);
}

/**
* @brief Returns @c true if @a lUse is in filtered left uses, otherwise
*        @c false.
*/
bool GlobalToLocalAndDeadGlobalAssign::FuncInfo::isInFilteredLUses(
		Instruction &lUse) {
	return filteredLUses.isIn(*lUse.getOperand(1), lUse);
}

} // namespace bin2llvmir
} // namespace retdec

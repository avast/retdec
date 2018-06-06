/**
* @file src/bin2llvmir/analyses/uses_analysis.cpp
* @brief Implementation of uses analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/analyses/uses_analysis.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/**
* @brief Emits all uses in basic blocks info to standard error.
*
* Only for debugging purposes.
*/
void UsesAnalysis::printBBsUses() {
	errs() << "[UsesAnalysis] Debug for basic blocks uses.\n";
	errs() << "-----------------------------------------------\n";
	for (auto &item : bbUseInfoMap) {
		errs() << "[UsesAnalysis] Debug info for basic block: '" <<
			item.first->getName() << "':\n";
		item.second->printBBUses();
	}
}

/**
* @brief Emits basic block uses to standard error.
*
* Only for debugging purposes.
*/
void UsesAnalysis::BBUses::printBBUses() {
	errs() << "*******************************************\n";
	errs() << "Uses info:\n";
	for (auto &item : useInfoMap) {
		errs() << "     Instruction: '" << *item.first << "'\n";
		errs() << "          Value for use: '" << *item.second.value << "'.";
		if (item.second.isLUse) {
			errs() << " Left use.\n" ;
		} else {
			errs() << " Right use.\n" ;
		}
	}
	errs() << "*******************************************\n";
}

/**
* @brief Emits basic block uses to standard error.
*
* Only for debugging purposes.
*/
void UsesAnalysis::printBBUses(BasicBlock &bb) {
	errs() << "[UsesAnalysis] Debug info for basic block: '" <<
		bb.getName() << "':\n";
	auto it(bbUseInfoMap.find(&bb));
	if (it == bbUseInfoMap.end()) {
		errs() << "     Uses for basic block were not found.\n";
		return;
	}
	it->second->printBBUses();
}

/**
* @brief Constructs a new uses analysis info.
*/
UsesAnalysis::UsesAnalysis() {}

/**
* @brief Destructs a uses analysis info.
*/
UsesAnalysis::~UsesAnalysis() {
	clear();
}

/**
* @brief Runs analysis about uses of @a globs and saves contained info.
*
* This method is need to run before methods that finds out results of this
* uses analysis.
*
* @param[in] globs Global variables of which uses are processing.
*/
void UsesAnalysis::doUsesAnalysis(const std::set<llvm::GlobalVariable*> &globs) {
	// If analysis was run before than now is need to clear everything.
	clear();

	for (GlobalVariable *glob : globs) {
		goThroughUses(*glob);
	}
}

/**
* @brief Clears allocated info.
*/
void UsesAnalysis::clear() {
	for (auto &item : bbUseInfoMap) {
		delete item.second;
	}
}

/**
* @brief Returns info about use for @a inst in @a bb if some exists, otherwise
*        returns the null pointer.
*
* Run @c doUsesAnalyses() before first use of this method.
*/
const UsesAnalysis::UseInfo *UsesAnalysis::getUseInfo(
		BasicBlock &bb, Instruction &inst) {
	auto it(bbUseInfoMap.find(&bb));
	return it != bbUseInfoMap.end()? it->second->getUseInfo(inst) : nullptr;
}

/**
* @brief Checks if exists some another uses except uses in @a std::set<llvm::Instruction*> for
*        @a value.
*
* @return @c true if has more uses, otherwise @c false.
*/
bool UsesAnalysis::hasValueUsesExcept(Value &value, const std::set<llvm::Instruction*> &instSet) {
	for (auto i = value.user_begin(), e = value.user_end(); i != e; ++i) {
		Instruction *inst(dyn_cast<Instruction>(*i));
		if (!inst) {
			// This is not instruction and we have set of instructions so
			// now we know that we have some use except instructions in set of
			// instructions.
			return true;
		}

		if (!hasItem(instSet, inst)) {
			return true;
		}
	}

	return false;
}

/**
* @brief Returns if @a glob has no uses.
*/
bool UsesAnalysis::hasNoUse(GlobalVariable &glob) {
	return glob.use_empty();
}

/**
* @brief Returns if @a glob has uses only in one function.
*
* If @a glob has no use than returns @c false because has no use.
*/
bool UsesAnalysis::hasUsesOnlyInOneFunc(GlobalVariable &glob) {
	if (hasNoUse(glob)) {
		return false;
	}

	// Go through uses.
	Instruction *firstUse(dyn_cast<Instruction>(*glob.user_begin()));
	if (!firstUse) {
		// Not supported instruction.
		return false;
	}
	Function *func(firstUse->getFunction());
	for (auto i = glob.user_begin(), e = glob.user_end(); i != e; ++i) {
		Instruction *useInst(dyn_cast<Instruction>(*i));
		if (!useInst) {
			// Not supported instruction.
			return false;
		}

		if (func != useInst->getFunction()) {
			// Different function.
			return false;
		}
	}

	return true;
}

/**
* @brief Returns @c true if some use of @a glob is volatile store or load,
*        otherwise @c false.
*/
bool UsesAnalysis::hasSomeUseVolatileLoadOrStore(GlobalVariable &glob) {
	for (auto i = glob.user_begin(), e = glob.user_end(); i != e; ++i) {
		if (LoadInst *load = dyn_cast<LoadInst>(*i)) {
			if (load->isVolatile()) {
				return true;
			}
		} else if (StoreInst *store = dyn_cast<StoreInst>(*i)) {
			if (store->isVolatile()) {
				return true;
			}
		}
	}

	return false;
}

/**
* @brief Goes through uses for @a glob and saves useful info obtained from use.
*
* Useful info means: Store to global variable or load from global variable.
*
* @param[in] glob Global variable which uses are analyzed.
*/
void UsesAnalysis::goThroughUses(GlobalVariable &glob) {
	for (auto i = glob.user_begin(), e = glob.user_end(); i != e; ++i) {
		// We grouped informations of use by their basic blocks.
		if (StoreInst *storeInst = dyn_cast<StoreInst>(*i)) {
			if (glob.getValueName() == storeInst->getOperand(1)->getValueName()) {
				// Saving info about new use on left.
				addNewLUse(*storeInst->getParent(), *storeInst);
			}
		} else if (LoadInst *loadInst = dyn_cast<LoadInst>(*i)) {
			// Saving info about new use on right.
			addNewRUse(*loadInst->getParent(), *loadInst);
		}
	}
}

/**
* @brief Saves a left use @a lUse for @a bb.
*/
void UsesAnalysis::addNewLUse(BasicBlock &bb, Instruction &lUse) {
	getIfExistsOrCreateNewBBInfo(bb).addNewLUse(lUse);
}

/**
* @brief Saves a right use @a rUse for @a bb.
*/
void UsesAnalysis::addNewRUse(BasicBlock &bb, Instruction &rUse) {
	getIfExistsOrCreateNewBBInfo(bb).addNewRUse(rUse);
}

/**
* @brief Tries to find existing basic block info and if not exists create new.
*
* @param[in] bb For this basic block is finding basic block info.
*
* @return Found basic block info, otherwise created new one.
*/
UsesAnalysis::BBUses &UsesAnalysis::getIfExistsOrCreateNewBBInfo(
		BasicBlock &bb) {
	auto it(bbUseInfoMap.find(&bb));
	if (it != bbUseInfoMap.end()) {
		return *it->second;
	} else {
		BBUses *bbUses(new BBUses());
		bbUseInfoMap[&bb] = bbUses;
		return *bbUses;
	}
}

/**
* @brief Constructs a new basic block info.
*/
UsesAnalysis::BBUses::BBUses() {}

/**
* @brief Destructs a basic block info.
*/
UsesAnalysis::BBUses::~BBUses() {}

/**
* @brief Saves a left use @a lUse.
*/
void UsesAnalysis::BBUses::addNewLUse(Instruction &lUse) {
	// store i32 1, i32* @glob0, so second operand is glob0.
	// Left because glob0 = 1; - global variable is on the left.
	useInfoMap[&lUse] = UseInfo::createLeftUseInfo(lUse.getOperand(1));
}

/**
* @brief Saves a right use @a rUse.
*/
void UsesAnalysis::BBUses::addNewRUse(Instruction &rUse) {
	// %x = load i32, i32* @glob0, so first operand is glob0.
	// Right because x = glob0; - global variable is on the right.
	useInfoMap[&rUse] = UseInfo::createRightUseInfo(rUse.getOperand(0));
}

/**
* @brief Returns info about use for @a inst if some exists, otherwise returns
*        the null pointer.
*/
const UsesAnalysis::UseInfo *UsesAnalysis::BBUses::getUseInfo(
		Instruction &inst) {
	auto it(useInfoMap.find(&inst));
	return it != useInfoMap.end()? &it->second : nullptr;
}

} // namespace bin2llvmir
} // namespace retdec

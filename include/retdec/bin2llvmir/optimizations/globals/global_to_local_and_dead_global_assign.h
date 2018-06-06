/**
* @file include/retdec/bin2llvmir/optimizations/globals/global_to_local_and_dead_global_assign.h
* @brief Converts global variables to local variables and removes dead assigns.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_GLOBALS_GLOBAL_TO_LOCAL_AND_DEAD_GLOBAL_ASSIGN_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_GLOBALS_GLOBAL_TO_LOCAL_AND_DEAD_GLOBAL_ASSIGN_H

#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/store_load_analysis.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/utils/debug.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Global to local and dead global assign optimization.
*
* What optimizes each optimization @see GlobalToLocal and @see DeadGlobalAssign.
*
* We don't optimize global variable in some special cases:
* 1. Global variable is not single type (array, structure, etc.).
* 2. Global variable is a pointer.
* 3. Address of global variable can be taken.
* 4. Global variable that doesn't have private or internal linkage.
*
* To decide when something optimize this optimization uses three pieces of
* information that are obtained in this optimization:
*  - Extended Right uses (in code @c extRUses)
*  - Last left uses (in code @c lastLUses).
*  - Not go through global variables (in code @c notGoThrough).
* How is this info obtained and what means @see StoreLoadAnalysis.
*/
class GlobalToLocalAndDeadGlobalAssign: public llvm::ModulePass {
public:
	GlobalToLocalAndDeadGlobalAssign();
	virtual ~GlobalToLocalAndDeadGlobalAssign() override;

	virtual bool runOnModule(llvm::Module &module) override;
	virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;

public:
	static char ID;

protected:
	// Signalizes that we want to do global to local optimization.
	bool globalToLocal;

	// Signalizes that we want to do dead global assign optimization.
	bool deadGlobalAssign;

private:
	/**
	* @brief Class for function info.
	*/
	class FuncInfo {
	public:
		FuncInfo(llvm::Function &func, StoreLoadAnalysis &storeLoadAnalysis);
		~FuncInfo();

		llvm::Function &getFunc();
		bool filterUsesThatCannotBeOptimizedReturnIfChanged(
			std::set<llvm::Instruction*> &lUsesNotToOptimize,
			std::set<llvm::Instruction*> &rUsesNotToOptimize);
		void findPatterns();
		bool hasPattern(llvm::Value &globValue,
			const std::set<llvm::Instruction*> &lastLUses);
		llvm::Instruction *findBeginfOfPattern(llvm::Value &globValue,
			llvm::Instruction &endInst);
		void savePatterns(llvm::Instruction &rUse,
			const std::set<llvm::Instruction*> &lUses);
		void convertGlobsToLocs(bool deadGlobalAssign);
		void removeDeadGlobalAssigns();
		void convertGlobToLocUseInOneFunc(llvm::GlobalVariable &glob);
		void removePatternInsts();
		void addExtRUsesToNotToOptimize(std::set<llvm::Instruction*> &notToOptimize);
		void addFilteredRUse(llvm::Instruction &rUse);
		void addFilteredLUse(llvm::Instruction &lUse);
		bool isInFilteredLUses(llvm::Instruction &lUse);

		void printFuncInfo();

	private:
		/// Mapping of a string to allocation instruction.
		using StringAllocaInstMap = std::map<std::string, llvm::AllocaInst *>;

	private:
		llvm::Value *getLocVarFor(llvm::Value &glob);
		std::string getLocalVarNameFor(llvm::Value &globValue);
		bool canBeOptimized(llvm::Instruction &lUse, llvm::Function &func,
			const std::set<llvm::Instruction*> &rUses,
			const std::set<llvm::Instruction*> &rUsesNotToOptimize);
		bool isPartOfPattern(llvm::Instruction &inst);
		void replaceGlobToLocInInsts(llvm::Value &from, llvm::Value &to,
			llvm::Instruction &lUse, const std::set<llvm::Instruction*> &rUses);
		llvm::Instruction *getFirstNonAllocaInst(llvm::BasicBlock &bb);

	private:
		/// For this function is created info.
		llvm::Function &func;

		/// Mapping of a global variable name to a local variable.
		StringAllocaInstMap convertedGlobsToLoc;

		/// Analysis for store and load instructions.
		StoreLoadAnalysis &storeLoadAnalysis;

		/// Contains instructions that create patterns.
		std::set<llvm::Instruction*> patternInsts;

		/// Saves filtered left uses in function.
		AnalysisInfo::ValInstSetMap filteredLUses;

		/// Saves filtered right uses in function.
		AnalysisInfo::ValInstSetMap filteredRUses;
	};

	/// Mapping of a function to function info.
	using FuncFuncInfoMap = std::map<llvm::Function *, FuncInfo *>;

private:
	void solveIndirectCallsAndNotAggressive();
	void solveNotAggressive();
	void solveLUsesForIndirectCalls();
	void solveLastLUsesForIndirectCalls();
	void goThroughLastLUsesAndSolveIndirectCalls(llvm::Function &func,
		const AnalysisInfo::ValInstSetMap &extRUses);
	void filterUsesThatCannotBeOptimized();
	bool goThroughFuncsInfoFilterAndReturnIfChanged(
		std::set<llvm::Instruction*> &lUsesNotToOptimize,
		std::set<llvm::Instruction*> &rUsesNotToOptimize);
	void doOptimization(llvm::Module &module,
		const std::set<llvm::GlobalVariable*> &globsToOptimize);
	void createInfoForAllFuncs(llvm::Module &module);
	void removePatternInsts();
	void convertGlobsToLocUseInOneFunc(const std::set<llvm::GlobalVariable*> &globs);
	bool hasSomeLUseForFuncOutOfModule(llvm::GlobalVariable &glob);
	void removeGlobsWithoutUse(llvm::Module::GlobalListType &globs);
	void addFilteredLUse(llvm::Instruction &lUse);
	void addFilteredRUse(llvm::Instruction &rUse);
	void addFilteredLUses(const std::set<llvm::Instruction*> &lUses);
	void addFilteredRUses(const std::set<llvm::Instruction*> &rUses);
	bool wasSomethingOptimized();
	FuncInfo &getFuncInfoFor(llvm::Function &func);

	void printFuncInfos();

private:
	/// Analysis for store and load instructions.
	StoreLoadAnalysis storeLoadAnalysis;

	/// Contains filtered right uses that can't be optimized.
	std::set<llvm::Instruction*> rUsesNotToOptimize;

	/// Mapping of a function to its info.
	FuncFuncInfoMap funcInfoMap;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

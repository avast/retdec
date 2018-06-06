/**
* @file include/retdec/bin2llvmir/analyses/store_load_analysis.h
* @brief Analysis that find out relations between load and store instructions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_STORE_LOAD_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_STORE_LOAD_ANALYSIS_H

#include <set>

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/analyses/traversal/bb_traversal_analysis.h"
#include "retdec/bin2llvmir/analyses/traversal/func_traversal_analysis.h"
#include "retdec/bin2llvmir/analyses/uses_analysis.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Contains some support for info that is contained by analysis.
*
* Contains support for:
* - For extended right uses.
* - For not go through.
* - For last left uses.
* - For global variables for indirect calls.
* - For global variables for calls for functions defined out of module.
* - For more details about this info @see StoreLoadAnalysis
*/
class AnalysisInfo {
public:
	/**
	* @brief Class that has one storage which is map where instruction set is
	*        mapped by value. This class implements support methods for this map.
	*/
	class ValInstSetMap {
	private:
		/// Mapping of a value to instruction set.
		using Storage = std::map<llvm::Value *, std::set<llvm::Instruction*>>;

	private:
		/// Storage for this class.
		Storage storage;

	public:
		/// ValInstSetMap constant iterator.
		/// Attributes (@c i is an iterator):
		///   - @c i->first is the key,
		///   - @c i->second is the mapped set of instructions.
		using iterator = Storage::const_iterator;

		/// @name ValInstSetMap constant accessors.
		/// @{
		iterator begin() const;
		iterator end() const;
		/// @}

	public:
		ValInstSetMap();
		~ValInstSetMap();

		void addInst(llvm::Value &value, llvm::Instruction &inst);
		void addInsts(llvm::Value &value, const std::set<llvm::Instruction*> &instSet);
		void addFrom(const ValInstSetMap &toAdd);
		void appendInstsFor(llvm::Value &value, std::set<llvm::Instruction*> &instSet);
		void clear();
		bool empty();
		bool isDifferentFrom(const ValInstSetMap &toDiff);
		bool isValIn(llvm::Value &value);
		bool isIn(llvm::Value &value, llvm::Instruction &inst);
		llvm::Instruction *getInstFor(llvm::Value &leftOp,
			llvm::Value &rightOp);
		bool hasExcept(llvm::Value &value, const std::set<llvm::Instruction*> &except);
		void tryToRemoveValue(llvm::Value &value);
		iterator find(llvm::Value &value) const;

		void print();
	};

	/// Extended right uses iterator.
	using extRUses_iterator = ValInstSetMap::iterator;

	/// Not go through global variables constant iterator.
	using notGoThrough_iterator = std::set<llvm::Value*>::const_iterator;

	/// Last left uses constant iterator.
	using lastLUses_iterator = ValInstSetMap::iterator;

public:
	AnalysisInfo();
	~AnalysisInfo();

	/// @name Extended right uses constant accessors.
	/// @{
	extRUses_iterator extRUses_begin() const;
	extRUses_iterator extRUses_end() const;
	/// @}

	/// @name Not go through global variables constant accessors.
	/// @{
	notGoThrough_iterator notGoThrough_begin() const;
	notGoThrough_iterator notGoThrough_end() const;
	/// @}

	/// @name Last left uses constant accessors.
	/// @{
	lastLUses_iterator lastLUses_begin() const;
	lastLUses_iterator lastLUses_end() const;
	/// @}

	void addExtRUse(llvm::Value &value, llvm::Instruction &inst);
	void addExtRUses(const AnalysisInfo &toAdd);
	bool areExtRUsesDiff(const AnalysisInfo &toDiff);
	bool isInExtRUses(llvm::Value &value);
	llvm::Instruction *getInstFromExtRUses(llvm::Value &leftOp,
		llvm::Value &rightOp);
	void appendFromExtRUses(llvm::Value &value, std::set<llvm::Instruction*> &instSet);
	void copyExtRUses(ValInstSetMap &toCopy);
	void removeValFromExtRUses(llvm::Value &value);
	void clearExtRUses();
	void clearGlobsForIndirectCalls();
	void clearGlobsForCallsForFuncsOutOfModule();
	void addNotGoThrough(llvm::Value &value);
	void addNotGoThrough(const AnalysisInfo &toAdd);
	bool isInNotGoThrough(llvm::Value &value) const;
	void intersectNotGoThrough(const AnalysisInfo &toAdd);
	bool areNotGoThroughDiff(const AnalysisInfo &toDiff);
	void replaceExceptLastLUses(const AnalysisInfo toReplace);
	bool emptyNotGoThrough();
	void addLastLUse(llvm::Value &value, llvm::Instruction &inst);
	void addLastLUses(llvm::Value &value, const std::set<llvm::Instruction*> &instSet);
	bool areLastLUsesDiff(const AnalysisInfo &toDiff);
	bool emptyLastLUses();
	void addGlobForIndirectCalls(llvm::Value &value);
	void addToGlobsForIndirectCalls(const AnalysisInfo &toAdd);
	bool areGlobsForIndirectCallsDiff(const AnalysisInfo &toDiff);
	bool isInGlobsForIndirectCalls(llvm::Value &value) const;
	void removeGlobFromGlobsForIndirectCalls(llvm::Value &value);
	void addToGlobsForCallsForFuncsOutOfModule(llvm::Value &value);
	void addGlobsForCallsForFuncsOutOfModule(const AnalysisInfo &toAdd);
	bool areGlobsForCallsForFuncsOutOfModuleDiff(const AnalysisInfo &toDiff);
	bool isInGlobsForCallsForFuncsOutOfModule(llvm::Value &value) const;
	void removeGlobFromGlobsForCallForFuncsOutOfModule(llvm::Value &value);

	void printExtRUses();
	void printNotGoThrough();
	void printLastLUses();
	void printGlobsForIndirectCalls();
	void printGlobsForCallsForFuncsOutOfModule();

private:
	/// Right uses with saved instructions for these right uses.
	ValInstSetMap extRUses;

	/// Not go through global variables.
	std::set<llvm::Value*> notGoThrough;

	/// Last left uses.
	ValInstSetMap lastLUses;

	/// Global variables for indirect calls.
	std::set<llvm::Value*> globsForIndirectCalls;

	/// Global variables for calls of functions defined out of module.
	std::set<llvm::Value*> globsForCallsForFuncsOutOfModule;
};

/**
* @brief Analysis that finds out relations between load and store instructions.
*
* Before use info from this analysis is need to run @c doAnalysis().
*
* For this analysis we need to know two terms.
* - Left use: Assign something to global variable.
* @code
* store i32 1, i32* @glob0
* @endcode
* - Right use: Read something from global variable.
* @code
* %x = load i32, i32* @glob0
* @endcode
*
* This analysis contains these information:
* - Extended right uses:
* @code
* func() {
*   x = g; // g is global variable. Right use.
* }
* @endcode
* Assign of global variable @c g we call right use in @c func because this right
* use is not connected with some store. We can have this information also for
* basic block. Extended is because we map global variable to all right uses for
* this global variable.
*
* - Last left uses:
* @code
* func() {
*   g = 4;
*   g = 2; // g is global variable. Last left use.
* }
* @endcode
* Assign value 2 to global variable we call last left use in @c func because
* after end of this function will global variable @c g have value 2. This info
* is saved only for function.
*
* - Not go through:
* @code
* func() {
*   ... ; // Not go through for global variable g.
*   g = 2;
* }
* @endcode
* Before assign to global variable @c g we have saved not go through for this
* global variable. It means that we have saved last left use for this way of
* execution. This info is saved for basic block and function.
*
* - Right uses for left use:
* @code
* bb:
*   store i32 1, @glob0
*   br label i1 1, label %left, label %right
* left:
*   %x = load i32, i32* @glob0
* right:
*   %y = load i32, i32* @glob.
* @endcode
* We can get info about relations between store and load instructions. Relation
* we mean that which load instructions can be reached with some specific store
* instruction. So in this info we have saved that both of loads can be reached
* with mentioned store.
*
* - Left uses for call of functions defined out of module:
* Analysis saves all stores that can reach call of functions defined out of
* module.
*
* - Left uses for indirect calls:
* Analysis saves all stores that can reach indirect calls.
*
* - Extended right uses for indirect calls:
* Analysis saves all extended right uses that is before indirect call of some
* function. This extended right uses are saved to all functions that can be
* indirectly called.
* For example:
* @code
* indirect_call_of_some_func().
* %x = load i32, i32* @glob0
* @endcode
* We save right uses below the indirect call to all functions that can be
* indirectly called. In right uses can be saved some indirect call which means
* that some indirect call can be reached from this indirect call.
*/
class StoreLoadAnalysis {
private:
	/// Mapping of a function to @c ValInstSetMap.
	using FuncValInstSetMap = std::map<llvm::Function *,
		AnalysisInfo::ValInstSetMap>;

public:
	/// Right uses for left use constant iterator.
	///   - @c i->first is the left use,
	///   - @c i->second is the set of right uses that can be reached with left
	///        use.
	using rUsesForLUse_iterator = std::map<llvm::Instruction*, std::set<llvm::Instruction*>>::const_iterator;

	/// Extended right uses constant iterator.
	///   - @c i->first is the global variable for extended right uses,
	///   - @c i->second is the right uses.
	using extRUses_iterator = AnalysisInfo::extRUses_iterator;

	/// Last left uses constant iterator.
	/// Attributes (@c i is an iterator):
	///   - @c i->first is the global variable for left uses,
	///   - @c i->second is the left uses.
	using lastLUses_iterator = AnalysisInfo::lastLUses_iterator;

	/// Constant iterator for left uses that can reach call of functions defined
	/// out of module.
	using lUsesOutFunc_iterator = std::set<llvm::Instruction*>::const_iterator;

	/// Constant iterator for left uses that can reach indirect call.
	using lUsesIndir_iterator = std::set<llvm::Instruction*>::const_iterator;

	/// Constant iterator for extended right uses that can reach indirect call.
	/// Attributes (@c i is an iterator):
	///   - @c i->first is the function that can be reached by extended right
	///        uses,
	///   - @c i->second is the extended right uses that can reach indirect
	///        call.
	using extRUsesIndir_iterator = FuncValInstSetMap::const_iterator;

public:
	StoreLoadAnalysis();
	~StoreLoadAnalysis();

	/// @name Right uses for left use constant accessors.
	/// @{
	rUsesForLUse_iterator rUsesForLUse_begin(llvm::Function &func) const;
	rUsesForLUse_iterator rUsesForLUse_end(llvm::Function &func) const;
	/// @}

	/// @name Extended right uses constant accessors.
	/// @{
	extRUses_iterator extRUses_begin(llvm::Function &func) const;
	extRUses_iterator extRUses_end(llvm::Function &func) const;
	/// @}

	/// @name Last left uses constant accessors.
	/// @{
	lastLUses_iterator lastLUses_begin(llvm::Function &func) const;
	lastLUses_iterator lastLUses_end(llvm::Function &func) const;
	/// @}

	/// @name Constant accessors for left uses that can reach call of functions
	///       defined out of module.
	/// @{
	lUsesOutFunc_iterator lUsesOutFunc_begin() const;
	lUsesOutFunc_iterator lUsesOutFunc_end() const;
	/// @}

	/// @name Constant accessors for left uses that can reach indirect call.
	/// @{
	lUsesIndir_iterator lUsesIndir_begin() const;
	lUsesIndir_iterator lUsesIndir_end() const;
	/// @}

	/// @name Constant accessors for extended right uses that can reach indirect
	///       call.
	/// @{
	extRUsesIndir_iterator extRUsesIndir_begin() const;
	extRUsesIndir_iterator extRUsesIndir_end() const;
	/// @}

	void doAnalysis(llvm::Module &module, std::set<llvm::GlobalVariable*> &globs,
		llvm::CallGraph &callGraph, bool funcsOutOfModule);
	bool isInLUsesForFuncOutOfModule(llvm::StoreInst &inst);
	bool hasSomeRUseEffectOutOfFunc(llvm::Value &globValue,
		llvm::Function &func);
	bool isInNotGoThrough(llvm::Value &globValue, llvm::Function &func);
	llvm::Instruction *getInstFromExtRUses(llvm::Value &leftOp,
		llvm::Value &rightOp, llvm::Function &func);
	std::set<llvm::Instruction*> getRUsesForLUse(llvm::Instruction &lUse);

	void printFuncInfos();
	void printFuncInfo(llvm::Function &func);

private:
	/**
	* @brief Class for basic block info.
	*/
	class BBInfo {
	public:
		/// Ordered instructions constant iterator.
		using ordInsts_iterator = std::vector<llvm::Instruction*>::const_iterator;

	public:
		BBInfo(llvm::BasicBlock &bb);
		~BBInfo();

		/// @name Ordered instructions accessors.
		/// @{
		ordInsts_iterator ordInsts_begin();
		ordInsts_iterator ordInsts_end();
		/// @}

		llvm::BasicBlock &getBB();
		void addIndirectCall(llvm::CallInst &callInst);
		void addCallForFuncOutOfModule(llvm::CallInst &callInst);
		void addAllGlobsToNotGoThrough(const std::set<llvm::GlobalVariable*> &globs);
		void addAllGlobsToGlobsForIndirectCall(
			const std::set<llvm::GlobalVariable*> &globs);
		void addAllGlobsToGlobsForCallsForFuncsOutOfModule(
			const std::set<llvm::GlobalVariable*> &globs);
		void tryToAddInstToOrderedList(llvm::Instruction &inst);
		void clearExtRUses();
		void clearGlobsForIndirectCalls();
		void clearCallsForFuncsOutOfModule();
		void clearInfo();
		void doCopyOfBBInfoAndCreateNew();
		void diffBBInfoFromLastVisitAndSetIfChanged();
		bool hasAnalyzedOrdsInsts();
		bool hasChangedInfo();
		bool hasLastLUse(llvm::Value &globValue);
		void markAsAnalyzedOrdInsts();
		void markAsNotAnalyzedOrdInsts();
		void markAsChangedInfo();
		void markAsNotChangedInfo();

		void printBBInfo();

	public:
		// Basic block info.
		AnalysisInfo *bbInfo;

		// Snapshot of basic block info.
		AnalysisInfo *copyBBInfo;

	private:
		// For this basic block is created info.
		llvm::BasicBlock &bb;

		// If has saved useful instructions.
		bool hasAnalyzedOrdInsts;

		// If info was changed from last visit.
		bool changedInfo;

		/// Saves order of useful instructions in basic block.
		std::vector<llvm::Instruction*> orderedInstVec;
	};

	/**
	* @brief Class for function info.
	*/
	class FuncInfo {
	public:
		FuncInfo(llvm::Function &func);
		~FuncInfo();

		/// @name Right uses for left use constant accessors.
		/// @{
		rUsesForLUse_iterator rUsesForLUse_begin() const;
		rUsesForLUse_iterator rUsesForLUse_end() const;
		/// @}

		/// @name Extended right uses constant accessors.
		/// @{
		extRUses_iterator extRUses_begin() const;
		extRUses_iterator extRUses_end() const;
		/// @}

		/// @name Last left uses constant accessors.
		/// @{
		lastLUses_iterator lastLUses_begin() const;
		lastLUses_iterator lastLUses_end() const;
		/// @}

		llvm::Function &getFunc();
		void addInRUsesForLUse(llvm::Instruction &lUse,
			const std::set<llvm::Instruction*> &rUse);
		std::set<llvm::Instruction*> getRUsesForLUse(llvm::Instruction &lUse);
		bool isBBVisited(llvm::BasicBlock &bb);
		llvm::Instruction *getInstFromExtRUses(llvm::Value &leftOp,
			llvm::Value &rightOp);
		void markBBAsVisited(llvm::BasicBlock &bb);
		bool isAnalyzed();
		void markAsAnalyzed();
		void markAsNotAnalyzed();
		void doCopyOfFuncInfoAndCreateNew();
		void clearVisitedBBs();
		bool isDiffFuncInfoFromLastVisit();
		bool isInExtRUses(llvm::Value &globValue);
		bool isInNotGoThrough(llvm::Value &globValue);
		void setFuncInfo(BBInfo &bbInfo);
		void removeFromRUsesForLUse(llvm::Instruction &lUse);

		void printFuncInfo();

	public:
		// Function info.
		AnalysisInfo *funcInfo;

		// Snapshot of function info.
		AnalysisInfo *copyFuncInfo;

	private:
		/// For this function is created this function info.
		llvm::Function &func;

		// Right uses for left use are saved in function where left use occur.
		/// Mapping of right uses for left use.
		std::map<llvm::Instruction*, std::set<llvm::Instruction*>> rUsesForLUse;

		/// Signalizes if this function was analyzed before.
		bool isAnalyzedFunc;

		/// Visited basic blocks for this function.
		std::set<llvm::BasicBlock*> visitedBBs;
	};

	/// Mapping of a function to function info.
	using FuncFuncInfoMap = std::map<llvm::Function *, FuncInfo *>;

	/// Mapping of a basic block to basic block info.
	using BBBBInfoMap = std::map<llvm::BasicBlock *, BBInfo *>;

private:
	void runAnalysis();
	void setFuncsInModule(llvm::Module &module);
	void createInfoForAllFuncs();
	void analyzeFuncsInSCC();
	void analyzeFuncNotInSCC();
	bool goThroughFuncsInSCCAndReturnIfChanged();
	void initBeforeProcessFuncInSCC(llvm::Function &func);
	void clearBBInfosIn(llvm::Function &func);
	void processFunc(llvm::Function &func);
	void goThroughBBsAndAnalyzeThem(llvm::Function &func);
	void afterAnalysisBBsInFunc();
	void visitBBsInSCC();
	void visitBBNotInSCC();
	void spreadNotGoThroughInSCC();
	bool goThroughBBsSCCAndReturnIfChanged();
	void processBB(llvm::BasicBlock &bb);
	bool isNeedToProcessBB(llvm::BasicBlock &bb, bool isBBVisited);
	void addInfoFromSuccBBsFor(llvm::BasicBlock &bb, bool isVisitedBB);
	void processInstsInBB(llvm::BasicBlock::InstListType &instList);
	void processInstsInBB();
	void tryToProcessInst(llvm::Instruction &inst);
	void processFuncCall(llvm::CallInst &callInst);
	void processCalledFuncInfo(const AnalysisInfo &calledFuncInfo);
	void solveIndirectCall(llvm::CallInst &callInst);
	void solveCallForFuncsOutOfModule();
	void addToExtRUsesForIndirectCall(
		const AnalysisInfo::ValInstSetMap &extRUses,
		llvm::Function &func);
	void processExtRUsesAfterFuncCall(const AnalysisInfo &calledFuncInfo);
	void processGlobsForIndirectCallAfterFuncCall(const AnalysisInfo &calledFuncInfo);
	void processCallsForFuncOutOfModuleAfterFuncCall(
		const AnalysisInfo &calledFuncInfo);
	void addInRUsesForLUses(const std::set<llvm::Instruction*> &lUses,
		const std::set<llvm::Instruction*> &rUses);
	void addInRUsesForLUse(llvm::Instruction &lUse,
		const std::set<llvm::Instruction*> &rUses);
	void addInLUsesForIndirectCalls(const std::set<llvm::Instruction*> &lUses);
	void addInLUsesForFuncsOutOfModule(const std::set<llvm::Instruction*> &lUses);
	void addToLastLUsesWithCheck(const AnalysisInfo &toAdd);
	void processLUse(llvm::Value &globValue, llvm::Instruction &lUse);
	void solveIndirectCallsForLUses(llvm::Value &globValue,
		const std::set<llvm::Instruction*> &lUses);
	void solveCallsForFuncsOutOfModuleForLUses(llvm::Value &globValue,
		const std::set<llvm::Instruction*> &lUses);
	void tryToAddLastLUse(llvm::Value &globValue, llvm::Instruction &lUse);
	void setCurrBBInfo(llvm::BasicBlock &bb);
	void setCurrFuncInfo(llvm::Function &func);
	FuncInfo &getFuncInfoFor(llvm::Function &func) const;
	BBInfo *getBBInfoFor(llvm::BasicBlock &bb);
	void clear();

	void printBBInfos();

private:
	/// Uses analysis.
	UsesAnalysis usesAnalysis;

	/// Function traversal analysis.
	FuncTraversalAnalysis funcTraversalAnalysis;

	/// Basic block traversal analysis.
	BBTraversalAnalysis bbTraversalAnalysis;

	/// Signalizes if analysis have to count with functions defined out of
	/// module.
	bool countWithFuncsOutOfModule;

	/// Functions that are in module.
	std::vector<llvm::Function*> funcsInModule;

	/// Global variables that can be optimized.
	std::set<llvm::GlobalVariable*> globsToAnalyze;

	/// Left uses that can reach indirect call.
	std::set<llvm::Instruction*> lUsesForIndirectCall;

	/// Extended right uses that can reach indirect call.
	FuncValInstSetMap extRUsesForIndirectCall;

	/// Left uses that can reach functions defined out of module.
	std::set<llvm::Instruction*> lUsesForFuncsOutOfModule;

	/// Mapping of a function to its info.
	FuncFuncInfoMap funcInfoMap;

	/// Mapping of a basic block to its info.
	BBBBInfoMap bbInfoMap;

	/// Current function info.
	FuncInfo *currFuncInfo;

	/// Current basic block info.
	BBInfo *currBBInfo;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

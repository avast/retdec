/**
* @file include/retdec/bin2llvmir/analyses/uses_analysis.h
* @brief Uses analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_USES_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_USES_ANALYSIS_H

#include <map>
#include <set>

#include <llvm/IR/GlobalVariable.h>

namespace retdec {
namespace bin2llvmir {

/**
* @brief Analysis that provides support for getting information about uses of
*        LLVM IR values.
*
* This class contains two types of methods.
* -# Is need to run @c doUsesAnalyses(). It is need for method @c getUseInfo().
* -# Nothing to need run before. Other methods.
*/
class UsesAnalysis {
public:
	/**
	* @brief Structure to save info about use.
	*
	* Uses for global variables are these:
	* Left use because something is assigned to global variable:
	* @code
	* store ..., i32* @glob
	* @endcode
	* Right use because something is loaded from global variable:
	* @code
	* load i32, i32* @glob
	* @endcode
	*/
	struct UseInfo {
		/**
		* @brief Constructs a new @c UseInfo.
		*
		* @param[in] value Value of global variable for which is this use saved.
		* @param[in] isLUse If is a left use.
		*/
		explicit UseInfo(llvm::Value *value = nullptr, bool isLUse = false):
			isLUse(isLUse), value(value) {}

		/**
		* @brief Returns a new left @c UseInfo.
		*
		* @param[in] value Value of global variable for which is this use saved.
		*/
		static UseInfo createLeftUseInfo(llvm::Value *value) {
			return UseInfo(value, true);
		}

		/**
		* @brief Returns a new right @c UseInfo.
		*
		* @param[in] value Value of global variable for which is this use saved.
		*/
		static UseInfo createRightUseInfo(llvm::Value *value) {
			return UseInfo(value, false);
		}

		/// If is left use.
		bool isLUse;

		/// Value of global variable for which is this use saved.
		llvm::Value *value;
	};

public:
	UsesAnalysis();
	~UsesAnalysis();

	std::string getName() const { return "UsesAnalysis"; }

	void doUsesAnalysis(const std::set<llvm::GlobalVariable*> &globs);
	const UseInfo *getUseInfo(llvm::BasicBlock &bb, llvm::Instruction &inst);

	static bool hasValueUsesExcept(llvm::Value &value,
		const std::set<llvm::Instruction*> &instSet);
	static bool hasNoUse(llvm::GlobalVariable &glob);
	static bool hasUsesOnlyInOneFunc(llvm::GlobalVariable &glob);
	static bool hasSomeUseVolatileLoadOrStore(llvm::GlobalVariable &glob);

	void printBBsUses();
	void printBBUses(llvm::BasicBlock &bb);

private:
	/// Mapping of an instruction to @c UseInfo.
	using InstUseInfoMap = std::map<llvm::Instruction *, UseInfo>;

	/**
	* Class that contains uses info for basic block.
	*/
	class BBUses {
	public:
		BBUses();
		~BBUses();

		void addNewLUse(llvm::Instruction &lUse);
		void addNewRUse(llvm::Instruction &rUse);
		const UseInfo *getUseInfo(llvm::Instruction &inst);

		void printBBUses();

	private:
		/// Contains uses of global variables.
		InstUseInfoMap useInfoMap;
	};

	/// Mapping of a basic block to basic block uses.
	using BBBBUsesMap = std::map<llvm::BasicBlock *, BBUses *>;

private:
	BBUses &getIfExistsOrCreateNewBBInfo(llvm::BasicBlock &bb);
	void goThroughUses(llvm::GlobalVariable &glob);
	void addNewLUse(llvm::BasicBlock &bb, llvm::Instruction &lUse);
	void addNewRUse(llvm::BasicBlock &bb, llvm::Instruction &rUse);
	void clear();

private:
	/// Contains uses of global variables for basic blocks.
	BBBBUsesMap bbUseInfoMap;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

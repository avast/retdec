/**
* @file include/retdec/llvmir2hll/llvm/llvm_support.h
* @brief Supportive functions regarding LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVM_SUPPORT_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVM_SUPPORT_H

#include <cstdint>
#include <set>
#include <string>

namespace llvm {

class AllocaInst;
class BasicBlock;
class ConstantArray;
class GlobalVariable;
class Instruction;
class Module;
class Value;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

/**
* @brief Supportive functions regarding LLVM IR.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class LLVMSupport {
public:
	static std::size_t getNumberOfUniquePredecessors(llvm::BasicBlock *bb);
	static bool isPredecessorOf(llvm::BasicBlock *pred, llvm::BasicBlock *bb);
	static bool isInlineAsm(const llvm::Instruction *i);
	static bool isInlinableInst(const llvm::Instruction *i);
	static const llvm::AllocaInst *isDirectAlloca(const llvm::Value *v);
	static bool endsWithRetOrUnreach(llvm::BasicBlock *bb, bool indirect = true);
	static bool endWithSameUncondBranch(llvm::BasicBlock *bb1, llvm::BasicBlock *bb2);
	static const llvm::Module *getModuleFromValue(const llvm::Value *v);
	static std::string getBasicBlockLabelPrefix();
	static bool isBasicBlockLabel(const std::string &str);

public:
	// Disable both constructors, destructor, and assignment operator.
	// They are declared public to make diagnostics messages more precise.
	LLVMSupport() = delete;
	LLVMSupport(const LLVMSupport &) = delete;
	~LLVMSupport() = delete;
	LLVMSupport &operator=(const LLVMSupport &) = delete;

private:
	/// Set of basic blocks.
	using BasicBlockSet = std::set<llvm::BasicBlock *>;

private:

	static bool endsWithRetOrUnreachImpl(llvm::BasicBlock *bb, bool indirect);

private:
	/// Set of basic blocks used in endsWithRetOrUnreach().
	/// It is used to prevent endless recursion.
	static BasicBlockSet endsWithRetOrUnreachBBSet;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

/**
* @file src/llvmir2hll/llvm/llvm_support.cpp
* @brief Implementation of LLVMSupport.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <set>
#include <string>

#include <llvm/Analysis/Interval.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

using retdec::utils::hasItem;
using retdec::utils::hasOnlyHexadecimalDigits;
using retdec::utils::startsWith;

namespace retdec {
namespace llvmir2hll {

// Definition and initialization of static data members.
LLVMSupport::BasicBlockSet LLVMSupport::endsWithRetOrUnreachBBSet;

/**
* @brief Returns the number of unique predecessors of the given basic block.
*
* @par Preconditions
*  - @a bb is non-null
*/
std::size_t LLVMSupport::getNumberOfUniquePredecessors(llvm::BasicBlock *bb) {
	PRECONDITION_NON_NULL(bb);

	std::set<llvm::BasicBlock *> preds;
	for (auto i = llvm::pred_begin(bb), e = llvm::pred_end(bb); i != e; ++i) {
		preds.insert(*i);
	}
	return preds.size();
}

/**
* @brief Returns @c true if @a pred is a predecessor of @a bb, @c false
*        otherwise.
*
* @par Preconditions
*  - both @a pred and @a bb are non-null
*/
bool LLVMSupport::isPredecessorOf(llvm::BasicBlock *pred, llvm::BasicBlock *bb) {
	PRECONDITION_NON_NULL(pred);
	PRECONDITION_NON_NULL(bb);

	for (auto i = llvm::pred_begin(bb), e = llvm::pred_end(bb); i != e; ++i) {
		if (*i == pred) {
			return true;
		}
	}
	return false;
}

/**
* @brief Returns @c true if the given LLVM instruction @a i is a call to an
*        inline asm chunk, @c false otherwise.
*
* @par Preconditions
*  - @a i is non-null
*/
bool LLVMSupport::isInlineAsm(const llvm::Instruction *i) {
	PRECONDITION_NON_NULL(i);

	if (const llvm::CallInst *ci = llvm::dyn_cast<llvm::CallInst>(i)) {
		return llvm::isa<llvm::InlineAsm>(ci->getCalledValue());
	}
	return false;
}

/**
* @brief Returns @c true if the given LLVM instruction @a i is inlinable, @c
*        false otherwise.
*
* We attempt to inline instructions into their uses to reduce the generated
* "trees" as much as possible. To do this, we have to consistently decide what
* is acceptable to inline.
*
* @par Preconditions
*  - @a i is non-null
*/
bool LLVMSupport::isInlinableInst(const llvm::Instruction *i) {
	PRECONDITION_NON_NULL(i);

	// NOTE: Do NOT try to automatically inline:
	//
	//   - call instructions (it might mess up the order in which
	//     functions are called)
	//
	//   - load instructions; for example, consider the following piece of
	//     code, where inlining the load instruction causes the function to
	//     return a wrong value (var is a global variable):
	//
	//         %result = load i32* @var, align 4
	//         store i32 0, i32* @var, align 4
	//         ret i32 %result

	// Always inline GEP instructions (this fixes several problems with invalid
	// generated code for structure/array indexing; e.g. when the same index
	// computed by a GEP instruction is used more than once.
	if (llvm::isa<llvm::GetElementPtrInst>(i))
		return true;

	// Always inline cast instructions (this prevents emission of useless
	// temporary variables).
	if (llvm::isa<llvm::BitCastInst>(i))
		return true;

	// Always inline CMP instructions, even if they are shared by multiple
	// expressions.
	if (llvm::isa<llvm::CmpInst>(i))
		return true;

	// Do not inline select instructions because they cause the resulting
	// expressions to be rather huge.
	if (llvm::isa<llvm::SelectInst>(i))
		return false;

	// It has to be an expression, and it has to be used exactly once. If it is
	// dead, we generate it inline where it would go.
	if (i->getType() == llvm::Type::getVoidTy(i->getContext()) || !i->hasOneUse() ||
			llvm::isa<llvm::TerminatorInst>(i) || llvm::isa<llvm::CallInst>(i) ||
			llvm::isa<llvm::PHINode>(i) || llvm::isa<llvm::LoadInst>(i) ||
			llvm::isa<llvm::VAArgInst>(i) || llvm::isa<llvm::InsertElementInst>(i) ||
			llvm::isa<llvm::InsertValueInst>(i)) {
		// Don't inline a load across a store or other bad things!
		return false;
	}

	// It must not be used in inline asm, extractelement, or shufflevector.
	if (i->hasOneUse()) {
		const llvm::Instruction &user = llvm::cast<llvm::Instruction>(*i->user_back());
		if (isInlineAsm(&user) || llvm::isa<llvm::ExtractElementInst>(user) ||
				llvm::isa<llvm::ShuffleVectorInst>(user)) {
			return false;
		}
	}

	// Only inline instruction it if its use is in the same basic block as the
	// instruction.
	return i->getParent() == llvm::cast<llvm::Instruction>(i->user_back())->getParent();
}

/**
* @brief If @a v is a direct alloca, it returns @a v converted into an alloca
*        instruction. Otherwise, the null pointer is returned.
*
* Define fixed sized allocas in the entry block as direct variables which are
* accessed with the & operator.
*
* @par Preconditions
*  - @a v is non-null
*/
const llvm::AllocaInst *LLVMSupport::isDirectAlloca(const llvm::Value *v) {
	PRECONDITION_NON_NULL(v);

	const llvm::AllocaInst *ai = llvm::dyn_cast<llvm::AllocaInst>(v);
	if (!ai || ai->isArrayAllocation() ||
			ai->getParent() != &ai->getParent()->getParent()->getEntryBlock()) {
		return nullptr;
	}
	return ai;
}

/**
* @brief Returns @c true if @a bb (indirectly) ends with a return or
*        an unreachable instruction, @c false otherwise.
*
* @param[in] bb Basic block to be examined.
* @param[in] indirect If @c true and @a bb ends with an unconditional branch
*                     @c b, this function is called recursively on the target
*                     of @c b.
*
* This function is not reentrant.
*
* @par Preconditions
*  - @a bb is non-null
*/
bool LLVMSupport::endsWithRetOrUnreach(llvm::BasicBlock *bb, bool indirect){
	PRECONDITION_NON_NULL(bb);

	endsWithRetOrUnreachBBSet.clear();
	return endsWithRetOrUnreachImpl(bb, indirect);
}

/**
* @brief Implementation of endsWithRetOrUnreach().
*
* It doesn't clear endsWithRetOrUnreachBBSet on return. This function may
* recursively calls itself. This function is not reentrant.
*
* @par Preconditions
*  - @a bb is non-null
*  - endsWithRetOrUnreachBBSet has been cleared
*/
bool LLVMSupport::endsWithRetOrUnreachImpl(llvm::BasicBlock *bb, bool indirect){
	PRECONDITION_NON_NULL(bb);

	// To prevent endless recursion, we store every accessed basic block to
	// endsWithRetOrUnreachBBSet. However, notice that this makes the function
	// not reentrant.
	if (hasItem(endsWithRetOrUnreachBBSet, bb)) {
		// We have already visited bb, so end with a failure.
		return false;
	}
	endsWithRetOrUnreachBBSet.insert(bb);

	llvm::TerminatorInst *t = bb->getTerminator();
	if (llvm::isa<llvm::ReturnInst>(t) || llvm::isa<llvm::UnreachableInst>(t)) {
		return true;
	}

	if (indirect) {
		llvm::BranchInst *bi = llvm::dyn_cast<llvm::BranchInst>(t);
		if (bi && !bi->isConditional()) {
			return endsWithRetOrUnreachImpl(bi->getSuccessor(0), true);
		}
	}

	return false;
}

/**
* @brief Returns @c true if both @a bb1 and @a bb2 end with an unconditional
*        branch to the same basic block, @c false otherwise.
*/
bool LLVMSupport::endWithSameUncondBranch(llvm::BasicBlock *bb1,
		llvm::BasicBlock *bb2) {
	llvm::BranchInst *bi1 = llvm::dyn_cast<llvm::BranchInst>(bb1->getTerminator());
	llvm::BranchInst *bi2 = llvm::dyn_cast<llvm::BranchInst>(bb2->getTerminator());
	if (!bi1 || !bi2 || bi1->isConditional() || bi2->isConditional()) {
		return false;
	}
	return bi1->getSuccessor(0) == bi2->getSuccessor(0);
}

/**
* @brief Returns the LLVM module corresponding to the given value @a v.
*
* If the module cannot be obtained, this function returns the null pointer.
*
* @par Preconditions
*  - @a v is non-null
*/
const llvm::Module *LLVMSupport::getModuleFromValue(const llvm::Value *v) {
	PRECONDITION_NON_NULL(v);

	// The implementation is based on llvm::AsmWriter::getModuleFromVal(const
	// Value *V).

	if (const llvm::Argument *a = llvm::dyn_cast<llvm::Argument>(v))
		return a->getParent() ? a->getParent()->getParent() : nullptr;

	if (const llvm::BasicBlock *bb = llvm::dyn_cast<llvm::BasicBlock>(v))
		return bb->getParent() ? bb->getParent()->getParent() : nullptr;

	if (const llvm::Instruction *i = llvm::dyn_cast<llvm::Instruction>(v)) {
		const llvm::Function *m = i->getParent() ? i->getParent()->getParent() : nullptr;
		return m ? m->getParent() : nullptr;
	}

	if (const llvm::GlobalValue *gv = llvm::dyn_cast<llvm::GlobalValue>(v))
		return gv->getParent();

	return nullptr;
}

/**
* @brief Returns the used prefix of labels in LLVM IR.
*/
std::string LLVMSupport::getBasicBlockLabelPrefix() {
	return "dec_label_pc_";
}

/**
* @brief Returns @c true if @a str has the format of a basic block's label in
*        LLVM IR, @c false otherwise.
*/
bool LLVMSupport::isBasicBlockLabel(const std::string &str) {
	// The string should be of the form "expectedPrefixY", where Y is a
	// hexadecimal number.
	std::string expectedPrefix(LLVMSupport::getBasicBlockLabelPrefix());
	return startsWith(str, expectedPrefix) && str.size() > expectedPrefix.size() &&
		hasOnlyHexadecimalDigits(str.substr(expectedPrefix.size()));
}

} // namespace llvmir2hll
} // namespace retdec

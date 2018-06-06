/**
 * @file src/capstone2llvmir/llvmir_utils.h
 * @brief LLVM IR utilities.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 *
 * LLVM IR utilities (routines) that:
 * - Are unrelated to the translation itself.
 * - Do not use any data from translation classes.
 */

#ifndef CAPSTONE2LLVMIR_LLVMIR_UTILS_H
#define CAPSTONE2LLVMIR_LLVMIR_UTILS_H

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

namespace retdec {
namespace capstone2llvmir {

/**
 * @return Negation of value @p val.
 */
llvm::Value* generateValueNegate(llvm::IRBuilder<>& irb, llvm::Value* val);

llvm::IntegerType* getIntegerTypeFromByteSize(llvm::Module* module, unsigned sz);

llvm::Type* getFloatTypeFromByteSize(llvm::Module* module, unsigned sz);

/**
 * Generate if-then statement at the current insert point of @p irb builder.
 * @code{.cpp}
	if (cond) {
	  // body
	}
	// after
 * @endcode
 * @param cond Value used as condition in @c if() statement.
 * @param irb  Reference to IR builder. After if-then is generated,
 *             irb's insert point is set to first instruction after the
 *             statement.
 * @return IR builder whose insert point is set to if-then body BB's
 *         terminator instruction. Use this builder to fill the body.
 */
llvm::IRBuilder<> generateIfThen(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb);

/**
 * Same as @c generateIfThen() but if @p cond is @c true, body is skipped:
 * @code{.cpp}
	if (!cond) {
	  // body
	}
	// after
 * @endcode
 */
llvm::IRBuilder<> generateIfNotThen(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb);

/**
 * Generate if-then-else statement at the current insert point of @p irb builder.
 * @code{.cpp}
	if (cond) {
	  // bodyIf
	} else {
	  // bodyElse
	}
	// after
 * @endcode
 * @param cond Value used as condition in @c if() statement.
 * @param irb  Reference to IR builder. After if-then-else is
 *             generated, irb's insert point is set to first instruction after
 *             the statement.
 * @return Pair of IR builders whose insert points are set to if-then-else's
 *         bodyIf (first) and bodyElse (second) terminator instructions.
 *         Use these builders to fill the bodies.
 */
std::pair<llvm::IRBuilder<>, llvm::IRBuilder<>> generateIfThenElse(
		llvm::Value* cond,
		llvm::IRBuilder<>& irb);

/**
 * Generate while statement at the current insert point of @p irb builder.
 * @code{.cpp}
	// before
	while (cond) {
	  // body
	}
	// after
 * @endcode
 * @param branch Reference to a branch instruction pointer that will be filled
 *               with a while's conditional branch, whose condition is set to
 *               @c true (infinite loop). Use before IR builder to generate
 *               condition and @c llvm::BranchInst::setCondition() to set it to
 *               whis branch.
 * @param irb    Reference to IR builder. After while is generated, irb's insert
 *               point is set to first instruction after the statement.
 * @return Pair of IR builders whose insert points are set to before BB's and
 *         while body BB's terminator instructions.
 *         Use these builders to fill while's condition and body.
 */
std::pair<llvm::IRBuilder<>, llvm::IRBuilder<>> generateWhile(
		llvm::BranchInst*& branch,
		llvm::IRBuilder<>& irb);

} // namespace capstone2llvmir
} // namespace retdec

#endif

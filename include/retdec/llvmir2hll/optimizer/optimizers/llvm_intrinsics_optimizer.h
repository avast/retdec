/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/llvm_intrinsics_optimizer.h
* @brief Optimizes calls to LLVM intrinsic functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_LLVM_INTRINSICS_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_LLVM_INTRINSICS_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes calls to LLVM intrinsic functions.
*
* This optimizer does the following optimizations:
*
*  (1) Removes all standalone calls to @c llvm.ctpop.* functions. If there are
*      then no @c llvm.ctpop.* calls after the conversion, the declaration of
*      this function is removed from the module.
*
* Some conversions of LLVM intrinsic functions are done in
* LLVMIntrinsicsConverter. Such conversions are not part of this optimizer.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class LLVMIntrinsicsOptimizer final: public FuncOptimizer {
public:
	LLVMIntrinsicsOptimizer(ShPtr<Module> module);

	virtual ~LLVMIntrinsicsOptimizer() override;

	virtual std::string getId() const override { return "LLVMIntrinsics"; }

private:
	virtual void doOptimization() override;

	ShPtr<Function> getCalledFunc(ShPtr<CallExpr> expr) const;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallExpr> expr) override;
	virtual void visit(ShPtr<CallStmt> stmt) override;
	/// @}

private:
	/// Set of functions whose declarations should be kept.
	FuncSet doNotRemoveFuncs;

	// Set of calls that were removed.
	FuncSet removedCalls;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

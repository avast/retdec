/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/remove_all_casts_optimizer.h
* @brief Removes all casts from a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_REMOVE_ALL_CASTS_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_REMOVE_ALL_CASTS_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class CastExpr;

/**
* @brief Removes all casts from a module.
*
* This optimizer can be used if the target language doesn't support types.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class RemoveAllCastsOptimizer final: public FuncOptimizer {
public:
	RemoveAllCastsOptimizer(ShPtr<Module> module);

	virtual ~RemoveAllCastsOptimizer() override;

	virtual std::string getId() const override { return "RemoveAllCasts"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<BitCastExpr> expr) override;
	virtual void visit(ShPtr<ExtCastExpr> expr) override;
	virtual void visit(ShPtr<TruncCastExpr> expr) override;
	virtual void visit(ShPtr<FPToIntCastExpr> expr) override;
	virtual void visit(ShPtr<IntToFPCastExpr> expr) override;
	virtual void visit(ShPtr<IntToPtrCastExpr> expr) override;
	virtual void visit(ShPtr<PtrToIntCastExpr> expr) override;
	/// @}

	void removeCast(ShPtr<CastExpr> castExpr);
};

} // namespace llvmir2hll
} // namespace retdec

#endif

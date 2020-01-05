/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr_optimizer.h
* @brief Optimizer that optimizes expressions to a simpler form.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ArithmExprEvaluator;

/**
* @brief Optimizer that optimizes expressions to a simpler form.
*
* The optimizer utilizes many sub-optimizers. They are in the @c
* simplify_arithm_expr sub-directory.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class SimplifyArithmExprOptimizer final: public Optimizer {
public:
	SimplifyArithmExprOptimizer(Module* module,
		ArithmExprEvaluator* arithmExprEvaluator);

	virtual std::string getId() const override { return "SimplifyArithmExpr"; }

private:
	virtual void doOptimization() override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
		virtual void visit(AddOpExpr* expr) override;
		virtual void visit(SubOpExpr* expr) override;
		virtual void visit(MulOpExpr* expr) override;
		virtual void visit(DivOpExpr* expr) override;
		virtual void visit(ModOpExpr* expr) override;
		virtual void visit(BitAndOpExpr* expr) override;
		virtual void visit(BitOrOpExpr* expr) override;
		virtual void visit(BitXorOpExpr* expr) override;
		virtual void visit(LtOpExpr* expr) override;
		virtual void visit(LtEqOpExpr* expr) override;
		virtual void visit(GtOpExpr* expr) override;
		virtual void visit(GtEqOpExpr* expr) override;
		virtual void visit(EqOpExpr* expr) override;
		virtual void visit(NeqOpExpr* expr) override;
		virtual void visit(NotOpExpr* expr) override;
		virtual void visit(OrOpExpr* expr) override;
		virtual void visit(TernaryOpExpr* expr) override;
		/// @}

	void createSubOptimizers(ArithmExprEvaluator* arithmExprEvaluator);
	void tryOptimizeInSubOptimizations(Expression* expr);

private:
	/// Vector of sub-optimizations.
	using SubOptimVec = std::vector<SubOptimizer*>;

private:
	/// Vector of sub-optimizations.
	SubOptimVec subOptims;

	/// @c true if the module was optimized in a sub/optimization, @c false
	/// otherwise.
	bool codeChanged;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

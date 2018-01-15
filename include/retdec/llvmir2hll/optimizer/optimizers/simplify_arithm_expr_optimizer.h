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
	SimplifyArithmExprOptimizer(ShPtr<Module> module,
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator);

	virtual ~SimplifyArithmExprOptimizer() override;

	virtual std::string getId() const override { return "SimplifyArithmExpr"; }

private:
	virtual void doOptimization() override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
		virtual void visit(ShPtr<AddOpExpr> expr) override;
		virtual void visit(ShPtr<SubOpExpr> expr) override;
		virtual void visit(ShPtr<MulOpExpr> expr) override;
		virtual void visit(ShPtr<DivOpExpr> expr) override;
		virtual void visit(ShPtr<ModOpExpr> expr) override;
		virtual void visit(ShPtr<BitAndOpExpr> expr) override;
		virtual void visit(ShPtr<BitOrOpExpr> expr) override;
		virtual void visit(ShPtr<BitXorOpExpr> expr) override;
		virtual void visit(ShPtr<LtOpExpr> expr) override;
		virtual void visit(ShPtr<LtEqOpExpr> expr) override;
		virtual void visit(ShPtr<GtOpExpr> expr) override;
		virtual void visit(ShPtr<GtEqOpExpr> expr) override;
		virtual void visit(ShPtr<EqOpExpr> expr) override;
		virtual void visit(ShPtr<NeqOpExpr> expr) override;
		virtual void visit(ShPtr<NotOpExpr> expr) override;
		virtual void visit(ShPtr<OrOpExpr> expr) override;
		virtual void visit(ShPtr<TernaryOpExpr> expr) override;
		/// @}

	void createSubOptimizers(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	void tryOptimizeInSubOptimizations(ShPtr<Expression> expr);

private:
	/// Vector of sub-optimizations.
	using SubOptimVec = std::vector<ShPtr<SubOptimizer>>;

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

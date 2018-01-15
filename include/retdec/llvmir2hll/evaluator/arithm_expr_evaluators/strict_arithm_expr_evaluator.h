/**
* @file include/retdec/llvmir2hll/evaluator/arithm_expr_evaluators/strict_arithm_expr_evaluator.h
* @brief Evaluates expressions with strict conditions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_EVALUATOR_ARITHM_EXPR_EVALUATORS_STRICT_ARITHM_EXPR_EVALUATOR_H
#define RETDEC_LLVMIR2HLL_EVALUATOR_ARITHM_EXPR_EVALUATORS_STRICT_ARITHM_EXPR_EVALUATOR_H

#include <string>

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Evaluates expressions with strict conditions.
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-evaluator which should not be subclassed.
*/
class StrictArithmExprEvaluator final: public ArithmExprEvaluator {
public:
	virtual ~StrictArithmExprEvaluator() override;

	static ShPtr<ArithmExprEvaluator> create();

	virtual std::string getId() const override;

private:
	StrictArithmExprEvaluator();

	// Resolve types.
	virtual void resolveTypesBinaryOp(ConstPair &constPair) override;

	// Resolve operators specifications.
	virtual void resolveOpSpecifications(ShPtr<DivOpExpr> expr,
		ConstPair &constPair) override;
	virtual void resolveOpSpecifications(ShPtr<ModOpExpr> expr,
		ConstPair &constPair) override;
	virtual void resolveOpSpecifications(ShPtr<NegOpExpr> expr,
		ShPtr<Constant> &constant) override;

	// Resolve casts.
	virtual void resolveCast(ShPtr<BitCastExpr> expr,
		ShPtr<Constant> &constant) override;
	virtual void resolveCast(ShPtr<ExtCastExpr> expr,
		ShPtr<Constant> &constant) override;
	virtual void resolveCast(ShPtr<FPToIntCastExpr> expr, ShPtr<Constant>
		&constant) override;
	virtual void resolveCast(ShPtr<IntToFPCastExpr> expr, ShPtr<Constant>
		&constant) override;
	virtual void resolveCast(ShPtr<TruncCastExpr> expr,
		ShPtr<Constant> &constant) override;

	// Resolve overflow.
	virtual void resolveOverflowForAPInt(bool overflow) override;
	virtual void resolveOverflowForAPFloat(
		llvm::APFloat::opStatus opStatus) override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

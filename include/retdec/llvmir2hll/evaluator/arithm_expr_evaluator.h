/**
* @file include/retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h
* @brief A base class for all evaluators.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_EVALUATOR_ARITHM_EXPR_EVALUATOR_H
#define RETDEC_LLVMIR2HLL_EVALUATOR_ARITHM_EXPR_EVALUATOR_H

#include <stack>
#include <string>

#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class for all evaluators.
*
* A concrete evaluator should
*  - implement the virtual functions where you wan't to change behaviour of
*    sub-evaluator. Default implementation of this virtual function do nothing.
*  - define a static <tt>ShPtr<ArithmExprEvaluator> create()</tt> function
*  - register itself at ArithmExprEvaluatorFactory by passing the static @c
*    create function and the concrete evaluator's ID
*/
class ArithmExprEvaluator: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	/// Pair of @c llvm::APSInt.
	using APSIntPair = std::pair<llvm::APSInt, llvm::APSInt>;

	/// Pair of @c llvm::APFloat.
	using APFloatPair = std::pair<llvm::APFloat, llvm::APFloat>;

	/// Pair of integer constants.
	using ConstIntPair = std::pair<ShPtr<ConstInt>, ShPtr<ConstInt>>;

	/// Pair of float constants.
	using ConstFloatPair = std::pair<ShPtr<ConstFloat>, ShPtr<ConstFloat>>;

	/// Pair of bool constants.
	using ConstBoolPair = std::pair<ShPtr<ConstBool>, ShPtr<ConstBool>>;

	/// Pair of constants.
	using ConstPair = std::pair<ShPtr<Constant>, ShPtr<Constant>>;

	/// Stack of constats.
	using ConstStack = std::stack<ShPtr<Constant>>;

	/// Mapping of variables to constants.
	using VarConstMap = std::map<ShPtr<Variable>, ShPtr<Constant>>;

public:
	virtual ~ArithmExprEvaluator() override;

	/**
	* @brief Returns the ID of the optimizer.
	*/
	virtual std::string getId() const = 0;
	virtual Maybe<bool> toBool(ShPtr<Expression> expr, VarConstMap
		varValues = VarConstMap());

	ShPtr<Constant> evaluate(ShPtr<Expression> expr);
	ShPtr<Constant> evaluate(ShPtr<Expression> expr, const VarConstMap
		&varValues);

	template<typename ConstType>
	static Maybe<std::pair<ShPtr<ConstType>, ShPtr<ConstType>>> castConstPair(
		const ConstPair &constPair);

protected:
	ArithmExprEvaluator();

	static APSIntPair getAPSIntsFromConstants(const Maybe<ConstIntPair>
		&constIntPair);
	static APFloatPair getAPFloatsFromConstants(const Maybe<ConstFloatPair>
		&ConstFloatPair);
	static bool isConstantZero(ShPtr<Constant> constant);

protected:
	/// Signalizes if evaluation can go on.
	bool canBeEvaluated;

private:
	using LLVMAPIntAPIntBoolOp = llvm::APInt (llvm::APInt::*)(
		const llvm::APInt &, bool &) const;
	using LLVMBoolAPIntOp = bool (llvm::APInt::*)(
		const llvm::APInt &) const;
	using LLVMAPIntAPIntOp = llvm::APInt (llvm::APInt::*)(
		const llvm::APInt &) const;
	using LLVMAPFloatOp = llvm::APFloat::opStatus (llvm::APFloat::*)(
		const llvm::APFloat &, llvm::APFloat::roundingMode);
	// Since LLVM 3.9, APFloat::mode() and APFloat::remainder() do not accept
	// roundingMode, so we have to create another alias for operations without
	// the rounding mode.
	using LLVMAPFloatOpNoRounding = llvm::APFloat::opStatus (llvm::APFloat::*)(
		const llvm::APFloat &);

private:
	using OrderedAllVisitor::visit;
	/// @name Visitor Interface
	/// @{
	// Expressions
	virtual void visit(ShPtr<AddOpExpr> expr) override;
	virtual void visit(ShPtr<AddressOpExpr> expr) override;
	virtual void visit(ShPtr<AndOpExpr> expr) override;
	virtual void visit(ShPtr<ArrayIndexOpExpr> expr) override;
	virtual void visit(ShPtr<BitAndOpExpr> expr) override;
	virtual void visit(ShPtr<BitOrOpExpr> expr) override;
	virtual void visit(ShPtr<BitShlOpExpr> expr) override;
	virtual void visit(ShPtr<BitShrOpExpr> expr) override;
	virtual void visit(ShPtr<BitXorOpExpr> expr) override;
	virtual void visit(ShPtr<CallExpr> expr) override;
	virtual void visit(ShPtr<DerefOpExpr> expr) override;
	virtual void visit(ShPtr<DivOpExpr> expr) override;
	virtual void visit(ShPtr<EqOpExpr> expr) override;
	virtual void visit(ShPtr<GtEqOpExpr> expr) override;
	virtual void visit(ShPtr<GtOpExpr> expr) override;
	virtual void visit(ShPtr<LtEqOpExpr> expr) override;
	virtual void visit(ShPtr<LtOpExpr> expr) override;
	virtual void visit(ShPtr<ModOpExpr> expr) override;
	virtual void visit(ShPtr<MulOpExpr> expr) override;
	virtual void visit(ShPtr<NegOpExpr> expr) override;
	virtual void visit(ShPtr<NeqOpExpr> expr) override;
	virtual void visit(ShPtr<NotOpExpr> expr) override;
	virtual void visit(ShPtr<OrOpExpr> expr) override;
	virtual void visit(ShPtr<StructIndexOpExpr> expr) override;
	virtual void visit(ShPtr<SubOpExpr> expr) override;
	virtual void visit(ShPtr<TernaryOpExpr> expr) override;
	virtual void visit(ShPtr<Variable> var) override;
	// Casts
	virtual void visit(ShPtr<BitCastExpr> expr) override;
	virtual void visit(ShPtr<ExtCastExpr> expr) override;
	virtual void visit(ShPtr<FPToIntCastExpr> expr) override;
	virtual void visit(ShPtr<IntToFPCastExpr> expr) override;
	virtual void visit(ShPtr<IntToPtrCastExpr> expr) override;
	virtual void visit(ShPtr<PtrToIntCastExpr> expr) override;
	virtual void visit(ShPtr<TruncCastExpr> expr) override;
	// Constants
	virtual void visit(ShPtr<ConstArray> constant) override;
	virtual void visit(ShPtr<ConstBool> constant) override;
	virtual void visit(ShPtr<ConstFloat> constant) override;
	virtual void visit(ShPtr<ConstInt> constant) override;
	virtual void visit(ShPtr<ConstNullPointer> constant) override;
	virtual void visit(ShPtr<ConstString> constant) override;
	virtual void visit(ShPtr<ConstStruct> constant) override;
	virtual void visit(ShPtr<ConstSymbol> constant) override;
	/// @}

	// Resolve types.
	virtual void resolveTypesUnaryOp(ShPtr<Constant> &operand);
	virtual void resolveTypesBinaryOp(ConstPair &constPair);

	// Resolve operators specifications.
	virtual void resolveOpSpecifications(ShPtr<AddOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<AndOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<BitAndOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<BitOrOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<BitShlOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<BitShrOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<BitXorOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<DivOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<EqOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<GtEqOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<GtOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<LtEqOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<LtOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<ModOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<MulOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<NegOpExpr> expr,
		ShPtr<Constant> &constant);
	virtual void resolveOpSpecifications(ShPtr<NeqOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<NotOpExpr> expr,
		ShPtr<Constant> &constant);
	virtual void resolveOpSpecifications(ShPtr<OrOpExpr> expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ShPtr<SubOpExpr> expr,
		ConstPair &constPair);

	// Resolve casts.
	virtual void resolveCast(ShPtr<BitCastExpr> expr, ShPtr<Constant> &constant);
	virtual void resolveCast(ShPtr<ExtCastExpr> expr, ShPtr<Constant> &constant);
	virtual void resolveCast(ShPtr<FPToIntCastExpr> expr,
		ShPtr<Constant> &constant);
	virtual void resolveCast(ShPtr<IntToFPCastExpr> expr,
		ShPtr<Constant> &constant);
	virtual void resolveCast(ShPtr<TruncCastExpr> expr,
		ShPtr<Constant> &constant);

	// Resolve overflow.
	virtual void resolveOverflowForAPInt(bool overflow);
	virtual void resolveOverflowForAPFloat(llvm::APFloat::opStatus opStatus);

	// Perform functions.
	ShPtr<ConstFloat> performOperationOverApFloat(const Maybe<ConstFloatPair>
		&constFloatPair, LLVMAPFloatOp op, llvm::APFloat::opStatus &status);
	ShPtr<ConstFloat> performOperationOverApFloat(const Maybe<ConstFloatPair>
		&constFloatPair, LLVMAPFloatOpNoRounding op, llvm::APFloat::opStatus &status);
	llvm::APFloat::cmpResult performOperationOverApFloat(const Maybe<
		ConstFloatPair> &constFloatPair);
	ShPtr<ConstInt> performOperationOverApInt(const Maybe<ConstIntPair>
		&constIntPair, LLVMAPIntAPIntBoolOp op, bool &overflow);
	ShPtr<ConstInt> performOperationOverApInt(const Maybe<ConstIntPair>
		&constIntPair, LLVMAPIntAPIntOp op);
	ShPtr<ConstBool> performOperationOverApInt(const Maybe<ConstIntPair>
		&constIntPair, LLVMBoolAPIntOp op);

	// Other functions.
	ConstPair getOperandsForBinaryOpAndResolveTypes();
	ShPtr<Constant> getOperandForUnaryOpAndResolveTypes();
	void resolveOverflows(bool overflow, llvm::APFloat::opStatus opStatus);

private:
	/// Map of constants that substitute variables in evaluation.
	const VarConstMap *varValues;

	/// Stack of results during the evaluation.
	ConstStack stackOfResults;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

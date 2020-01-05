/**
* @file include/retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h
* @brief A base class for all evaluators.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_EVALUATOR_ARITHM_EXPR_EVALUATOR_H
#define RETDEC_LLVMIR2HLL_EVALUATOR_ARITHM_EXPR_EVALUATOR_H

#include <optional>
#include <stack>
#include <string>

#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/constant.h"
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
*  - define a static <tt>ArithmExprEvaluator* create()</tt> function
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
	using ConstIntPair = std::pair<ConstInt*, ConstInt*>;

	/// Pair of float constants.
	using ConstFloatPair = std::pair<ConstFloat*, ConstFloat*>;

	/// Pair of bool constants.
	using ConstBoolPair = std::pair<ConstBool*, ConstBool*>;

	/// Pair of constants.
	using ConstPair = std::pair<Constant*, Constant*>;

	/// Stack of constats.
	using ConstStack = std::stack<Constant*>;

	/// Mapping of variables to constants.
	using VarConstMap = std::map<Variable*, Constant*>;

public:
	/**
	* @brief Returns the ID of the optimizer.
	*/
	virtual std::string getId() const = 0;
	virtual std::optional<bool> toBool(Expression* expr, VarConstMap
		varValues = VarConstMap());

	Constant* evaluate(Expression* expr);
	Constant* evaluate(Expression* expr, const VarConstMap
		&varValues);

	template<typename ConstType>
	static std::optional<std::pair<ConstType*, ConstType*>> castConstPair(
		const ConstPair &constPair)
{
	ConstType* firstConst(cast<ConstType>(constPair.first));
	ConstType* secConst(cast<ConstType>(constPair.second));
	if (!firstConst || !secConst) {
		return std::nullopt;
	} else {
		return std::make_pair(firstConst, secConst);
	}
}

protected:
	ArithmExprEvaluator() = default;

	static APSIntPair getAPSIntsFromConstants(const std::optional<ConstIntPair>
		&constIntPair);
	static APFloatPair getAPFloatsFromConstants(const std::optional<ConstFloatPair>
		&ConstFloatPair);
	static bool isConstantZero(Constant* constant);

protected:
	/// Signalizes if evaluation can go on.
	bool canBeEvaluated = true;

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
	virtual void visit(AddOpExpr* expr) override;
	virtual void visit(AddressOpExpr* expr) override;
	virtual void visit(AndOpExpr* expr) override;
	virtual void visit(ArrayIndexOpExpr* expr) override;
	virtual void visit(BitAndOpExpr* expr) override;
	virtual void visit(BitOrOpExpr* expr) override;
	virtual void visit(BitShlOpExpr* expr) override;
	virtual void visit(BitShrOpExpr* expr) override;
	virtual void visit(BitXorOpExpr* expr) override;
	virtual void visit(CallExpr* expr) override;
	virtual void visit(DerefOpExpr* expr) override;
	virtual void visit(DivOpExpr* expr) override;
	virtual void visit(EqOpExpr* expr) override;
	virtual void visit(GtEqOpExpr* expr) override;
	virtual void visit(GtOpExpr* expr) override;
	virtual void visit(LtEqOpExpr* expr) override;
	virtual void visit(LtOpExpr* expr) override;
	virtual void visit(ModOpExpr* expr) override;
	virtual void visit(MulOpExpr* expr) override;
	virtual void visit(NegOpExpr* expr) override;
	virtual void visit(NeqOpExpr* expr) override;
	virtual void visit(NotOpExpr* expr) override;
	virtual void visit(OrOpExpr* expr) override;
	virtual void visit(StructIndexOpExpr* expr) override;
	virtual void visit(SubOpExpr* expr) override;
	virtual void visit(TernaryOpExpr* expr) override;
	virtual void visit(Variable* var) override;
	// Casts
	virtual void visit(BitCastExpr* expr) override;
	virtual void visit(ExtCastExpr* expr) override;
	virtual void visit(FPToIntCastExpr* expr) override;
	virtual void visit(IntToFPCastExpr* expr) override;
	virtual void visit(IntToPtrCastExpr* expr) override;
	virtual void visit(PtrToIntCastExpr* expr) override;
	virtual void visit(TruncCastExpr* expr) override;
	// Constants
	virtual void visit(ConstArray* constant) override;
	virtual void visit(ConstBool* constant) override;
	virtual void visit(ConstFloat* constant) override;
	virtual void visit(ConstInt* constant) override;
	virtual void visit(ConstNullPointer* constant) override;
	virtual void visit(ConstString* constant) override;
	virtual void visit(ConstStruct* constant) override;
	virtual void visit(ConstSymbol* constant) override;
	/// @}

	// Resolve types.
	virtual void resolveTypesUnaryOp(Constant* &operand);
	virtual void resolveTypesBinaryOp(ConstPair &constPair);

	// Resolve operators specifications.
	virtual void resolveOpSpecifications(AddOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(AndOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(BitAndOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(BitOrOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(BitShlOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(BitShrOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(BitXorOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(DivOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(EqOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(GtEqOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(GtOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(LtEqOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(LtOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(ModOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(MulOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(NegOpExpr* expr,
		Constant* &constant);
	virtual void resolveOpSpecifications(NeqOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(NotOpExpr* expr,
		Constant* &constant);
	virtual void resolveOpSpecifications(OrOpExpr* expr,
		ConstPair &constPair);
	virtual void resolveOpSpecifications(SubOpExpr* expr,
		ConstPair &constPair);

	// Resolve casts.
	virtual void resolveCast(BitCastExpr* expr, Constant* &constant);
	virtual void resolveCast(ExtCastExpr* expr, Constant* &constant);
	virtual void resolveCast(FPToIntCastExpr* expr,
		Constant* &constant);
	virtual void resolveCast(IntToFPCastExpr* expr,
		Constant* &constant);
	virtual void resolveCast(TruncCastExpr* expr,
		Constant* &constant);

	// Resolve overflow.
	virtual void resolveOverflowForAPInt(bool overflow);
	virtual void resolveOverflowForAPFloat(llvm::APFloat::opStatus opStatus);

	// Perform functions.
	ConstFloat* performOperationOverApFloat(const std::optional<ConstFloatPair>
		&constFloatPair, LLVMAPFloatOp op, llvm::APFloat::opStatus &status);
	ConstFloat* performOperationOverApFloat(const std::optional<ConstFloatPair>
		&constFloatPair, LLVMAPFloatOpNoRounding op, llvm::APFloat::opStatus &status);
	llvm::APFloat::cmpResult performOperationOverApFloat(const std::optional<
		ConstFloatPair> &constFloatPair);
	ConstInt* performOperationOverApInt(const std::optional<ConstIntPair>
		&constIntPair, LLVMAPIntAPIntBoolOp op, bool &overflow);
	ConstInt* performOperationOverApInt(const std::optional<ConstIntPair>
		&constIntPair, LLVMAPIntAPIntOp op);
	ConstBool* performOperationOverApInt(const std::optional<ConstIntPair>
		&constIntPair, LLVMBoolAPIntOp op);

	// Other functions.
	ConstPair getOperandsForBinaryOpAndResolveTypes();
	Constant* getOperandForUnaryOpAndResolveTypes();
	void resolveOverflows(bool overflow, llvm::APFloat::opStatus opStatus);

private:
	/// Map of constants that substitute variables in evaluation.
	const VarConstMap *varValues = nullptr;

	/// Stack of results during the evaluation.
	ConstStack stackOfResults;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

/**
* @file include/retdec/llvmir2hll/hll/compound_op_manager.h
* @brief A base class for compound operator managers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_COMPOUND_OP_MANAGER_H
#define RETDEC_LLVMIR2HLL_HLL_COMPOUND_OP_MANAGER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class BinaryOpExpr;

/**
* @brief A base class for compound operator managers.
*
* Every compound operator manager should subclass this class and override
* private methods @c optimizeToCompoundOp().
*
* For how to use this class @see tryOptimizeToCompoundOp
*
* Instances of this class have reference object semantics.
*/
class CompoundOpManager: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	/**
	* @brief Stores the resulting compound operator.
	*/
	class CompoundOp {
	public:
		CompoundOp(std::string op);
		CompoundOp(std::string op, Expression* operand);

		const std::string &getOperator() const;
		Expression* getOperand() const;
		bool isUnaryOperator() const;
		bool isBinaryOperator() const;

	private:
		/// The resulting operator.
		std::string op;

		/// The right-hand side operand of a binary operator.
		Expression* operand = nullptr;
	};

public:
	CompoundOpManager();

	/**
	* @brief Returns the ID of the manager.
	*/
	virtual std::string getId() const = 0;

	CompoundOp tryOptimizeToCompoundOp(AssignStmt* stmt);
	CompoundOp tryOptimizeToCompoundOp(AssignOpExpr* expr);
	CompoundOp tryOptimizeToCompoundOp(Expression* lhs,
		Expression* rhs);

protected:
	void createResultingUnaryCompoundOp(const std::string &op);
	void createResultingBinaryCompoundOp(const std::string &op,
		Expression* operand);

private:
	/// @name OrderedAllVisitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(AddOpExpr* expr) override;
	virtual void visit(SubOpExpr* expr) override;
	virtual void visit(MulOpExpr* expr) override;
	virtual void visit(ModOpExpr* expr) override;
	virtual void visit(DivOpExpr* expr) override;
	virtual void visit(BitAndOpExpr* expr) override;
	virtual void visit(BitOrOpExpr* expr) override;
	virtual void visit(BitXorOpExpr* expr) override;
	virtual void visit(BitShlOpExpr* expr) override;
	virtual void visit(BitShrOpExpr* expr) override;
	/// @}

	/// @name Specializations To What Optimize
	/// @{
	virtual void optimizeToCompoundOp(AddOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(SubOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(MulOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(ModOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(DivOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(BitAndOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(BitOrOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(BitXorOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(BitShlOpExpr* expr,
		Expression* operand);
	virtual void optimizeToCompoundOp(BitShrOpExpr* expr,
		Expression* operand);
	/// @}

	template<typename ToOptimizeExpr>
	void tryOptimizeWhenOneOfOperandsEqWithLhsOfAssignStmt(ToOptimizeExpr*
		expr);
	template<typename ToOptimizeExpr>
	void tryOptimizeWhenLeftOperandEqWithLhsOfAssignStmt(ToOptimizeExpr*
		expr);

	Expression* getNextOpIfSecondOneIsEqWithLhsOfAssign(BinaryOpExpr* expr);

private:
	/// Saved left-hand side of an assign statement.
	Expression* lhsOfAssignStmt = nullptr;

	/// Resulting operator.
	CompoundOp compoundOp;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

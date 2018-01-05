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
		CompoundOp(std::string op, ShPtr<Expression> operand);

		const std::string &getOperator() const;
		ShPtr<Expression> getOperand() const;
		bool isUnaryOperator() const;
		bool isBinaryOperator() const;

	private:
		/// The resulting operator.
		std::string op;

		/// The right-hand side operand of a binary operator.
		ShPtr<Expression> operand;
	};

public:
	CompoundOpManager();

	virtual ~CompoundOpManager() override;

	/**
	* @brief Returns the ID of the manager.
	*/
	virtual std::string getId() const = 0;

	CompoundOp tryOptimizeToCompoundOp(ShPtr<AssignStmt> stmt);
	CompoundOp tryOptimizeToCompoundOp(ShPtr<AssignOpExpr> expr);
	CompoundOp tryOptimizeToCompoundOp(ShPtr<Expression> lhs,
		ShPtr<Expression> rhs);

protected:
	void createResultingUnaryCompoundOp(const std::string &op);
	void createResultingBinaryCompoundOp(const std::string &op,
		ShPtr<Expression> operand);

private:
	/// @name OrderedAllVisitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<AddOpExpr> expr) override;
	virtual void visit(ShPtr<SubOpExpr> expr) override;
	virtual void visit(ShPtr<MulOpExpr> expr) override;
	virtual void visit(ShPtr<ModOpExpr> expr) override;
	virtual void visit(ShPtr<DivOpExpr> expr) override;
	virtual void visit(ShPtr<BitAndOpExpr> expr) override;
	virtual void visit(ShPtr<BitOrOpExpr> expr) override;
	virtual void visit(ShPtr<BitXorOpExpr> expr) override;
	virtual void visit(ShPtr<BitShlOpExpr> expr) override;
	virtual void visit(ShPtr<BitShrOpExpr> expr) override;
	/// @}

	/// @name Specializations To What Optimize
	/// @{
	virtual void optimizeToCompoundOp(ShPtr<AddOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<SubOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<MulOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<ModOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<DivOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<BitAndOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<BitOrOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<BitXorOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<BitShlOpExpr> expr,
		ShPtr<Expression> operand);
	virtual void optimizeToCompoundOp(ShPtr<BitShrOpExpr> expr,
		ShPtr<Expression> operand);
	/// @}

	template<typename ToOptimizeExpr>
	void tryOptimizeWhenOneOfOperandsEqWithLhsOfAssignStmt(ShPtr<ToOptimizeExpr>
		expr);
	template<typename ToOptimizeExpr>
	void tryOptimizeWhenLeftOperandEqWithLhsOfAssignStmt(ShPtr<ToOptimizeExpr>
		expr);

	ShPtr<Expression> getNextOpIfSecondOneIsEqWithLhsOfAssign(ShPtr<
		BinaryOpExpr> expr);

private:
	/// Saved left-hand side of an assign statement.
	ShPtr<Expression> lhsOfAssignStmt;

	/// Resulting operator.
	CompoundOp compoundOp;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

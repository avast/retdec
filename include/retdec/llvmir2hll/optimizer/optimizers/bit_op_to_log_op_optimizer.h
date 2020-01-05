/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/bit_op_to_log_op_optimizer.h
* @brief Optimizes BitAndExpr to AndOpExpr or BitOrExpr to OrOpExpr if fulfil
*        conditions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_BIT_OP_TO_LOG_OP_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_BIT_OP_TO_LOG_OP_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class IfStmt;
class SwitchStmt;
class WhileLoopStmt;
class BinaryOpExpr;
class ValueAnalysis;

/**
* @brief Optimizes Optimizes BitAndExpr to AndOpExpr or BitOrExpr to OrOpExpr
*        if fulfil conditions.
*
* Some conditions for the optimization:
* We can't optimize in this cases because || or && have short evaluating.
* But | or & evaluates both operands.
*    We can't optimize in this cases:
*    - second operand has a DerefOpExpr.
*      Example: if (p != 0 | *p == 5);
*    - second operand has an array access.
*      Example: if (p != 0 & a[5] > 3);
*    - second operand has a divide with zero.
*      Example: if (p != 0 & b / 0);
*      - second operand has a divide with -1. First operand is IntType.
*      Example: if (p & (b / -1));
*      - second operand has a modulo with 0.
*      Example: if (p & (b % 0));
*      - if first operand is a -1 and second is an IntType or second operand is
*        a -1 and first operand is an IntType. Multiplication.
*      Example: if (p & (b * -1));  *
*    - second operand has a call().
*      Example: if (p!= 0 & call());
*
* Examples of optimizations:
* ////////////
* IFSTMT
* ////////////
* @code
* if (a | b) {}
* @endcode
* can be optimized into
* @code
* if (a || b) {}
* @code
* if (a(bool) & b(bool)) {} else if (c & d) {}
* @endcode
* can be optimized into
* @code
* if (a && b) {} else if (c && d) {}
* @endcode
* ////////////
* WHILELOOPSTMT
* ////////////
* @code
* while (a | b) {}
* @endcode
* can be optimized into
* @code
* while (a || b) {}
* @code
* while (a(bool) & b(bool)) {}
* @endcode
* can be optimized into
* @code
* while (a && b) {}
* @endcode
* ////////////
* SWITCHSTMT
* ////////////
* @code
* switch (a | b) {}
* @endcode
* can be optimized into
* @code
* switch (a || b) {}
* @code
* switch (a(bool) & b(bool)) {}
* @endcode
* can be optimized into
* @code
* siwtch (a && b) {}
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class BitOpToLogOpOptimizer final: public FuncOptimizer {
public:
	BitOpToLogOpOptimizer(Module* module, ValueAnalysis* va);

	virtual std::string getId() const override { return "BitOpToLogOp"; }

private:
	bool canBeBitOrBitAndOptimized(Expression* expr);
	bool isPotentionalDivProblem(DivOpExpr* divOpExpr);
	bool isPotentionalModProblem(Expression* expr);
	bool isPotentionalMulProblem(MulOpExpr* mulOpExpr);
	void tryOptimizeCond(Expression* expr);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(IfStmt* stmt) override;
	virtual void visit(SwitchStmt* stmt) override;
	virtual void visit(WhileLoopStmt* stmt) override;
	virtual void visit(BitAndOpExpr* expr) override;
	virtual void visit(BitOrOpExpr* expr) override;
	virtual void visit(DivOpExpr* expr) override;
	virtual void visit(ModOpExpr* expr) override;
	virtual void visit(MulOpExpr* expr) override;
	/// @}

private:
	/// Analysis of values.
	ValueAnalysis* va = nullptr;

	/// A variable for check if we are in some condition.
	bool isCondition;

	/// A variable for check if is some chance to divide by zero.
	bool isPotentionalProblem;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

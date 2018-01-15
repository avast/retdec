/**
* @file include/retdec/llvmir2hll/ir/call_stmt.h
* @brief A statement wrapping a call expression.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CALL_STMT_H
#define RETDEC_LLVMIR2HLL_IR_CALL_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class CallExpr;
class Expression;
class Visitor;

/**
* @brief A statement wrapping a call expression.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class CallStmt final: public Statement {
public:
	static ShPtr<CallStmt> create(ShPtr<CallExpr> call,
		ShPtr<Statement> succ = nullptr);

	virtual ~CallStmt() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return false; }
	virtual ShPtr<Value> clone() override;
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	ShPtr<CallExpr> getCall() const;
	void setCall(ShPtr<CallExpr> newCall);

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject, ShPtr<Value> arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit CallStmt(ShPtr<CallExpr> call);

private:
	/// Wrapped call expression.
	ShPtr<CallExpr> call;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

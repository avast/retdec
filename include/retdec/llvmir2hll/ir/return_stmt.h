/**
* @file include/retdec/llvmir2hll/ir/return_stmt.h
* @brief A return statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_RETURN_STMT_H
#define RETDEC_LLVMIR2HLL_IR_RETURN_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A return statement.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ReturnStmt final: public Statement {
public:
	static ShPtr<ReturnStmt> create(ShPtr<Expression> retVal = nullptr,
		ShPtr<Statement> succ = nullptr);

	virtual ~ReturnStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return false; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	ShPtr<Expression> getRetVal() const;
	void setRetVal(ShPtr<Expression> newRetVal);
	bool hasRetVal() const;

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
	explicit ReturnStmt(ShPtr<Expression> retVal = nullptr);

private:
	/// Return value.
	ShPtr<Expression> retVal;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

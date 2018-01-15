/**
* @file include/retdec/llvmir2hll/ir/goto_stmt.h
* @brief A goto statement for unconditional transfer of control.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_GOTO_STMT_H
#define RETDEC_LLVMIR2HLL_IR_GOTO_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A goto statement for unconditional transfer of control.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class GotoStmt final: public Statement {
public:
	static ShPtr<GotoStmt> create(ShPtr<Statement> target);

	virtual ~GotoStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return false; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	ShPtr<Statement> getTarget() const;

	void setTarget(ShPtr<Statement> target);

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
	explicit GotoStmt(ShPtr<Statement> target);

private:
	/// Jump target.
	ShPtr<Statement> target;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

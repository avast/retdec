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
	static ReturnStmt* create(Expression* retVal = nullptr,
		Statement* succ = nullptr, Address a = Address::Undefined);

	virtual Value* clone() override;
	virtual bool isEqualTo(Value* otherValue) const override;
	virtual bool isCompound() override { return false; }
	virtual void replace(Expression* oldExpr, Expression* newExpr) override;
	virtual Expression* asExpression() const override;

	Expression* getRetVal() const;
	void setRetVal(Expression* newRetVal);
	bool hasRetVal() const;

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject, Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

    static bool classof(const Value* v) {
        return v->getKind() == Value::ValueKind::ReturnStmt; }

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit ReturnStmt(Expression* retVal = nullptr,
		Address a = Address::Undefined);

private:
	/// Return value.
	Expression* retVal = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

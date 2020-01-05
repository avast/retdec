/**
* @file include/retdec/llvmir2hll/ir/ufor_loop_stmt.h
* @brief A universal for loop statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_UFOR_LOOP_STMT_H
#define RETDEC_LLVMIR2HLL_IR_UFOR_LOOP_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Value;

/**
* @brief A universal for loop statement.
*
* It differs from ForLoopStmt in the following way. In UForLoopStmt, the
* declaration, condition, and increment parts can contain an arbitrary
* expression. In contrast, in ForLoopStmt, the content of these parts is rather
* limited.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class UForLoopStmt final: public Statement {
public:
	static UForLoopStmt* create(
		Expression* init,
		Expression* cond,
		Expression* step,
		Statement* body,
		Statement* succ = nullptr,
		Address a = Address::Undefined
	);

	virtual Value* clone() override;
	virtual bool isEqualTo(Value* otherValue) const override;
	virtual bool isCompound() override { return true; }
	virtual void replace(Expression* oldExpr, Expression* newExpr) override;
	virtual Expression* asExpression() const override;

	Expression* getInit() const;
	Expression* getCond() const;
	Expression* getStep() const;
	Statement* getBody() const;

	void setInit(Expression* newInit);
	void setCond(Expression* newCond);
	void setStep(Expression* newStep);
	void setBody(Statement* newBody);

	bool isInitDefinition() const;
	void markInitAsDefinition();

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject, Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

    static bool classof(const Value* v) {
        return v->getKind() == Value::ValueKind::UForLoopStmt; }

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	UForLoopStmt(
		Expression* init,
		Expression* cond,
		Expression* step,
		Statement* body,
		Address a = Address::Undefined
	);

	/// Initialization part.
	Expression* init = nullptr;

	/// Is the initialization part a definition?
	bool initIsDefinition;

	/// Conditional part.
	Expression* cond = nullptr;

	/// Step part.
	Expression* step = nullptr;

	/// Body.
	Statement* body = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

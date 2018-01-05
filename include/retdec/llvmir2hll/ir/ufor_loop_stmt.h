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
	static ShPtr<UForLoopStmt> create(
		ShPtr<Expression> init,
		ShPtr<Expression> cond,
		ShPtr<Expression> step,
		ShPtr<Statement> body,
		ShPtr<Statement> succ = nullptr
	);

	virtual ~UForLoopStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return true; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	ShPtr<Expression> getInit() const;
	ShPtr<Expression> getCond() const;
	ShPtr<Expression> getStep() const;
	ShPtr<Statement> getBody() const;

	void setInit(ShPtr<Expression> newInit);
	void setCond(ShPtr<Expression> newCond);
	void setStep(ShPtr<Expression> newStep);
	void setBody(ShPtr<Statement> newBody);

	bool isInitDefinition() const;
	void markInitAsDefinition();

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
	UForLoopStmt(
		ShPtr<Expression> init,
		ShPtr<Expression> cond,
		ShPtr<Expression> step,
		ShPtr<Statement> body
	);

	/// Initialization part.
	ShPtr<Expression> init;

	/// Is the initialization part a definition?
	bool initIsDefinition;

	/// Conditional part.
	ShPtr<Expression> cond;

	/// Step part.
	ShPtr<Expression> step;

	/// Body.
	ShPtr<Statement> body;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

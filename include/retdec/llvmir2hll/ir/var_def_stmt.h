/**
* @file include/retdec/llvmir2hll/ir/var_def_stmt.h
* @brief A variable definition statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_VAR_DEF_STMT_H
#define RETDEC_LLVMIR2HLL_IR_VAR_DEF_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Variable;
class Visitor;

/**
* @brief A variable definition statement.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class VarDefStmt final: public Statement {
public:
	static ShPtr<VarDefStmt> create(ShPtr<Variable> var,
		ShPtr<Expression> init = nullptr,
		ShPtr<Statement> succ = nullptr);

	virtual ~VarDefStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return false; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	ShPtr<Variable> getVar() const;
	ShPtr<Expression> getInitializer() const;
	bool hasInitializer() const;

	void setVar(ShPtr<Variable> newVar);
	void setInitializer(ShPtr<Expression> newInit);
	void removeInitializer();

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
	explicit VarDefStmt(ShPtr<Variable> var,
		ShPtr<Expression> init = nullptr);

private:
	/// Variable.
	ShPtr<Variable> var;

	/// Variable initializer.
	ShPtr<Expression> init;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

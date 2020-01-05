/**
* @file include/retdec/llvmir2hll/ir/global_var_def.h
* @brief A definition of a global variable.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_GLOBAL_VAR_DEF_H
#define RETDEC_LLVMIR2HLL_IR_GLOBAL_VAR_DEF_H

#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Variable;
class Visitor;

/**
* @brief A definition of a global variable.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class GlobalVarDef final: public Value {
public:
	static GlobalVarDef* create(Variable* var,
		Expression* init = nullptr);

	virtual Value* clone() override;
	virtual bool isEqualTo(Value* otherValue) const override;
	void replace(Expression* oldExpr, Expression* newExpr);

	Variable* getVar() const;
	Expression* getInitializer() const;
	bool hasInitializer() const;
	bool definesExternalVar() const;
	Address getAddress() const;

	void setVar(Variable* newVar);
	void setInitializer(Expression* newInit);
	void removeInitializer();

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject, Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit GlobalVarDef(Variable* var,
		Expression* init = nullptr);

private:
	/// Global variable.
	Variable* var = nullptr;

	/// Initializer of the variable. May be empty.
	Expression* init = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

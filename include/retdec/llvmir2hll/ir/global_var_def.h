/**
* @file include/retdec/llvmir2hll/ir/global_var_def.h
* @brief A definition of a global variable.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_GLOBAL_VAR_DEF_H
#define RETDEC_LLVMIR2HLL_IR_GLOBAL_VAR_DEF_H

#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

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
	static ShPtr<GlobalVarDef> create(ShPtr<Variable> var,
		ShPtr<Expression> init = nullptr);

	virtual ~GlobalVarDef() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr);

	ShPtr<Variable> getVar() const;
	ShPtr<Expression> getInitializer() const;
	bool hasInitializer() const;
	bool definesExternalVar() const;

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
	explicit GlobalVarDef(ShPtr<Variable> var,
		ShPtr<Expression> init = nullptr);

private:
	/// Global variable.
	ShPtr<Variable> var;

	/// Initializer of the variable. May be empty.
	ShPtr<Expression> init;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

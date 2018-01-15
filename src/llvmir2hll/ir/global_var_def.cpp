/**
* @file src/llvmir2hll/ir/global_var_def.cpp
* @brief Implementation of GlobalVarDef.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new definition of a global variable.
*
* See create() for more information.
*/
GlobalVarDef::GlobalVarDef(ShPtr<Variable> var, ShPtr<Expression> init):
	var(var), init(init) {}

/**
* @brief Destructs the definition.
*/
GlobalVarDef::~GlobalVarDef() {}

ShPtr<Value> GlobalVarDef::clone() {
	ShPtr<GlobalVarDef> varDefStmt(GlobalVarDef::create(ucast<Variable>(var->clone())));
	varDefStmt->setMetadata(getMetadata());
	if (init) {
		varDefStmt->setInitializer(ucast<Expression>(init->clone()));
	}
	return varDefStmt;
}

bool GlobalVarDef::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types, variables and variable initializers have to be equal.
	if (ShPtr<GlobalVarDef> otherGlobalVarDef = cast<GlobalVarDef>(otherValue)) {
		return var->isEqualTo(otherGlobalVarDef->var) &&
			init->isEqualTo(otherGlobalVarDef->init);
	}
	return false;
}

void GlobalVarDef::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	if (oldExpr == var) {
		ShPtr<Variable> newVar(cast<Variable>(newExpr));
		ASSERT_MSG(newVar, "defined variable can be replaced only with a variable");
		setVar(newVar);
	} else {
		var->replace(oldExpr, newExpr);
	}

	if (oldExpr == init) {
		setInitializer(newExpr);
	} else if (init) {
		init->replace(oldExpr, newExpr);
	}
}

/**
* @brief Return the variable.
*/
ShPtr<Variable> GlobalVarDef::getVar() const {
	return var;
}

/**
* @brief Returns the variable initializer.
*
* If there is no initializer, it returns the null pointer.
*/
ShPtr<Expression> GlobalVarDef::getInitializer() const {
	return init;
}

/**
* @brief Returns @c true if the global variable has an initializer, @c false
*        otherwise.
*/
bool GlobalVarDef::hasInitializer() const {
	return init != ShPtr<Expression>();
}

/**
* @brief Checks if it defines an external global variable.
*
* @return @c true if it defines an external global variable, @c false otherwise.
*/
bool GlobalVarDef::definesExternalVar() const {
	return var->isExternal();
}

/**
* @brief Sets a new variable.
*
* @par Preconditions
*  - @a newVar is non-null
*/
void GlobalVarDef::setVar(ShPtr<Variable> newVar) {
	PRECONDITION_NON_NULL(newVar);

	var->removeObserver(shared_from_this());
	newVar->addObserver(shared_from_this());
	var = newVar;
}

/**
* @brief Sets a new initializer.
*/
void GlobalVarDef::setInitializer(ShPtr<Expression> newInit) {
	if (init) {
		init->removeObserver(shared_from_this());
	}
	if (newInit) {
		newInit->addObserver(shared_from_this());
	}
	init = newInit;
}

/**
* @brief Removes the initializer.
*/
void GlobalVarDef::removeInitializer() {
	setInitializer(ShPtr<Expression>());
}

/**
* @brief Creates a new definition of a global variable.
*
* @param[in] var Global variable to be defined.
* @param[in] init Initializer of @a var.
*
* @par Preconditions
*  - @a var is non-null
*/
ShPtr<GlobalVarDef> GlobalVarDef::create(ShPtr<Variable> var, ShPtr<Expression> init) {
	PRECONDITION_NON_NULL(var);

	ShPtr<GlobalVarDef> varDef(new GlobalVarDef(var, init));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	var->addObserver(varDef);
	if (init) {
		init->addObserver(varDef);
	}

	return varDef;
}

/**
* @brief Updates the definition according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* It replaces @a subject with @arg. For example, if @a subject is the variable,
* this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any part of the definition
*  - @a arg is not a variable/expression
*
* @par Preconditions
*  - @a subject is non-null
*  - if @a subject is a variable, @a arg has to be non-null
*
* @see Subject::update()
*/
void GlobalVarDef::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);

	ShPtr<Variable> newVar = cast<Variable>(arg);
	if (subject == var && newVar) {
		setVar(newVar);
		return;
	}

	ShPtr<Expression> newInit = cast<Expression>(arg);
	if (subject == init && (!arg || newInit)) {
		setInitializer(newInit);
	}
}

void GlobalVarDef::accept(Visitor *v) {
	v->visit(ucast<GlobalVarDef>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec

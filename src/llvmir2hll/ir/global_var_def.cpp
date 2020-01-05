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
GlobalVarDef::GlobalVarDef(Variable* var, Expression* init):
	var(var), init(init) {}

Value* GlobalVarDef::clone() {
	GlobalVarDef* varDefStmt(GlobalVarDef::create(ucast<Variable>(var->clone())));
	varDefStmt->setMetadata(getMetadata());
	if (init) {
		varDefStmt->setInitializer(ucast<Expression>(init->clone()));
	}
	return varDefStmt;
}

bool GlobalVarDef::isEqualTo(Value* otherValue) const {
	// Both types, variables and variable initializers have to be equal.
	if (GlobalVarDef* otherGlobalVarDef = cast<GlobalVarDef>(otherValue)) {
		return var->isEqualTo(otherGlobalVarDef->var) &&
			init->isEqualTo(otherGlobalVarDef->init);
	}
	return false;
}

void GlobalVarDef::replace(Expression* oldExpr, Expression* newExpr) {
	if (oldExpr == var) {
		Variable* newVar(cast<Variable>(newExpr));
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
Variable* GlobalVarDef::getVar() const {
	return var;
}

/**
* @brief Returns the variable initializer.
*
* If there is no initializer, it returns the null pointer.
*/
Expression* GlobalVarDef::getInitializer() const {
	return init;
}

/**
* @brief Returns @c true if the global variable has an initializer, @c false
*        otherwise.
*/
bool GlobalVarDef::hasInitializer() const {
	return init != nullptr;
}

/**
* @brief Checks if it defines an external global variable.
*
* @return @c true if it defines an external global variable, @c false otherwise.
*/
bool GlobalVarDef::definesExternalVar() const {
	return var->isExternal();
}

Address GlobalVarDef::getAddress() const {
	return var->getAddress();
}

/**
* @brief Sets a new variable.
*
* @par Preconditions
*  - @a newVar is non-null
*/
void GlobalVarDef::setVar(Variable* newVar) {
	PRECONDITION_NON_NULL(newVar);

	var->removeObserver(this);
	newVar->addObserver(this);
	var = newVar;
}

/**
* @brief Sets a new initializer.
*/
void GlobalVarDef::setInitializer(Expression* newInit) {
	if (init) {
		init->removeObserver(this);
	}
	if (newInit) {
		newInit->addObserver(this);
	}
	init = newInit;
}

/**
* @brief Removes the initializer.
*/
void GlobalVarDef::removeInitializer() {
	setInitializer(nullptr);
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
GlobalVarDef* GlobalVarDef::create(Variable* var, Expression* init) {
	PRECONDITION_NON_NULL(var);

	GlobalVarDef* varDef(new GlobalVarDef(var, init));

	// Initialization (recall that this cannot be called in a
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
void GlobalVarDef::update(Value* subject, Value* arg) {
	PRECONDITION_NON_NULL(subject);

	Variable* newVar = cast<Variable>(arg);
	if (subject == var && newVar) {
		setVar(newVar);
		return;
	}

	Expression* newInit = cast<Expression>(arg);
	if (subject == init && (!arg || newInit)) {
		setInitializer(newInit);
	}
}

void GlobalVarDef::accept(Visitor *v) {
	v->visit(ucast<GlobalVarDef>(this));
}

} // namespace llvmir2hll
} // namespace retdec

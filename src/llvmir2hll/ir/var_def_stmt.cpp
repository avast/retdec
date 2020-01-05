/**
* @file src/llvmir2hll/ir/var_def_stmt.cpp
* @brief Implementation of VarDefStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new variable definition statement.
*
* See create() for more information.
*/
VarDefStmt::VarDefStmt(Variable* var, Expression* init, Address a):
	Statement(Value::ValueKind::VarDefStmt, a), var(var), init(init) {}

Value* VarDefStmt::clone() {
	VarDefStmt* varDefStmt(VarDefStmt::create(ucast<Variable>(var->clone()),
		nullptr, nullptr, getAddress()));
	varDefStmt->setMetadata(getMetadata());
	if (init) {
		varDefStmt->setInitializer(ucast<Expression>(init->clone()));
	}
	return varDefStmt;
}

bool VarDefStmt::isEqualTo(Value* otherValue) const {
	// Both types, variables and variable initializers have to be equal.
	if (VarDefStmt* otherVarDefStmt = cast<VarDefStmt>(otherValue)) {
		return var->isEqualTo(otherVarDefStmt->var) &&
			init->isEqualTo(otherVarDefStmt->init);
	}
	return false;
}

void VarDefStmt::replace(Expression* oldExpr, Expression* newExpr) {
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

Expression* VarDefStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Return the variable.
*/
Variable* VarDefStmt::getVar() const {
	return var;
}

/**
* @brief Returns the variable initializer.
*
* If there is no initializer, it returns the null pointer.
*/
Expression* VarDefStmt::getInitializer() const {
	return init;
}

/**
* @brief Returns @c true if the statement has an initializer, @c false otherwise.
*/
bool VarDefStmt::hasInitializer() const {
	return init != nullptr;
}

/**
* @brief Sets a new variable.
*
* @par Preconditions
*  - @a newVar is non-null
*/
void VarDefStmt::setVar(Variable* newVar) {
	PRECONDITION_NON_NULL(newVar);

	var->removeObserver(this);
	newVar->addObserver(this);
	var = newVar;
}

/**
* @brief Sets a new initializer.
*/
void VarDefStmt::setInitializer(Expression* newInit) {
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
void VarDefStmt::removeInitializer() {
	setInitializer(nullptr);
}

/**
* @brief Creates a new variable definition statement.
*
* @param[in] var Variable to be defined.
* @param[in] init Initializer of @a var.
* @param[in] succ Follower of the statement in the program flow.
* @param[in] a Address.
*
* @par Preconditions
*  - @a var is non-null
*/
VarDefStmt* VarDefStmt::create(Variable* var,
		Expression* init, Statement* succ, Address a) {
	PRECONDITION_NON_NULL(var);

	VarDefStmt* stmt(new VarDefStmt(var, init, a));
	stmt->setSuccessor(succ);

	// Initialization (recall that this cannot be called in a
	// constructor).
	var->addObserver(stmt);
	if (init) {
		init->addObserver(stmt);
	}

	return stmt;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* It replaces @a subject with @arg. For example, if @a subject is the variable,
* this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any part of the statement
*  - @a arg is not a variable/expression
*
* @par Preconditions
*  - @a subject is non-null
*  - if @a subject is a variable, @a arg has to be non-null
*
* @see Subject::update()
*/
void VarDefStmt::update(Value* subject, Value* arg) {
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

void VarDefStmt::accept(Visitor *v) {
	v->visit(ucast<VarDefStmt>(this));
}

} // namespace llvmir2hll
} // namespace retdec

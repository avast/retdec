/**
* @file src/llvmir2hll/utils/ir.cpp
* @brief Implementation of the IR utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/used_vars_visitor.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/obtainer/calls_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/variable_replacer.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/utils/container.h"
#include "retdec/utils/string.h"

using retdec::utils::hasItem;
using retdec::utils::isLowerThanCaseInsensitive;

namespace {

using namespace retdec::llvmir2hll;

/**
* @brief Compares the two given functions by their name.
*
* @return @c true if the name of @a f1 comes before the name of @a f2
*         (case-insensitively), @c false otherwise.
*/
bool compareFuncs(const ShPtr<Function> &f1, const ShPtr<Function> &f2) {
	return isLowerThanCaseInsensitive(f1->getName(), f2->getName());
}

/**
* @brief Compares the two given variables by their name.
*
* @return @c true if the name of @a v1 comes before the name of @a v2
*         (case-insensitively), @c false otherwise.
*/
bool compareVars(const ShPtr<Variable> &v1, const ShPtr<Variable> &v2) {
	return isLowerThanCaseInsensitive(v1->getName(), v2->getName());
}

/**
* @brief Compares the two given variables with initializers by their name.
*
* @return @c true if the name of @a v1 comes before the name of @a v2
*         (case-insensitively), @c false otherwise.
*/
bool compareVarInits(const VarInitPair &v1, const VarInitPair &v2) {
	return isLowerThanCaseInsensitive(v1.first->getName(), v2.first->getName());
}

/**
* @brief Skips the given type of unary expressions in the given expression.
*
* @return The first expression that is not of the given type.
*
* @tparam T Class type whose instances have the @c getOperand() member
*           function.
*/
template<class T>
ShPtr<Expression> skipUnaryExpr(ShPtr<Expression> expr) {
	while (auto castedExpr = cast<T>(expr)) {
		expr = castedExpr->getOperand();
	}
	return expr;
}

} // anonymous namespace

/**
* @brief Sorts the given vector by the name of its elements (case-insensitively).
* @note This one function is defined outside the namespace below with explicit
*       namespace declarations to help Doxygen and prevent it from generating
*       "no matching file member found for" warnings.
*/
void retdec::llvmir2hll::sortByName(retdec::llvmir2hll::FuncVector &vec) {
	std::sort(vec.begin(), vec.end(), compareFuncs);
}

namespace retdec {
namespace llvmir2hll {

/**
* @brief Sorts the given vector by the name of its elements (case-insensitively).
*/
void sortByName(VarVector &vec) {
	std::sort(vec.begin(), vec.end(), compareVars);
}

/**
* @brief Sorts the given vector by the name of its elements (case-insensitively).
*
* Only the name of a variable is considered.
*/
void sortByName(VarInitPairVector &vec) {
	std::sort(vec.begin(), vec.end(), compareVarInits);
}

/**
* @brief Skips empty statements in @a stmt.
*
* @param[in] stmts Sequence of statements where empty statements should be
*                  skipped.
*
* @return First non-empty statement in @a stmts.
*
* If there is no non-empty statement in @a stmts, the null pointer is returned.
*/
ShPtr<Statement> skipEmptyStmts(ShPtr<Statement> stmts) {
	auto currStmt = stmts;
	while (isa<EmptyStmt>(currStmt)) {
		currStmt = currStmt->getSuccessor();
	}
	return currStmt;
}

/**
* @brief Skips casts in the given expression and returns the first non-cast
*        expression.
*/
ShPtr<Expression> skipCasts(ShPtr<Expression> expr) {
	return skipUnaryExpr<CastExpr>(expr);
}

/**
* @brief Skips dereferences in the given expression and returns the first
*        non-dereference expression.
*/
ShPtr<Expression> skipDerefs(ShPtr<Expression> expr) {
	return skipUnaryExpr<DerefOpExpr>(expr);
}

/**
* @brief Skips addresses in the given expression and returns the first
*        non-address expression.
*/
ShPtr<Expression> skipAddresses(ShPtr<Expression> expr) {
	return skipUnaryExpr<AddressOpExpr>(expr);
}

/**
* @brief Returns @c true if the sequence of statements @a stmts ends with
*        a return or unreachable statement, @c false otherwise.
*
* If @a stmts is the null pointer, it returns @c false.
*/
bool endsWithRetOrUnreach(ShPtr<Statement> stmts) {
	if (!stmts) {
		return false;
	}

	auto lastStmt = Statement::getLastStatement(stmts);
	return (isa<ReturnStmt>(lastStmt) || isa<UnreachableStmt>(lastStmt));
}

/**
* @brief Returns the left-hand side of the given variable definition/assign
*        statement.
*
* Precondition:
*  - @a stmt is either a variable definition statement or an assign statement
*/
ShPtr<Expression> getLhs(ShPtr<Statement> stmt) {
	if (auto varDefStmt = cast<VarDefStmt>(stmt)) {
		return varDefStmt->getVar();
	} else if (auto assignStmt = cast<AssignStmt>(stmt)) {
		return assignStmt->getLhs();
	} else {
		PRECONDITION_FAILED("the statement `" << stmt <<
			"` is not a variable-defining or assign statement");
		return {};
	}
}

/**
* @brief Returns the right-hand side of the given variable definition/assign
*        statement.
*
* Precondition:
*  - @a stmt is either a variable definition statement or an assign statement
*/
ShPtr<Expression> getRhs(ShPtr<Statement> stmt) {
	if (auto varDefStmt = cast<VarDefStmt>(stmt)) {
		return varDefStmt->getInitializer();
	} else if (auto assignStmt = cast<AssignStmt>(stmt)) {
		return assignStmt->getRhs();
	} else {
		PRECONDITION_FAILED("the statement `" << stmt <<
			"` is not a variable-defining or assign statement");
		return {};
	}
}

/**
* @brief Removes the given variable definition/assignment statement.
*
* @param[in] stmt Statement to be removed.
* @param[in] func If non-null and the removed statement is a variable definition
*                 statement, updates the set of local variables of the function.
*
* @return A vector of statements (possibly empty) with which @a stmt has been
*         replaced.
*
* If there are function calls in the right-hand side of @a stmt, they are
* preserved, and returned in the resulting list. Debug comments are also
* preserved.
*
* Precondition:
*  - @a stmt is either a variable definition statement or an assign statement
*/
StmtVector removeVarDefOrAssignStatement(ShPtr<Statement> stmt,
		ShPtr<Function> func) {
	PRECONDITION(isVarDefOrAssignStmt(stmt), "the statement `" << stmt <<
		"` is not a variable-defining or assign statement");

	// A vector of statements with which stmt has been replaced.
	StmtVector newStmts;

	// Update also the set of local variables in func?
	if (auto varDefStmt = cast<VarDefStmt>(stmt)) {
		if (func) {
			func->removeLocalVar(varDefStmt->getVar());
		}
	}

	// Is there a right-hand side?
	auto rhs = getRhs(stmt);
	if (!rhs) {
		// There is an empty initializer, so there are no function calls.
		Statement::removeStatementButKeepDebugComment(stmt);
		return newStmts;
	}

	// Are there any function calls in the right-hand side?
	auto calls = CallsObtainer::getCalls(rhs);
	if (calls.empty()) {
		// There are no function calls in the right-hand side.
		Statement::removeStatementButKeepDebugComment(stmt);
		return newStmts;
	}

	//
	// There are some function calls, so preserve them.
	//

	// Insert the first found call.
	auto callStmt = CallStmt::create(*calls.begin());
	callStmt->setMetadata(stmt->getMetadata());
	Statement::replaceStatement(stmt, callStmt);
	newStmts.push_back(callStmt);
	calls.erase(calls.begin());

	// Insert the remaining calls.
	auto lastCallStmt = callStmt;
	for (auto call : calls) {
		callStmt = CallStmt::create(call);
		lastCallStmt->appendStatement(callStmt);
		newStmts.push_back(callStmt);
		lastCallStmt = callStmt;
	}

	return newStmts;
}

/**
* @brief Replaces @a var with @a expr in @a stmt.
*/
void replaceVarWithExprInStmt(ShPtr<Variable> var,
		ShPtr<Expression> expr, ShPtr<Statement> stmt) {
	// If stmt is not a variable-defining/assign statement, we can directly
	// replace the variable.
	if (!isVarDefOrAssignStmt(stmt)) {
		stmt->replace(var, expr);
		return;
	}

	// The statement is of the form
	//
	//   someVar = rhs(stmt)
	//

	// If the left-hand side of the statement differs from var, we may also
	// directly replace the variable in the statement.
	if (getLhs(stmt) != var) {
		stmt->replace(var, expr);
		return;
	}

	// The statement is of the form
	//
	//    var = rhs(stmt)
	//
	// We have to replace var only on the right-hand side of the statement.

	// If rhs(stmt) differs from vars, we may directly replace the variable in
	// the right-hand side of the statement.
	if (getRhs(stmt) != var) {
		getRhs(stmt)->replace(var, expr);
		return;
	}

	// The statement is of the form
	//
	//    var = var
	//
	// so set the right-hand side using the appropriate methods instead of
	// using getRhs(stmt)->replace(), which wouldn't work in this case.
	if (auto assignStmt = cast<AssignStmt>(stmt)) {
		assignStmt->setRhs(expr);
	} else if (auto varDefStmt = cast<VarDefStmt>(stmt)) {
		varDefStmt->setInitializer(expr);
	} else {
		FAIL("this should never happen since stmt has to be either a VarDefStmt"
			" or AssignStmt; stmt is `" << stmt << "`");
	}
}

/**
* @brief Returns @c true if @a stmt is a VarDefStmt or AssignStmt, @c false
*        otherwise.
*/
bool isVarDefOrAssignStmt(ShPtr<Statement> stmt) {
	return isa<VarDefStmt>(stmt) || isa<AssignStmt>(stmt);
}

/**
* @brief Returns @c true if @a stmt is a loop, @c false otherwise.
*
* A loop can be either a for loop or a while loop.
*/
bool isLoop(ShPtr<Statement> stmt) {
	return isa<WhileLoopStmt>(stmt) || isa<ForLoopStmt>(stmt) ||
		isa<UForLoopStmt>(stmt);
}

/**
* @brief Returns @c true if the given loop is both empty and infinite, @c false
*        otherwise.
*
* An infinite empty loop is of the following form:
* @code
* while (true) {
*     // optional empty statements
* }
* @endcode
*/
bool isInfiniteEmptyLoop(ShPtr<WhileLoopStmt> stmt) {
	// Check that the condition is a literal "true".
	auto boolCond = cast<ConstBool>(stmt->getCondition());
	if (!boolCond || !boolCond->getValue()) {
		return false;
	}

	// Check that the body is empty.
	if (skipEmptyStmts(stmt->getBody())) {
		return false;
	}

	return true;
}

/**
* @brief Returns @c true if @a stmt is a <tt>while True</tt> loop, @c false
*        otherwise.
*/
bool isWhileTrueLoop(ShPtr<WhileLoopStmt> stmt) {
	auto boolCond = cast<ConstBool>(stmt->getCondition());
	return boolCond && boolCond->isTrue();
}

/**
* @brief Returns the function called in @a call.
*
* If the call is indirect, the null pointer is returned.
*/
ShPtr<Function> getCalledFunc(ShPtr<CallExpr> callExpr, ShPtr<Module> module) {
	// If the called expression is not a variable, then it is definitely a call
	// by pointer.
	auto calledVar = cast<Variable>(callExpr->getCalledExpr());
	if (!calledVar) {
		return {};
	}

	return module->getFuncByName(calledVar->getName());
}

/**
* @brief Returns the name of the function called in @a call.
*
* If the call is indirect, the empty string is returned.
*/
std::string getNameOfCalledFunc(ShPtr<CallExpr> callExpr, ShPtr<Module> module) {
	auto calledFunc = getCalledFunc(callExpr, module);
	return calledFunc ? calledFunc->getName() : std::string();
}

/**
* @brief Returns @a true if the given call expression @a callExpr in the given
*        @a module is indirect (by a pointer), @c false otherwise.
*/
bool isCallByPointer(ShPtr<Expression> callExpr, ShPtr<Module> module) {
	// If the called expression is not a variable, then it is definitely an indirect call
	// by pointer.
	auto calledVar = cast<Variable>(callExpr);
	if (!calledVar) {
		return true;
	}

	return !module->getFuncByName(calledVar->getName());
}

/**
* @brief Returns the innermost loop inside which @a stmt is.
*
* If there is no innermost loop, it returns the null pointer.
*
* @par Preconditions
*  - @a stmt is non-null
*/
ShPtr<Statement> getInnermostLoop(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	auto innLoop = stmt->getParent();
	while (innLoop && !isLoop(innLoop)) {
		innLoop = innLoop->getParent();
	}
	return innLoop;
}

/**
* @brief Returns the innermost loop or switch inside which @a stmt is.
*
* If there is no innermost loop or switch, it returns the null pointer.
*
* @par Preconditions
*  - @a stmt is non-null
*/
ShPtr<Statement> getInnermostLoopOrSwitch(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);

	auto innLoopOrSwitch = stmt->getParent();
	while (innLoopOrSwitch && !isLoop(innLoopOrSwitch) &&
			!isa<SwitchStmt>(innLoopOrSwitch)) {
		innLoopOrSwitch = innLoopOrSwitch->getParent();
	}
	return innLoopOrSwitch;
}

/**
* @brief Returns @c true if @a stmt defines @a var, @c false otherwise.
*
* @par Preconditions
*  - @a stmt and @a var are non-null
*/
bool isDefOfVar(ShPtr<Statement> stmt, ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION_NON_NULL(var);

	auto writtenVars = UsedVarsVisitor::getUsedVars(stmt, false,
		false)->getWrittenVars();
	return hasItem(writtenVars, var);
}

/**
* @brief Adds @a var as a new local variable of @a func, possibly with an
*        initializer @a init.
*
* An advatage of using this function over manually adding @a var to @a func is
* that this function also creates a VarDefStmt at the beginning of @a func, and
* places it in a proper place so that all VarDefStmts at the beginning of @a
* func are sorted alphabetically.
*
* If @a var is already a local function of @a func, this function does nothing.
*
* @par Preconditions
*  - @a func is a definition, not a declaration
*/
void addLocalVarToFunc(ShPtr<Variable> var, ShPtr<Function> func,
		ShPtr<Expression> init) {
	PRECONDITION(func->isDefinition(), "it has to be a definition");

	if (func->hasLocalVar(var)) {
		return;
	}

	func->addLocalVar(var);

	// Insert a variable-defining statement to a proper position at the
	// beginning of the function's body.
	// First, we find a proper position...
	auto stmt = func->getBody();
	while (auto varDefStmt = cast<VarDefStmt>(stmt)) {
		if (varDefStmt->getVar()->getName() > var->getName() ||
				!stmt->getSuccessor()) {
			break;
		}
		stmt = stmt->getSuccessor();
	}
	// ...then, we place a VarDefStmt of var into that position.
	stmt->prependStatement(VarDefStmt::create(var, init));
}

/**
* @brief Converts the given global variable @a var into a local variable of @a
*        func, possibly with the given initializer @a init.
*
* The converted function gets the same name as the global variable.
*
* @par Preconditions
*  - @a var is a global variable
*  - @a func is a definition, not a declaration
*/
void convertGlobalVarToLocalVarInFunc(ShPtr<Variable> var, ShPtr<Function> func,
		ShPtr<Expression> init) {
	PRECONDITION(func->isDefinition(), "it has to be a definition");

	// We cannot use clone() because variables are not cloned, so we use
	// copy().
	auto varCopy = var->copy();
	addLocalVarToFunc(varCopy, func, init);
	VariableReplacer::replaceVariable(var, varCopy, func);
}

} // namespace llvmir2hll
} // namespace retdec

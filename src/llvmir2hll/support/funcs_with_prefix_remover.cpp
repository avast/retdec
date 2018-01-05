/**
* @file src/llvmir2hll/support/funcs_with_prefix_remover.cpp
* @brief Implementation of FuncsWithPrefixRemover.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/funcs_with_prefix_remover.h"
#include "retdec/utils/string.h"

using retdec::utils::startsWith;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new remover.
*
* See removeFuncs() for the description of all parameters and preconditions.
*/
FuncsWithPrefixRemover::FuncsWithPrefixRemover(ShPtr<Module> module,
	const StringSet &prefixes):
		OrderedAllVisitor(), module(module), prefixes(prefixes) {}

/**
* @brief Destructs the remover.
*/
FuncsWithPrefixRemover::~FuncsWithPrefixRemover() {}

/**
* @brief Removes functions from @a module whose name starts with a prefix from
*        @a prefixes.
*
* @param[in,out] module Module in which the functions will be removed.
* @param[in] prefixes Prefixes of functions to be removed.
*
* It is assumed that the calls may appear only in the following situations:
*  - as the right-hand side of a variable-defining statement;
*  - as the right-hand side of an assign statement;
*  - as a single call statement.
* They cannot appear in other statements or expressions.
*
* All declarations of such functions are removed as well.
*
* @par Preconditions
*  - @a module is non-null
*/
void FuncsWithPrefixRemover::removeFuncs(ShPtr<Module> module,
		const StringSet &prefixes) {
	PRECONDITION_NON_NULL(module);

	ShPtr<FuncsWithPrefixRemover> remover(new FuncsWithPrefixRemover(module,
		prefixes));
	remover->performRemoval();
}

/**
* @brief Overload of removeFuncs() for a single prefix.
*/
void FuncsWithPrefixRemover::removeFuncs(ShPtr<Module> module,
		const std::string &prefix) {
	StringSet prefixes{prefix};
	removeFuncs(module, prefixes);
}

/**
* @brief Performs the removal of functions.
*
* For more information, see the description of removeFuncs().
*/
void FuncsWithPrefixRemover::performRemoval() {
	removeCallsOfFuncsWithPrefixes();
	removeDeclarationsOfFuncsWithPrefixes();
}

/**
* @brief Removes calls to functions whose name starts with a prefix from @c
*        prefixes.
*/
void FuncsWithPrefixRemover::removeCallsOfFuncsWithPrefixes() {
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		visit(*i);
	}
}

/**
* @brief Removes the declarations of functions whose name starts with a prefix
*        from @c prefixes.
*/
void FuncsWithPrefixRemover::removeDeclarationsOfFuncsWithPrefixes() {
	// Since we are going to modify the module, we have to store a copy of
	// declared functions and iterate over this copy.
	FuncVector funcDecls(
		module->func_declaration_begin(),
		module->func_declaration_end()
	);
	for (const auto &func : funcDecls) {
		if (shouldBeRemoved(func)) {
			module->removeFunc(func);
		}
	}
}

/**
* @brief Returns @c true if @a expr is a call to a function that should be
*        removed, @c false otherwise.
*/
bool FuncsWithPrefixRemover::isCallOfFuncToBeRemoved(ShPtr<Expression> expr) const {
	ShPtr<CallExpr> callExpr(cast<CallExpr>(expr));
	if (!callExpr) {
		return false;
	}

	ShPtr<Variable> callVar(cast<Variable>(callExpr->getCalledExpr()));
	if (!callVar) {
		return false;
	}

	ShPtr<Function> callFunc(module->getFuncByName(callVar->getName()));
	if (!callFunc) {
		return false;
	}

	return shouldBeRemoved(callFunc);
}

/**
* @brief Returns @c true if @a func is a function that should be removed, @c
*        false otherwise.
*/
bool FuncsWithPrefixRemover::shouldBeRemoved(ShPtr<Function> func) const {
	for (const auto &prefix : prefixes) {
		if (startsWith(func->getName(), prefix)) {
			return true;
		}
	}
	return false;
}

void FuncsWithPrefixRemover::visit(ShPtr<CallStmt> stmt) {
	// We have to backup the statement's successor because
	// removeStatementButKeepDebugComment() resets the successor.
	ShPtr<Statement> stmtSucc(stmt->getSuccessor());

	if (isCallOfFuncToBeRemoved(stmt->getCall())) {
		Statement::removeStatementButKeepDebugComment(stmt);
	}

	// Visit the successor (if any).
	if (stmtSucc) {
		visitStmt(stmtSucc);
	}
}

void FuncsWithPrefixRemover::visit(ShPtr<AssignStmt> stmt) {
	// We have to backup the statement's successor because
	// removeStatementButKeepDebugComment() resets the successor.
	ShPtr<Statement> stmtSucc(stmt->getSuccessor());

	if (isCallOfFuncToBeRemoved(stmt->getRhs())) {
		Statement::removeStatementButKeepDebugComment(stmt);
	}

	// Visit the successor (if any).
	if (stmtSucc) {
		visitStmt(stmtSucc);
	}
}

void FuncsWithPrefixRemover::visit(ShPtr<VarDefStmt> stmt) {
	if (isCallOfFuncToBeRemoved(stmt->getInitializer())) {
		stmt->removeInitializer();
	}

	// Visit the successor (if any).
	if (ShPtr<Statement> stmtSucc = stmt->getSuccessor()) {
		visitStmt(stmtSucc);
	}
}

} // namespace llvmir2hll
} // namespace retdec

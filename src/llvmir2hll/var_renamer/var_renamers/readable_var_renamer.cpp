/**
* @file src/llvmir2hll/var_renamer/var_renamers/readable_var_renamer.cpp
* @brief Implementation of ReadableVarRenamer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/statements_counter.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gens/num_var_name_gen.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer_factory.h"
#include "retdec/llvmir2hll/var_renamer/var_renamers/readable_var_renamer.h"
#include "retdec/utils/array.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"

using namespace std::string_literals;

using retdec::utils::addToSet;
using retdec::utils::arraySize;
using retdec::utils::toString;

namespace retdec {
namespace llvmir2hll {

namespace {

/// Available names for induction variables.
const char *IND_VAR_NAMES[] = {
	"i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w"
};

/// Number of available induction variables.
const std::size_t NUM_OF_AVAIL_IND_VAR_NAMES = arraySize(IND_VAR_NAMES);

/// Name of the variable which is the returned from a function.
const std::string RETURN_VAR_NAME = "result";

} // anonymous namespace

REGISTER_AT_FACTORY("readable", READABLE_VAR_RENAMER_ID, VarRenamerFactory,
	ReadableVarRenamer::create);

/**
* @brief Constructs a new renamer.
*
* For more details, see create().
*/
ReadableVarRenamer::ReadableVarRenamer(ShPtr<VarNameGen> varNameGen,
	bool useDebugNames): VarRenamer(varNameGen, useDebugNames),
		globalVarNameGen(NumVarNameGen::create("g")),
		localVarNameGen(NumVarNameGen::create("v")),
		indVarsNamesInCurrFunc(),
		renamingInductionVars(false),
		renamingReturnVars(false),
		renamingResultsOfWellKnownFuncs(false),
		renamingArgsOfWellKnownFuncs(false) {}

/**
* @brief Creates a new renamer.
*
* @param[in] varNameGen Used generator of variable names (not used in this
*                       renamer).
* @param[in] useDebugNames Should we use variable names from debugging
*                          information?
*
* @par Preconditions
*  - @a varNameGen is non-null
*/
ShPtr<VarRenamer> ReadableVarRenamer::create(ShPtr<VarNameGen> varNameGen,
		bool useDebugNames) {
	PRECONDITION_NON_NULL(varNameGen);

	return ShPtr<VarRenamer>(new ReadableVarRenamer(varNameGen, useDebugNames));
}

std::string ReadableVarRenamer::getId() const {
	return READABLE_VAR_RENAMER_ID;
}

void ReadableVarRenamer::renameGlobalVar(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	assignName(var, globalVarNameGen->getNextVarName());
}

void ReadableVarRenamer::renameVarsInFunc(ShPtr<Function> func) {
	PRECONDITION_NON_NULL(func);

	currFunc = func;
	renameMainParams(func);
	renameInductionVars(func);
	renameResultsOfWellKnownFuncs(func);
	renameArgsOfWellKnownFuncs(func);
	renameReturnedVars(func);
	renameOtherLocalVars(func);
}

void ReadableVarRenamer::renameFuncParam(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	assignName(var, genNameForFuncParam(var, func), func);
}

void ReadableVarRenamer::renameFuncLocalVar(ShPtr<Variable> var,
		ShPtr<Function> func) {
	PRECONDITION_NON_NULL(var);

	assignName(var, localVarNameGen->getNextVarName(), func);
}

/**
* @brief Visits subsequent statements of @a stmt (if any).
*/
void ReadableVarRenamer::visitSubsequentStmts(ShPtr<Statement> stmt) {
	if (stmt->hasSuccessor()) {
		stmt->getSuccessor()->accept(this);
	}
}

/**
* @brief Visits the body of the given function.
*
* If the function doesn't have a body, this function does nothing. Otherwise,
* it sets @c currFunc, calls @c restart(), and visits the body.
*/
void ReadableVarRenamer::visitFuncBody(ShPtr<Function> func) {
	ShPtr<Statement> body(func->getBody());
	if (!body) {
		return;
	}

	currFunc = func;
	restart();
	body->accept(this);
}

/**
* @brief If the given function is "main", it properly renames its parameters.
*/
void ReadableVarRenamer::renameMainParams(ShPtr<Function> func) {
	VarVector params(func->getParams());
	if (func->getName() == "main" && params.size() == 2) {
		// It's the main function. If we have not yet renamed the parameters
		// (for example, by utilizing debug information), we name them argc and
		// argv.

		// argc
		ShPtr<Variable> argc(params.front());
		if (!hasBeenRenamed(argc)) {
			assignName(argc, "argc", func);
		}

		// argv
		ShPtr<Variable> argv(params.back());
		if (!hasBeenRenamed(argv)) {
			assignName(argv, "argv", func);
		}
	}
}

/**
* @brief Properly renames induction variables in the given function.
*/
void ReadableVarRenamer::renameInductionVars(ShPtr<Function> func) {
	renamingInductionVars = true;
	indVarsNamesInCurrFunc.clear();
	visitFuncBody(func);
	// We have to insert the names of induction variables to the set of
	// assigned names of local variables in the current function to prevent
	// name clashes.
	addToSet(indVarsNamesInCurrFunc, localVarsNames[func]);
	renamingInductionVars = false;
}

/**
* @brief Renames the given induction variable in the given function.
*/
void ReadableVarRenamer::renameInductionVar(ShPtr<Variable> var,
		ShPtr<Function> func) {
	renameVarByChoosingNameFromList(var, currFunc, &IND_VAR_NAMES[0],
		NUM_OF_AVAIL_IND_VAR_NAMES);
}

/**
* @brief Properly renames variables returned from the given function.
*/
void ReadableVarRenamer::renameReturnedVars(ShPtr<Function> func) {
	renamingReturnVars = true;
	visitFuncBody(func);
	renamingReturnVars = false;
}

/**
* @brief Renames variables storing the results of calls to well-known
*        functions.
*/
void ReadableVarRenamer::renameResultsOfWellKnownFuncs(ShPtr<Function> func) {
	renamingResultsOfWellKnownFuncs = true;
	visitFuncBody(func);
	renamingResultsOfWellKnownFuncs = false;
}

/**
* @brief Renames variables passed as arguments to well-known functions.
*/
void ReadableVarRenamer::renameArgsOfWellKnownFuncs(ShPtr<Function> func) {
	renamingArgsOfWellKnownFuncs = true;
	visitFuncBody(func);
	renamingArgsOfWellKnownFuncs = false;
}

/**
* @brief Properly renames other local variables in the given function.
*/
void ReadableVarRenamer::renameOtherLocalVars(ShPtr<Function> func) {
	localVarNameGen->restart();

	VarRenamer::renameVarsInFunc(func);
}

/**
* @brief Renames the given variable in the given function by choosing the first
*        fitting name from @a names.
*
* @param[in,out] var Variable to be renamed.
* @param[in] func Function that contains @a var as a parameter or local variable.
* @param[in] names List of available names.
* @param[in] numOfAvailNames Number of available names in @a names.
*
* If there are no names that can be used, the last name of @a names is used,
* but a suffix is appended to it.
*/
void ReadableVarRenamer::renameVarByChoosingNameFromList(ShPtr<Variable> var,
		ShPtr<Function> func, const char **names, std::size_t numOfAvailNames) {
	// Choose a new name for the variable.
	std::string newName;
	for (std::size_t i = 0, e = numOfAvailNames; i < e; ++i) {
		newName = names[i];
		if (!nameExists(newName, func)) {
			break;
		}
	}

	// If we have tried all the available variable names and all of them are
	// already used, use the last available one, which is stored in newName at
	// this moment. The assignName() call below makes sure that the name is
	// unique by appending a suffix to it.
	assignName(var, newName, func);
}

/**
* @brief Tries to rename the variable on the left-hand side of the given
*        statement based on the function that is called in the right-hand side.
*
* @par Preconditions
*  - @a stmt is non-null
*  - @a stmt is either a variable-defining statement or an assign statement

* This function does nothing when:
*  - the left-hand side of @a stmt is not a variable
*  - the right-hand side of @a stmt is a function call to anything but a
*    declared function
*  - the variable has already been renamed or it is a global variable
*/
void ReadableVarRenamer::tryRenameVarStoringCallResult(ShPtr<Statement> stmt) {
	PRECONDITION_NON_NULL(stmt);
	PRECONDITION(isVarDefOrAssignStmt(stmt), "the statement " << stmt <<
		"is not a variable-defining statement or an assign statement");

	ShPtr<Variable> lhsVar(cast<Variable>(getLhs(stmt)));
	if (!lhsVar || hasBeenRenamed(lhsVar) || isGlobalVar(lhsVar)) {
		return;
	}

	ShPtr<CallExpr> callExpr(cast<CallExpr>(skipCasts(getRhs(stmt))));
	if (!callExpr) {
		return;
	}

	ShPtr<Function> calledFunc(getDeclaredFunc(callExpr));
	if (!calledFunc) {
		return;
	}

	Maybe<std::string> newName(module->getSemantics()->getNameOfVarStoringResult(
		calledFunc->getName()));
	if (newName) {
		assignName(lhsVar, newName.get(), currFunc);
	}
}

/**
* @brief Tries to rename variables pass as arguments to the given call.
*
* @par Preconditions
*  - @a expr is non-null

* This function does nothing when:
*  - @a expr is a function call to anything but a declared function
*  - there are no variables to be renamed
*/
void ReadableVarRenamer::tryRenameVarsPassedAsArgsToFuncCall(
		ShPtr<CallExpr> expr) {
	PRECONDITION_NON_NULL(expr);

	ShPtr<Function> calledFunc(getDeclaredFunc(expr));
	if (!calledFunc) {
		return;
	}

	// For each argument...
	const ExprVector &args(expr->getArgs());
	unsigned argPos = 1;
	for (auto i = args.begin(), e = args.end(); i != e; ++i, ++argPos) {
		if (ShPtr<Variable> var = getVarFromCallArg(*i)) {
			tryRenameVarPassedAsArgToFuncCall(calledFunc, var, argPos);
		}
	}
}

/**
* @brief Tries to rename the given argument of the given call to a declared
*        function.
*
* This function does nothing when:
*  - @a var is a global variable, function, or it has already been renamed
*/
void ReadableVarRenamer::tryRenameVarPassedAsArgToFuncCall(
		ShPtr<Function> calledFunc, ShPtr<Variable> var, unsigned argPos) {
	if (isGlobalVar(var) || isFunc(var) || hasBeenRenamed(var)) {
		return;
	}

	Maybe<std::string> newName(module->getSemantics()->getNameOfParam(
		calledFunc->getName(), argPos));
	if (newName) {
		assignName(var, newName.get(), currFunc);
	}
}

/**
* @brief Returns the function called in the given expression provided that it
*        is a call to a declared function, the null pointer otherwise.
*/
ShPtr<Function> ReadableVarRenamer::getDeclaredFunc(ShPtr<CallExpr> expr) const {
	ShPtr<Variable> callVar(cast<Variable>(expr->getCalledExpr()));
	if (!callVar) {
		return ShPtr<Function>();
	}

	ShPtr<Function> calledFunc(getFuncByName(callVar->getName()));
	if (!calledFunc || !calledFunc->isDeclaration()) {
		return ShPtr<Function>();
	}

	return calledFunc;
}

/**
* @brief Tries to obtain a variable from the given argument of a function call.
*
* When the variable cannot be obtained, the null pointer is returned.
*/
ShPtr<Variable> ReadableVarRenamer::getVarFromCallArg(ShPtr<Expression> arg) const {
	// Motivation: For example, the given function call is present when
	// decompiling file enc_1_.exe:
	//
	//     GetSystemTimeAsFileTime((struct FILETIME *)&v1);
	//
	// We want to rename v1 to lpSystemTimeAsFileTime, so we have to skip
	// casts, address-taking operators etc.
	ShPtr<Expression> oldExpr;
	ShPtr<Expression> newExpr(arg);
	do {
		oldExpr = newExpr;
		newExpr = skipCasts(newExpr);
		newExpr = skipAddresses(newExpr);
		newExpr = skipDerefs(newExpr);
	} while (newExpr != oldExpr);

	return cast<Variable>(newExpr);
}

/**
* @brief Generates a name for the given parameter of the given function.
*/
std::string ReadableVarRenamer::genNameForFuncParam(
		ShPtr<Variable> var, ShPtr<Function> func) const {
	// Use name "aX", where X is the position of the parameter. In this way, if
	// there are some parameters with assigned names from debug information, we
	// number the parameters correctly, e.g. p2 is always the second parameter,
	// no matter if the first parameter has assigned a name from debug
	// information.
	return "a"s + toString(func->getParamPos(var));
}

void ReadableVarRenamer::visit(ShPtr<ForLoopStmt> stmt) {
	//
	// Renaming of induction variables.
	//
	if (renamingInductionVars) {
		ShPtr<Variable> indVar(stmt->getIndVar());
		if (!hasBeenRenamed(indVar)) {
			renameInductionVar(indVar, currFunc);
		}

		// Store the name for later use.
		indVarsNamesInCurrFunc.insert(indVar->getName());

		// Visit nested loops (if any).
		visitStmt(stmt->getBody());

		// Since the induction variable is local to the loop, we may reuse it
		// after the loop. We add it back to localVarsNames later by using
		// indVarsNamesInCurrFunc.
		localVarsNames[currFunc].erase(indVar->getName());

		visitSubsequentStmts(stmt);
	} else {
		VarRenamer::visit(stmt);
	}
}

void ReadableVarRenamer::visit(ShPtr<ReturnStmt> stmt) {
	//
	// Renaming of variables returned from the function.
	//
	if (renamingReturnVars) {
		// TODO Is this the best way of doing this? What if there are more
		//      variables returned from the function?
		if (ShPtr<Variable> var = cast<Variable>(stmt->getRetVal())) {
			if (!isGlobalVar(var) && !isFunc(var) && !hasBeenRenamed(var)) {
				assignName(var, RETURN_VAR_NAME, currFunc);
			}
		}

		visitSubsequentStmts(stmt);
	} else {
		VarRenamer::visit(stmt);
	}
}

void ReadableVarRenamer::visit(ShPtr<AssignStmt> stmt) {
	//
	// Renaming of variables storing the results of calls to well-known
	// functions.
	//
	if (renamingResultsOfWellKnownFuncs) {
		tryRenameVarStoringCallResult(stmt);
		visitSubsequentStmts(stmt);
	} else {
		VarRenamer::visit(stmt);
	}
}

void ReadableVarRenamer::visit(ShPtr<VarDefStmt> stmt) {
	//
	// Renaming of variables storing the results of calls to well-known
	// functions.
	//
	if (renamingResultsOfWellKnownFuncs) {
		tryRenameVarStoringCallResult(stmt);
		visitSubsequentStmts(stmt);
	} else {
		VarRenamer::visit(stmt);
	}
}

void ReadableVarRenamer::visit(ShPtr<CallExpr> expr) {
	VarRenamer::visit(expr);

	//
	// Renaming of variables passed as arguments of calls to well-known
	// functions.
	//
	if (renamingArgsOfWellKnownFuncs) {
		tryRenameVarsPassedAsArgsToFuncCall(expr);
	}
}

void ReadableVarRenamer::visit(ShPtr<Variable> var) {
	// Do not rename already renamed variables.
	if (hasBeenRenamed(var)) {
		return;
	}

	// Do not rename function names.
	if (getFuncByName(var->getName())) {
		return;
	}

	if (renamingInductionVars || renamingReturnVars ||
			renamingResultsOfWellKnownFuncs ||
			renamingArgsOfWellKnownFuncs) {
		// These renames are handled in other functions.
		return;
	}

	renameFuncLocalVar(var, currFunc);
}

} // namespace llvmir2hll
} // namespace retdec
